# Agent, retrieval, SQL, and models

## Bounded graph

The graph has seven nodes and no autonomous loop:

```text
guard → route → execute bounded tools → rerank → synthesize without tools → verify → END
```

Direct override attempts can be blocked before model use. More importantly, indirect injection in
OCR/transcripts/search cannot trigger tools because the router has already completed and the answer
model has no tools. Regex flags are telemetry/defense-in-depth—not the primary boundary.

## Router

An OpenAI-compatible chat endpoint receives strict tool schemas for `search_evidence`,
`query_analytics`, and optionally `search_web`. Unknown tools/fields or invalid types are discarded.
The executor limit defaults to three proposals and is schema-bounded to 1–6; the router prompt asks
for no more than three and the reference production configuration retains the default. The offline
heuristic always searches local evidence, adds SQL for aggregate/numeric language, and adds web only
for current/live language when the request opted in.

`CRISISWEAVE_LLM_ROUTER_MODEL` and `CRISISWEAVE_LLM_ANSWER_MODEL` are separate settings; they may
name the same deployment only if it satisfies both contracts. The router must support typed function
calls. The answer model must accept vision input because selected JPEG derivatives are sent as bounded
data URLs. Production startup performs a forced router-tool probe and a red-pixel vision probe and
fails if either contract is absent.

OCR is not performed by either model. It runs during ingestion through Windows Runtime OCR in the
local Windows fallback or through Tesseract. CLIP visual embeddings are also separate: they select
likely images/pages but do not answer the question. See
[OCR, vision, and model setup](ocr-vision-and-models.md) for configuration and validation.

Router temperature is **0.0**. Answer temperature defaults to **0.1** and production rejects values
above **0.2**. SQL is proposed in the router call and has no separate temperature. Provider models
that do not accept temperature require an explicit gateway adapter; temperature is a reproducibility
setting, not an authorization guardrail.

## Multimodal retrieval

Qdrant collection `crisisweave_evidence_v1` has named `text` and `visual` cosine vectors. Text and
visual-text queries run separately and merge by best score. Production defaults are BGE-small text
embeddings and CLIP ViT-B/32 pixels/text. Text chunks are indexed with SentenceTransformers
`encode_document`; questions use `encode_query`, and both are normalized. This asymmetric pipeline
is included in the embedding fingerprint. An index produced by the previous generic `encode`
pipeline is rejected at startup and must be rebuilt in a new collection/alias migration. Candidate
count defaults to 30; the Windows convenience launcher deliberately raises it to 200 for local
scanned-report recall. When multiple documents compete, successful lexical/cross-encoder reranking
admits at most three units per document to final context. A single-document library may fill the
requested context limit so a long report is not artificially reduced to three pages.

The development hash embedder is deterministic and offline but not semantically representative. It
hashes OCR/placeholder text and does not inspect pixels. Production startup rejects it. For
higher-end deployments, benchmark unified video/image/text models
such as Qwen3-VL embeddings against CLIP+BGE before changing dimensions; use a new collection/model
version and an alias migration rather than mutating an existing vector schema.

## Reranking

- Local plumbing: weighted cosine and lexical overlap, with indirect-injection flags downweighted.
- Production: BGE cross-encoder logits normalized to 0–1, then source diversity applied.
- Final evidence count is the request's bounded `top_k` (1–30, UI default 8).

If a reranker raises, the agent returns the top retrieval scores and a warning. That fallback remains
bounded by `top_k` but does not apply the three-per-document diversity cap; monitor the warning and
do not describe fallback output as reranked.

Measure Recall@K before and after reranking, nDCG/MRR, per-modality recall, duplicate share and the
gain/loss caused by diversity caps. Never promote a model solely on generic benchmark scores.

## SQL security contract

The LLM may propose SQL, but `sqlglot` must parse exactly one `SELECT` against the model-facing
`authorized_storm_events` name. The AST rejects comments, CTEs, subqueries, joins, non-allowlisted
tables/columns/functions and all mutation/DDL. It also rejects `DISTINCT`, windows, aggregate
`FILTER`, conditional aggregates, concatenation, advanced grouping, sampling, pivots and `OFFSET`.
A caller's smaller literal `LIMIT` is preserved; otherwise the server adds its own cap. Trusted code
then rewrites the table to `storm_events` and injects tenant and `ready`-document predicates before
using a dedicated, memory/thread/time/result/cell-bounded DuckDB connection. External access,
automatic extensions and community extensions are disabled where supported.

Allowed view: `authorized_storm_events`. Allowed functions: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`,
`ROUND`, `COALESCE`, `LOWER`, `UPPER`. This deliberately favors safe, explainable aggregations over
general natural-language-to-SQL capability.

For a non-empty SQL result, one augmented tenant-scoped query computes visible rows and bounded
document lineage together. Each generated table evidence unit contains only result rows to which its
`ready` source document contributed, preserves filename/source URI, and reports whether the source
count is exact or a lower bound. At most ten source citations are exposed to the model. This is exact
result-row-to-document provenance, not cell-level causality: it does not claim that every source
determined every aggregate cell.

## Web search

Web search is disabled by default and requires both configured Tavily credentials and per-request
`allow_web=true`. Only official-domain snippets from NASA, NOAA, USGS and FEMA (configurable exact
suffix allowlist) enter context. CrisisWeave does not fetch result URLs, eliminating the agent's
arbitrary-URL/redirect SSRF path. Search text is still tagged untrusted.

## Answer and verifier

Each unit is labeled `[E#]` in a tagged untrusted block. The answer must cite those labels, separate
observation from inference, and abstain when missing. The verifier removes malformed/unknown labels
and withholds uncited drafts. For text-backed claims it also checks lexical overlap, cited numbers,
localized negation, mixed polarity, and a small deterministic antonym set. Visual evidence is exempt
from text-overlap scoring only when that citation's bounded pixels were successfully attached to the
answer-model request. An artifact path or a skipped/oversized image does not grant this exemption.
Cited OCR/caption numbers and contradictions still apply. Pure pixel claims receive a vision-quality
warning because this verifier is not a second visual entailment model; visual citations grounded only
in extracted text say so explicitly. Production evaluation must still measure claim-level citation
precision/coverage, contradiction handling, and visual groundedness.

The answer gateway attaches only retrieved image/PDF-page/video-frame artifacts, at most
`CRISISWEAVE_MAX_VISION_IMAGES` (four by default), each no larger than
`CRISISWEAVE_MAX_VISION_IMAGE_BYTES` (5 MiB by default), as low-detail JPEG data URLs. It does not
inspect every document page. A capable VLM can interpret selected pixels but cannot compensate for a
page that retrieval omitted.

Structured evidence and citations also expose bounded image boxes, PDF-page boxes, chart-element
references and video intervals when available. These are provenance locators, not verifier-issued
entailment decisions. The offline benchmark separately compares `model_proposal` regions with blind
`human_annotation` regions using deterministic one-to-one IoU matching; see
[region-level grounding](12-region-level-grounding.md).

Concordance combines source diversity (35%), modality diversity (25%), retrieval/rerank strength
(25%) and tool-route coverage (15%). It is an evidence-coverage indicator, **not a
probability that the answer is true**.
