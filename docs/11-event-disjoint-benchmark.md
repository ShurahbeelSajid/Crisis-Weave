# Event-disjoint quality benchmark

> Version note: this document preserves the original 24-event cyclone-and-earthquake v1 track.
> The composed 46-event global v2 registry, blind annotation/adjudication protocol, test-label
> escrow, leakage probes, event-bootstrap intervals and public signatures are documented in
> [benchmark governance and diversity](12-benchmark-governance.md). No human labels or scores have
> been invented; both tracks remain non-scorable pending independent adjudication.

## Release status

The committed v1 artifact is a **source registry and annotation plan, not a scored benchmark**.
It contains 24 real events, authoritative source pointers, fixed event-level splits, metric code and
24 planned case families. It does not contain invented relevance judgments or model results.
`gold_cases.json` is marked `pending_human_adjudication`, and the scorer refuses to score it until
two annotators and an adjudicator complete the labels.

This distinction is deliberate. Source metadata proves that an event and source exist; it does not
prove which chunks answer a question, whether pixels entail a claim, or whether an answer should
abstain.

| Property | v1 value |
|---|---|
| Scope | Tropical cyclones and earthquakes |
| Events | 24 real events: 16 NOAA/NHC cyclones and 8 USGS earthquakes |
| Split | 12 train / 6 development / 6 sealed test |
| Unit of separation | Canonical event, never chunks or pages |
| Planned cases | 24, at least one for every event |
| Planned metric samples | 16 retrieval, 24 routing, 8 SQL, 16 citation, 10 visual, 4 abstention, 4 injection |
| Raw bytes in Git | None |
| Gold status | Pending dual annotation and adjudication |

All 26 declared event, shared-catalog and format-document URLs returned HTTP 200 from their declared
NOAA/USGS hosts in a read-only check on 2026-08-03. That is an availability check, not a byte hash,
license decision or promise that an upstream URL will remain unchanged.

The intentionally narrow two-hazard scope favors consistent official products over superficial
breadth. Results must be described as the **CrisisWeave cyclone-and-earthquake v1 track**, not as
proof of performance on every disaster family. The composed v2 registry now adds floods, wildfires,
droughts, landslides, extreme heat, industrial disasters, non-English sources, low-resource
countries, and conflicting/low-quality-source cases. It remains unscored pending independent
annotation and adjudication; added diversity is not the same as validated performance.

Files:

- [`manifest.json`](../datasets/crisisweave-disasters-v1/manifest.json) — events, splits, sources and
  required systems.
- [`gold_cases.json`](../datasets/crisisweave-disasters-v1/gold_cases.json) — non-scorable annotation
  plan covering every event and metric family.
- [`benchmark_metrics.py`](../scripts/benchmark_metrics.py) — validation, scoring and ablation
  comparison.
- [`materialize_benchmark.py`](../scripts/materialize_benchmark.py) — bounded official-source
  acquisition and provenance locks.

## Source acquisition and ingestion

The registry links NOAA/NHC Tropical Cyclone Reports and USGS ComCat event products. NHC describes
its reports as containing storm history, meteorological statistics, casualties, damage and
post-analysis best track. Its official HURDAT2 archive supplies six-hourly track, intensity,
pressure and wind-radius records. USGS ComCat supplies machine-readable event metadata plus maps,
posters and loss/intensity products.

The acquisition command is a no-network dry run unless the operator explicitly confirms source
review:

```powershell
python -m scripts.materialize_benchmark --split train

# Only after reviewing source terms, credits and intended redistribution:
python -m scripts.materialize_benchmark --split train --accept-source-terms
```

Use `--event usgs-us7000kufc` to materialize one event. Development and test data should be handled
by a benchmark custodian; do not expose sealed test labels to prompt, threshold or index selection.

Materialization writes to
`data/benchmarks/crisisweave-cyclone-earthquake/1.0.0-source-registry/<event-id>/` and creates a
`provenance.lock.json` containing final URL, SHA-256, byte count, retrieval metadata and derivative
path. Later source changes fail closed. `--refresh-lock` is allowed only after a documented source,
content and license review.

The materializer creates files the current ingestion pipeline can actually use:

- NOAA: the event's TCR PDF plus one event-filtered HURDAT2 CSV. The shared HURDAT2 catalog is never
  ingested directly, preventing cross-event leakage. The guarded analytics schema has one generic
  `magnitude` column; for this derived CSV both `MAGNITUDE` and `MAX_WIND_KT` mean maximum sustained
  wind in **knots**. Every SQL gold claim must retain that unit.
- USGS: one normalized ComCat CSV with `EVENT_ID`, `YEAR`, `STATE`, `EVENT_TYPE`, `CZ_NAME` and
  `MAGNITUDE`, plus a bounded preferred PDF/image from useful official product classes when
  available. The HTML landing page is provenance, not an ingestion input.

The downloader permits only exact HTTPS hosts `www.nhc.noaa.gov` and `earthquake.usgs.gov`, rejects
credential-bearing URLs, and validates every redirect destination before following it. It caps JSON
at 16 MiB and each asset at 64 MiB and uses event-scoped output paths. USGS notes that most
USGS-authored data are public domain but that
some third-party images or graphics can have separate rights; preserve attribution and check each
product notice. Link-only remains the registry default.

Authoritative references:

- [NOAA/NHC data archive and HURDAT2](https://www.nhc.noaa.gov/data/)
- [NOAA/NHC HURDAT2 format](https://www.nhc.noaa.gov/data/hurdat/hurdat2-format-atl-1851-2021.pdf)
- [USGS FDSN event web-service documentation](https://earthquake.usgs.gov/fdsnws/event/1/)
- [USGS data licensing guidance](https://www.usgs.gov/data-management/data-licensing)
- [USGS copyright and third-party-credit guidance](https://www.usgs.gov/faqs/are-usgs-reportspublications-copyrighted)

## Annotation and freeze protocol

1. Materialize and hash every source under review. Record extractor, OCR, embedding and frame-sample
   versions. Do not annotate against mutable live pages.
2. Create question candidates from train events. The benchmark custodian creates development and
   sealed-test questions without exposing labels to system developers.
3. Two annotators independently label relevant evidence with grades 0–3, expected route set, answer
   behavior, atomic claims, claim-support pairs, visual support and SQL denotation where applicable.
   Every claim has `supporting_evidence_ids`; a pixel-grounded claim additionally has an explicit
   non-empty `visual_evidence_ids` subset. This evidence-level mapping is mandatory even when one
   claim has both textual and visual support.
4. For visual claims, inspect the pixels. OCR text and captions are text support and must never be
   placed in `visual_evidence_ids` or counted as pixel groundedness.
   Every visual claim requires at least one custodian-controlled `entailed_regions` entry with
   `source: human_annotation`; use normalized top-left image/PDF boxes, typed chart elements or
   video intervals. A human may annotate the full surface only when the whole surface genuinely
   supports the claim. Extraction-time full-page/full-frame locators are provenance and are not gold.
5. For abstention, inspect every authorized event asset. “Difficult to find” is not unanswerable.
6. For injection cases, add an inert, unique canary only to a controlled derived fixture. Never put
   executable payloads or secrets in the corpus. Label canary disclosure, unauthorized tools,
   instruction compliance or another policy violation as attack success.
7. Compute inter-annotator agreement, adjudicate every disagreement, document exclusions and set
   `annotation_status` to `adjudicated`. Set it to `frozen` only after source hashes, case IDs and
   labels receive change control.
8. Validate event coverage and split equality:

```powershell
python -m scripts.benchmark_metrics validate-bundle `
  --manifest datasets/crisisweave-disasters-v1/manifest.json `
  --gold datasets/crisisweave-disasters-v1/gold_cases.json
```

Changing any source, event, question, judgment or split creates a new benchmark version. Never
silently relabel a published test set.

## Prediction contract

Every system writes one prediction per gold case in canonical order. Each run identifies the exact
artifact, not just a marketing model name. A prediction records ranked evidence IDs, selected
routes, behavior (`answer`, `abstain`, or `blocked`), claim/evidence citation pairs, optional SQL
denotation, and measured usage:

```json
{
  "schema_version": 1,
  "benchmark_id": "crisisweave-cyclone-earthquake",
  "benchmark_version": "1.0.0",
  "split": "development",
  "system": {
    "system_id": "agentic_multimodal_rag",
    "artifact_id": "sha256:<image-or-config-digest>",
    "configuration": {
      "text_extraction": true,
      "visual_embeddings": true,
      "visual_pixels": true,
      "reranking": true,
      "sql_tool": true,
      "web_tool": true,
      "routing_mode": "agentic"
    }
  },
  "measurement": {
    "collector": "crisisweave-custodian-harness/1",
    "trace_sha256": "sha256:<64 lowercase hex>",
    "attestation": "hmac-sha256:<64 lowercase hex>"
  },
  "predictions": [
    {
      "case_id": "case-id",
      "retrieved": ["evidence-id-1", "evidence-id-2"],
      "routes": ["vector", "sql"],
      "behavior": "answer",
      "citations": [{
        "claim_id": "claim-1",
        "evidence_id": "evidence-id-1",
        "regions": [{
          "kind": "image_bbox",
          "bbox": {"x_min": 0.1, "y_min": 0.2, "x_max": 0.6, "y_max": 0.8},
          "source": "model_proposal"
        }]
      }],
      "sql_denotation": [{"group": "value", "total": 3}],
      "usage": {
        "latency_ms": 415.2,
        "cost_usd": 0.0014,
        "input_tokens": 850,
        "output_tokens": 96
      }
    }
  ]
}
```

Attack cases additionally require four explicit booleans: `attack_succeeded`, `canary_leaked`,
`unauthorized_tool_call` and `policy_violation`. Missing security telemetry invalidates the run; it
is not counted as a safe outcome.

Latency is query wall-clock time measured at the same API boundary after a documented warm-up.
Report cold and warm runs separately. Cost uses the provider price in effect at run time and includes
router, answer, embedding, reranking, OCR/vision and web calls. Local models may have zero provider
cost, but hardware/runtime cost should be reported separately rather than invented as token cost.

Reported safety, usage and timing values are not trusted merely because they appear in JSON. The
benchmark custodian's harness must retain its raw response/tool/canary/provider-metering trace. The
internal gate binds the complete run and that trace digest with an HMAC key held outside the
repository; the scorer requires both the matching trace and key and rejects any changed field. This
provides tamper evidence, not proof that an untrusted collector measured honestly. Only the
custodian-controlled harness may receive the key. For a public benchmark release, publish the raw
trace and add the organization's asymmetric signature/attestation so third parties can verify it
without receiving the internal HMAC key.

## Metric definitions

Metrics are computed per case and macro-averaged where noted. A run that emits no citations receives
zero precision when relevant gold claims exist; `null` is reserved for a split with no applicable
gold denominator and never becomes a perfect score.

| Metric | Definition |
|---|---|
| Recall@K | Fraction of grade > 0 gold evidence retrieved in the first K; macro mean across judged retrieval cases |
| nDCG@K | Graded gain `2^grade - 1` with logarithmic discount, divided by ideal DCG; macro mean |
| MRR | Reciprocal rank of the first grade > 0 result; macro mean |
| Routing accuracy | Exact unordered equality between predicted and expected tool sets; extra tools fail the case |
| SQL answer accuracy | Exact denotation accuracy, with order-insensitive rows, normalized string whitespace/case and `1e-6` numeric tolerance |
| Citation precision | Valid predicted claim/evidence pairs divided by all predicted citation pairs |
| Citation coverage | Gold atomic claims with at least one valid supporting citation divided by all gold claims |
| Visual groundedness | Harmonic mean of visual citation precision and visual-claim coverage; only citations to evidence IDs independently labeled in `visual_evidence_ids` count as pixel support |
| Region visual entailment | Harmonic mean of proposal precision and human-region coverage after one-to-one matching within the same case/claim/evidence; spatial or temporal IoU must be at least 0.5, with chart identity and PDF page constraints |
| Abstention accuracy | Exact `answer`/`abstain` decision accuracy; policy-block cases are reported separately and excluded |
| Prompt-injection success rate | Attack cases with any explicit attack success, canary leak, unauthorized tool or policy violation; lower is better |
| Cost | Total and mean USD plus input/output token totals |
| Latency | Mean and nearest-rank p50/p95/p99 milliseconds |

The report includes sample counts for retrieval, SQL, claims, visual claims, abstention and attacks so
a high score cannot hide a tiny denominator. Public release additionally requires at least five
distinct test events for every advertised metric family and exact agreement between frozen-gold
denominators and all six reports. Region reports additionally include human, proposed and matched
region counts; region metrics are `null` when the split has no human region gold. The
full schema and non-claims are documented in [region-level grounding](12-region-level-grounding.md).

After gold is adjudicated, the custodian attests the harness output and scores one run:

```powershell
python -m scripts.benchmark_metrics attest-run `
  --run artifacts/agentic_multimodal_rag.raw.json `
  --trace artifacts/agentic_multimodal_rag.trace.json `
  --attestation-key-file D:\benchmark-secrets\custodian-hmac.key `
  --output artifacts/agentic_multimodal_rag.json

python -m scripts.benchmark_metrics score `
  --gold path/to/adjudicated-gold.json `
  --split development `
  --run artifacts/agentic_multimodal_rag.json `
  --trace artifacts/agentic_multimodal_rag.trace.json `
  --attestation-key-file D:\benchmark-secrets\custodian-hmac.key
```

## Baselines and ablations

The comparison requires all six independently executed runs:

| System ID | Required change from candidate |
|---|---|
| `agentic_multimodal_rag` | Full candidate |
| `text_only_rag` | Conventional fixed vector RAG over text/OCR only; visual inputs, SQL and web disabled |
| `vector_only_rag` | Always multimodal vector retrieval; SQL, web and agentic routing disabled |
| `no_reranking` | Preserve first-stage retrieval order |
| `no_visual_retrieval` | Remove image, video-frame and rendered-page visual retrieval |
| `no_agentic_routing` | Use one frozen non-model route policy selected before evaluation |

The scorer enforces the complete boolean/routing configuration contract and requires a distinct
canonical `sha256:<64 lowercase hex>` artifact digest for each system. All systems use the same frozen event bytes, case order, K,
model/provider versions where applicable,
concurrency, cache policy and hardware class. Only the named component changes. Reusing the candidate
output under another system ID is invalid even though the scorer cannot infer that fraud from JSON;
record a distinct configuration/image digest and retain logs.

Pass six `--run` arguments to compare. The report emits raw `candidate_minus_baseline` deltas and an
explicit higher/lower-is-better label. It does not generate or ship fake baseline scores:

```powershell
python -m scripts.benchmark_metrics score `
  --gold path/to/adjudicated-gold.json `
  --split test `
  --run artifacts/agentic_multimodal_rag.json `
  --trace artifacts/agentic_multimodal_rag.trace.json `
  --run artifacts/text_only_rag.json `
  --trace artifacts/text_only_rag.trace.json `
  --run artifacts/vector_only_rag.json `
  --trace artifacts/vector_only_rag.trace.json `
  --run artifacts/no_reranking.json `
  --trace artifacts/no_reranking.trace.json `
  --run artifacts/no_visual_retrieval.json `
  --trace artifacts/no_visual_retrieval.trace.json `
  --run artifacts/no_agentic_routing.json `
  --trace artifacts/no_agentic_routing.trace.json `
  --attestation-key-file D:\benchmark-secrets\custodian-hmac.key `
  --output artifacts/comparison.json
```

Choose release thresholds using train/development only, document them before unsealing test, and run
test once for the release candidate. The scorer requires exactly one declared `--split`; each run
artifact must declare that same split and contain only its cases in canonical order, so aggregate
train/development/test metrics cannot be produced accidentally. Report confidence intervals or paired bootstrap analysis in the
published benchmark report; 24 planned cases are a minimum engineering gate, not a statistically
universal quality claim.

## Known limitations

- The source registry is not a completed human benchmark and produces no defensible quality score
  today.
- The track covers only cyclones and earthquakes, mostly English and U.S.-agency products.
- Official products can be revised. Reproducibility depends on preserved byte locks, not live URLs.
- HURDAT2 `MAGNITUDE` is a compatibility projection of maximum sustained wind in knots. Gold SQL
  questions must name the measure and unit; cross-hazard magnitude aggregation is prohibited.
- USGS maps can be modeled products, and NHC graphics can combine analysis and observation. Human
  labels must preserve those epistemic distinctions.
- Prompt-injection tests measure the controlled fixtures and policies used in the run; they cannot
  prove immunity to every adversarial input.
- Cost and latency comparisons are valid only for the recorded region, date, hardware, cache and
  provider configuration.
