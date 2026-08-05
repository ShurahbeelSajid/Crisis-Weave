# CrisisWeave

CrisisWeave is an evidence-first multimodal research assistant for disaster reports. It accepts
multiple PDFs, images, videos, text files, and structured tables; retrieves relevant evidence;
optionally runs guarded SQL or official-domain web search; and returns a cited answer or an explicit
abstention.

> **Current status:** the default local profile is a working research/demo system, not a certified
> emergency system or a completed production deployment. It is useful today for evidence discovery,
> scanned-report search, cited fact extraction, and architecture demonstrations. Real-model quality,
> independently adjudicated benchmark results, and live production infrastructure still require
> external validation.

## What problem it solves

Disaster evidence is usually fragmented across long reports, scanned pages, charts, images, videos,
and event tables. Finding one defensible answer can require searching many files, calculating an
aggregate, checking where a statement came from, and recognizing when the source does not answer the
question.

CrisisWeave puts that workflow behind one interface:

1. Ingest several evidence files into a tenant-isolated library.
2. Extract native text, OCR text, page images, video frames/transcripts, and table rows.
3. Route a question to local retrieval, bounded read-only SQL, and/or approved web snippets.
4. Rerank the candidate evidence and generate or extract an answer.
5. Validate citation labels, expose source freshness/conflicts, and abstain when support is missing.

At this stage it can help analysts, researchers, students, NGOs, insurers, and public-sector teams
find facts in report collections faster. It must not be the sole basis for evacuation, dispatch,
medical, legal, insurance, or other high-impact decisions.

## What works today

| Capability | Default local profile | When configured |
|---|---|---|
| PDF and image text | Native PDF text plus Windows OCR fallback | Tesseract in parser/production environments |
| Text retrieval | Deterministic hash vectors plus lexical matching | BGE/SentenceTransformers embeddings |
| Visual retrieval | Placeholder/text-derived vectors only | CLIP pixel embeddings |
| Answering | Query-matched extractive answers and abstention | Vision-capable LLM synthesis with selected images |
| Routing | Deterministic vector/SQL/web heuristic | Tool-capable router model |
| Reranking | Lexical reranking | BGE cross-encoder |
| Video | Requires FFmpeg; transcription is off | FFmpeg plus Faster Whisper |
| Storage | Local files, DuckDB/SQLite, embedded Qdrant | PostgreSQL, versioned object storage, external Qdrant |

The default profile is intentionally downloadable-model-free. It is good for validating ingestion,
OCR, citations, SQL guardrails, deletion, and the UI. It is not evidence of semantic or visual-model
quality.

## Run locally on Windows

If `.venv313` is already prepared, start the API and frontend with one command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_local.ps1"
```

Open `http://127.0.0.1:8501` and use API key `local-dev-key`. The launcher safely reuses an already
healthy local copy and does not terminate unrelated processes occupying ports 8000 or 8501.

For a new checkout, follow [Start here](docs/start-here.md) once to create `.venv313` and install the
dependencies. Virtual environments are local generated files and are not part of the repository.

## Use the application

1. Open **Ingestion** and select one or more supported files.
2. Wait until every job reports `succeeded`; inspect any OCR or extraction warnings.
3. Open **Query**, keep web search off unless current official information is required, and ask a
   source-specific question.
4. Verify important numbers on the cited page or time interval.
5. Use **Reset evidence library** only when you want to delete the current tenant's indexed evidence.

Good first questions for a report include:

- `What total number of people were affected in 2024?`
- `Which disaster type caused the highest direct economic loss, and on which page is it stated?`
- `Compare the reported totals in the executive summary with the detailed table.`
- `What evidence is missing to answer how many hospital beds were damaged?`

A question such as `Which area of this satellite image has the largest burn scar?` requires pixel
interpretation. The default OCR-only profile should abstain from that question instead of guessing.

## OCR, visual retrieval, and vision are different

| Layer | Purpose | Example |
|---|---|---|
| OCR | Reads characters printed in pixels | Extract `USD 62.9 billion` from a scanned page |
| Visual embedding | Retrieves images/pages with similar visual meaning | Find likely wildfire or map pages |
| Vision-language model | Interprets selected pixels | Explain a chart, object, color, or spatial region |

A vision model is **not required for OCR**. Conversely, OCR does not understand objects, burn scars,
colors, chart geometry, or map regions. Full visual question answering generally needs both visual
retrieval and a vision-capable answer model.

See [OCR, vision, and model setup](docs/ocr-vision-and-models.md) for exact Windows OCR, Tesseract,
OpenAI-compatible tool/vision model, CLIP/BGE, re-ingestion, and validation steps.

## Architecture

```text
multiple uploads -> bounded extraction/OCR -> local or external vector index
                                                  |
question -> injection guard -> bounded router -> vector / guarded SQL / approved web snippets
                                                  |
                                      rerank -> answer -> citation verifier
```

The router sees the question but not retrieved content. Retrieved content reaches a tool-less answer
stage. Server code injects tenant filters and authorizes every tool call; model output never receives
database, shell, filesystem, or arbitrary-URL authority.

Local development uses embedded persistence for simplicity. The production reference separates the
API, ingestion workers, no-egress parsers, PostgreSQL, versioned object storage, Qdrant, identity,
secrets, and telemetry. Those manifests are a topology contract, not proof of a live highly
available deployment.

## Important limitations

- OCR can misread numbers, columns, and low-quality scans. Citations show provenance, not truth.
- Windows OCR uses an installed user-profile language and does not provide tight word boxes here.
- The vision model receives only retrieved images/pages (four by default), not every page in a file.
- Enabling a vision LLM without CLIP can interpret retrieved pixels but does not improve page
  selection.
- Parser-created boxes are source locators, not proof that a region entails an answer.
- Non-English OCR, handwriting, dense tables, charts, and low-quality media require domain testing.
- Video needs FFmpeg; speech transcription needs Faster Whisper and a reviewed model.
- Web search is disabled by default and is limited to configured official-domain snippets.
- The 46-event evaluation registry and scoring framework exist, but independent labels, private
  holdouts, six real-model runs, and public signed results do not.
- Real p50/p95/p99 latency, cost, DAST, malformed-media, load, failover, restore, organizational SSO,
  and analyst-pilot evidence remain deployment gates.
- The system is not an emergency alert feed, autonomous response agent, VAPT certificate, or
  production certification.

## Documentation

Start with the [documentation home](docs/README.md). It separates new-user instructions from model
configuration, architecture, security, operations, evaluation, and production deployment.

The most useful entry points are:

- [Start here: install, ingest, query, reset, troubleshoot](docs/start-here.md)
- [OCR, vision, and model setup](docs/ocr-vision-and-models.md)
- [Architecture and trust boundaries](docs/02-architecture.md)
- [Security threat model](docs/05-security-threat-model.md)
- [Local and production deployment](docs/06-deployment.md)
- [QA, evaluation, and VAPT status](docs/09-qa-vapt.md)
- [Security reporting policy](SECURITY.md)

## License

Project code is Apache-2.0. Dataset and uploaded assets retain their original terms and credits.
