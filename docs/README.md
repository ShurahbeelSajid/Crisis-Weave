# CrisisWeave documentation

This page is the documentation home. Use the path that matches what you are trying to do rather
than reading every file in order.

## New user path

1. [Start here](start-here.md) - install once, start the UI, upload several files, ask useful
   questions, reset the library, and solve common local errors.
2. [OCR, vision, and model setup](ocr-vision-and-models.md) - understand the three visual layers and
   configure Windows OCR, Tesseract, a tool-capable router, a vision answer model, CLIP/BGE, or
   transcription.
3. [Data ingestion and lineage](03-data-ingestion.md) - supported formats, limits, asynchronous jobs,
   source lineage, object storage, and deletion behavior.
4. [Agent, retrieval, SQL, and models](04-agent-retrieval.md) - how a question is routed, reranked,
   answered, and verified.

## Presenter or reviewer path

1. [Requirements and acceptance criteria](01-requirements.md)
2. [Architecture and trust boundaries](02-architecture.md)
3. [QA, evaluation, and VAPT status](09-qa-vapt.md)
4. [Dataset card](10-dataset-card.md)
5. [Event-disjoint benchmark](11-event-disjoint-benchmark.md)
6. [Benchmark governance and public verification](12-benchmark-governance.md)
7. [Region- and time-level visual grounding](12-region-level-grounding.md)

The benchmark documents describe a framework and release gates. They do not claim that independent
annotation, private holdouts, six real-model executions, or signed public results already exist.

## Operator and security path

1. [Security threat model](05-security-threat-model.md)
2. [Local and production deployment](06-deployment.md)
3. [Operations runbook](07-operations-runbook.md)
4. [API contract](08-api.md)
5. [Performance, HA, and release evidence](12-performance-ha-and-release-evidence.md)
6. [Kubernetes reference prerequisites](../deploy/kubernetes/README.md)
7. [Security reporting policy](../SECURITY.md)

## Current stage

| Area | Current repository state | Evidence still required outside this workspace |
|---|---|---|
| Local application | Working multi-file UI, OCR/text ingestion, retrieval, guarded SQL, citations, reset | User acceptance on target files and hardware |
| Visual intelligence | Pixel derivatives and locators exist; optional CLIP/VLM integration exists | Pinned compatible models, real region labels, visual-grounding measurements |
| Evaluation | 46-event registry, metrics, baselines, leak checks, publication gate | Blind dual annotation, adjudication, private events, six controlled runs |
| Security | Source guardrails, tenant tests, upload validation, bounded tools, reference policies | Authorized DAST, hostile-media runtime testing, exact-image scans, live SSO/RLS |
| Scale and resilience | PostgreSQL/S3/Qdrant/worker/Kubernetes contracts exist | Load, multi-zone failover, backup/restore, autoscaling, operational SLO evidence |
| Impact | Intended analyst workflow and instrumentation are defined | A limited analyst pilot measuring time saved, errors, and trust |

## Capability terminology

The following terms are intentionally not interchangeable:

- **OCR** extracts text visible in scans and images.
- **Visual embeddings** retrieve likely relevant pages or images from pixel features.
- **A vision-language model** interprets selected pixels while answering.
- **A citation** identifies source evidence; it does not prove that the source is correct.
- **Concordance** measures retrieval/source diversity; it is not answer confidence or factual
  probability.
- **Region locators** identify source coordinates or time intervals; parser-derived locators are not
  semantic entailment judgments.

## Documentation maintenance rules

- Code and validated configuration take precedence over prose when they disagree.
- Local, model-enabled, and production profiles must be described separately.
- A source-code control must not be reported as a completed live-infrastructure test.
- Benchmark plans must not be reported as benchmark results.
- OCR changes require re-ingestion; embedding changes require a fresh/versioned index and
  re-ingestion.
- Never put secrets, private benchmark labels, annotator identities, or private event material in
  documentation or committed examples.
