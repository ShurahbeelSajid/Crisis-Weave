# Requirements and acceptance criteria

## Product objective

CrisisWeave must let an authenticated researcher upload multimodal disaster evidence and ask a
complex question that may require semantic/visual retrieval, numerical aggregation, and a current
official-source check. The response must identify which tools ran, cite authorized evidence, expose
limitations, and abstain when evidence is missing.

Absolute worldwide novelty is not an auditable requirement. The product-level differentiator is a
reproducible event evidence chain plus a concordance score that measures source/modality diversity
without presenting it as factual certainty.

At the current stage, the product is intended to reduce the time needed to discover and compare
evidence in a bounded report collection. It can demonstrate ingestion, OCR, retrieval, guarded
analytics, citations, abstention, and production-oriented control boundaries. A requirement marked
as implemented in source is not automatically validated on real models or live infrastructure; the
QA/VAPT document lists the external release evidence that remains open.

## Actors and assumptions

- **Researcher:** uploads and queries evidence belonging to one tenant.
- **Human reviewer:** independently approves or rejects a withheld consequential answer; a service
  identity and the original requester cannot satisfy this role.
- **Operator:** configures providers, secrets, quotas, backups, model revisions, and incident controls.
- **Auditor:** reviews query/tool metadata without needing raw prompt logs.
- **Benchmark annotators/adjudicator:** two qualified domain annotators label blind packets
  independently; a third qualified person resolves every disagreement.
- **Evaluation custodian:** holds private events, plaintext test labels, escrow/signing keys and the
  independently operated harness outside developer and serving-system access.
- Production uses PostgreSQL leasing, versioned object storage, multiple API workers, and isolated
  ingestion-worker and parser-service deployments. A one-shot privileged migration job must complete before runtime rollout;
  API/worker database roles are DML-only and never migrate at startup.
- A worker streams one authenticated, size- and digest-bound payload to the no-egress parser service;
  the parser uses request-private temporary storage and returns bounded artifacts. The two roles do
  not share a filesystem, and both deployments enforce independent concurrency limits.
- Uploaded and retrieved content is untrusted. Provider endpoints, Qdrant, and search results may
  fail or be adversarial.

## Functional requirements

| ID | Requirement | Acceptance criterion |
|---|---|---|
| FR-01 | Accept PDF, JPEG/PNG/WebP, MP4/WebM, CSV, JSON, TXT/MD/SRT/VTT | Magic bytes and extension must agree; unsupported content returns 422 |
| FR-02 | Extract PDF text and visual pages | Each accepted page produces lineage with page number; page/render limits are enforced |
| FR-03 | Extract OCR text and visual evidence independently | OCR is recorded when available without claiming pixel understanding; real visual embeddings index pixels separately in production |
| FR-04 | Extract video frames and transcript | Duration/frame limits apply; sampled frames have timecodes; configured transcription produces timestamped chunks |
| FR-05 | Index text and visual evidence | Qdrant uses named vectors, asymmetric document/query text encoding, and mandatory tenant filtering |
| FR-06 | Route tools agentically | LangGraph selects vector, SQL, web, or a bounded combination; trace is returned |
| FR-07 | Run analytics | Only an AST-approved, server-capped `SELECT` executes; result rows carry bounded contributing-document provenance without claiming cell-level causality |
| FR-08 | Search current sources | Search is request-opt-in, provider-configured, snippet-only, and domain allowlisted |
| FR-09 | Rerank and diversify | Candidates are reranked; one document cannot fill the entire answer context |
| FR-10 | Ground and cite answers | Unsupported citation labels are removed; no-evidence queries abstain |
| FR-11 | Report confidence correctly | Concordance explains source/modality coverage and explicitly disclaims certainty |
| FR-12 | Manage evidence | Tenant can list, retrieve metadata for, deduplicate, and delete its documents/derivatives |
| FR-13 | Run durable asynchronous ingestion | Multi-file uploads return tenant-scoped jobs with progress, bounded retry/backoff, cooperative cancellation, lease recovery, explicit dead-letter retry, resumable immutable inputs, and durable cleanup reconciliation |
| FR-14 | Evaluate without event leakage | The 46-event global registry uses event-disjoint train/development/test splits and measures retrieval, routing, SQL, citations, visual regions, abstention, injection, cost, and latency against the full candidate plus five independently executed simpler baselines; pretraining exposure is reported separately for historical, recent and private events |
| FR-15 | Localize visual support without overstating it | Evidence/citations carry bounded typed image/PDF boxes, chart references and video ranges with an explicit source; parser output remains provenance-only, while benchmark model proposals are scored one-to-one against human annotations |
| FR-16 | Authenticate and authorize people and services | Production accepts asymmetric OIDC access tokens and optional explicitly bound service keys; tenant, roles and user/service identity type are server-derived, and every endpoint enforces a named RBAC permission |
| FR-17 | Withhold consequential answers for review | High-risk, low-confidence, conflicting or stale-evidence responses return a review ID instead of the candidate answer; decisions are tenant-scoped, maker-checker, human-only, terminal and audited |
| FR-18 | Measure real operations | Root receipt-to-final-body query and enqueue-to-terminal ingestion metrics are distinct from OCR, transcription, retrieval, reranking, LLM-generation and core-pipeline spans; an independently collected raw sample envelope reports p50/p95/p99 plus token, compute, per-query and per-document cost against one explicit price sheet without double-counting child spans; recovered or backfilled lifecycle observations are marked estimated and cannot satisfy release cost evidence |
| FR-19 | Publish only independently controlled results | Test labels are encrypted to a custodian key, public reports require an external Ed25519 signature, and publication fails unless adjudication, IAA, private holdouts, six equal-setting runs, at least five distinct test events per advertised metric, exact denominators, per-event results and internally consistent confidence intervals are all present |

## Non-functional requirements

- **Security:** OIDC/RBAC, explicit user/service identities, production PostgreSQL RLS, server-derived
  tenant scope, no public data stores, exact origins/hosts, bounded tools, safe upload handling,
  centrally managed secrets, retained audit metadata, and zero exploitable Critical/High release
  findings.
- **Reliability:** idempotent SHA-256 deduplication, bounded retries (provider SDK layer), health checks,
  graceful model fallbacks, and tested backup/restore before production.
- **Performance targets (staging gates):** p95 complete query under 10 seconds, including provider and response-transfer latency;
  p95 text/PDF-page ingestion under the agreed hardware baseline; less than 1% 5xx at expected load.
- **Privacy:** raw questions are not logged by default; audit table stores query hashes, route, latency,
  citation count, and policy flags. Providers receive only the bounded context needed for synthesis.
- **Accessibility:** Streamlit controls are labeled; core workflows remain available through the API.
- **Reproducibility:** dependency lock, container digest, model revision/checksum, prompt version,
  reviewed dataset provenance lock, manifest and extraction settings are release artifacts. The
  repository pins runtime dependencies in `pyproject.toml`, but it does not include a resolved
  platform lock/SBOM or pre-trusted dataset content hashes. The downloader creates a local TOFU lock
  on first use; a release owner must review and preserve that lock independently.
- **Benchmark integrity:** test labels remain custodian-controlled; scoring requires one explicit
  split, canonical artifact digests, evaluator-owned raw traces, blind dual annotation, a third
  adjudicator, pre-adjudication agreement, private-event commitments and a matching asymmetric
  attestation. No benchmark score may be published while any publication gate is open.
- **Operational evidence:** production promotion requires fresh, artifact-bound evidence for OIDC
  and key rotation, database tenant isolation, destination egress, DAST/malformed media, load,
  failover/restore, replication, SLOs, real cost/latency and an analyst pilot.

## Explicitly out of scope for v1

- Autonomous write actions, shell/Python tools, arbitrary URL browsing, and emergency dispatch.
- Medical, legal, insurance, or evacuation decisions.
- Persistent conversational memory and cross-tenant sharing.
- Cross-region queue federation and per-job VM/microVM parsing isolation.
- A claim that the benchmark or technique is globally unprecedented.

## Definition of done

Code, configuration, docs, Docker assets, tests and scanners must pass; tenant-negative, SQL abuse,
prompt-injection, upload-signature, citation, and deletion cases must be automated. A staging release
also requires real-model retrieval evaluation, malformed-media tests with FFmpeg/Tesseract, load test,
backup/restore, AV-definition freshness, TLS/Qdrant policy checks, and authorized DAST. See the QA/VAPT
report for the exact distinction between repository verification and environment gates.

Repository checks and environment-specific release gates are reported separately in the QA/VAPT
document. Passing source tests alone never satisfies the staging definition of done.
