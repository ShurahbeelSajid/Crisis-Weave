# Performance, cost, HA, and release evidence

## Measurement boundaries

Release evidence distinguishes two scopes; they are not interchangeable:

- `end_to_end`: the query clock starts when the API receives the request and stops only after
  authorization, routing, retrieval, generation, serialization, and response completion. The
  ingestion clock starts at durable acceptance/enqueue and stops only when the job reaches a
  durable terminal state after parsing, indexing, and final commit.
- `core_operation`: an internal phase such as OCR, transcription, retrieval, reranking, LLM
  generation, `agent.ask`, or worker `ingest_path`.

The dedicated source series are
`crisisweave_query_end_to_end_duration_seconds{status_class}` and
`crisisweave_ingestion_job_end_to_end_seconds{status}`. The existing generic HTTP histogram can
corroborate request wall time, and the pipeline timers remain useful internal diagnostics. Pipeline
`query`/`ingestion` timers do **not** become complete latency merely by renaming them. A release
JSONL export must correlate the dedicated roots with pseudonymous operation IDs and root cost
records. Until a measured staging export provides the required samples, the release report
correctly fails closed.

The durable ingestion lifecycle outbox is operational telemetry, not the independent release
collector. Workers deliver it at least once, so an emit-before-ack crash can duplicate a Prometheus
observation; downstream trace/sample exports must deduplicate the stable pseudonymous operation ID.
Lease-recovery and legacy-backfill usage is explicitly marked `estimated`, while normal completed
attempts are `measured`. Estimated usage cannot satisfy complete release cost accounting. Negative
clock-skew samples and lifecycle durations over 30 days are counted and logged as exclusions, never
clamped to a plausible zero. Historical OTel spans use the durable enqueue and terminal timestamps.
The production API can insert terminal events but cannot inspect, claim, acknowledge, or prune the
global outbox; only ingestion workers perform delivery and bounded delivered-row retention. Monitor
the pending-count, oldest-pending-age and bounded delivery-failure series; the Kubernetes reference
raises `CrisisWeaveLifecycleOutboxStale` after an event is older than 300 seconds for ten minutes.

No query text, tenant ID, user ID, API key, authorization header, source URL, filename, or uploaded
content may appear in a metric label or span attribute. IDs used by the offline export must be
pseudonymous and unique to the run.

## Performance report v2

Each JSON Lines record must match `scripts.performance_report.PerformanceSample` schema version 2.
It binds a sample to one immutable `profile_id`, one `run_id`, a unique `sample_id`, and an
`operation_id`, plus a timezone-aware observation time. Root `query` and `ingestion` records must
declare `measurement_scope=end_to_end`; all child phases must declare
`measurement_scope=core_operation`. Every operation has exactly one root. Warmups are marked and
excluded. One run may span no more than seven days, and its price sheet must already be effective
when every priced root is observed.

The release-tail floor is **1,000 non-warmup observations for every present and required phase**.
The default release profile requires all seven phases and therefore at least 1,000 complete query
operations and 1,000 complete document operations. This provides about ten observations in the
nominal top one percent; use more samples when tighter p99 uncertainty is required. Thirty-sample
p99 claims are rejected.

Root records alone carry cost and usage, preventing child-span double counting. Each root requires:

- complete accounting and a non-placeholder price-sheet SHA-256;
- one timezone-aware price-sheet effective time for the run;
- a positive per-operation USD cost;
- a cost basis of `provider_usage`, `allocated_compute`, or `blended`;
- measured token usage for provider-priced query calls, measured input bytes for provider-priced
  document work, and positive wall time for compute allocation.

A zero price or zero operation cost is not evidence that a model, host, OCR service, or storage
operation was free. Account for on-premises inference through reviewed compute allocation. The
price sheet must include model/API prices, GPU/CPU allocation, storage/request charges, currency,
effective time, and the allocation method.

Run the report with the release floor:

```powershell
python scripts/performance_report.py `
  --input measurements.jsonl `
  --output performance-report.json `
  --profile gpu-a10-v1 `
  --minimum-samples-per-stage 1000 `
  --slo approved-slo.json
```

The report emits schema version 2, the measurement window, scope contract, linear-interpolated
mean/min/max/p50/p95/p99, per-phase error rates, a separate root-operation error rate, total
bytes/tokens/cost, and p50/p95/p99 cost per document and query. The release SLO uses the
root-operation error rate; it does not dilute failures by dividing them across child observations.
The report rejects mixed runs/profiles/price sheets/effective times, duplicate IDs, incomplete
operations, zero costs, non-finite values, unknown fields, weak sample counts, and ambiguous scope.
SLO failure exits with status 2.

Measure cold-cache, warm-cache, steady-state, and expected burst profiles separately. Never merge
different model revisions, hardware, concurrency, cache state, database topology, object-store
region, or price effective dates into one percentile. Preserve raw samples so an independent party
can recompute every aggregate.

## Signed, byte-bound release evidence v2

`scripts/validate_release_evidence.py` accepts only schema version 2. A release envelope contains
semantic claims plus an exact `artifact_bindings` entry for every digest claim. Bindings use a
normalized relative path, byte size, and SHA-256. The required set includes:

- raw registry-manifest bytes for every promoted image;
- rendered configuration and the model bundle;
- the independent assessor report;
- PostgreSQL failover/restore, object-store restore, and Qdrant snapshot/restore artifacts;
- DAST, malformed-media, dependency, identity, and analyst-pilot reports;
- the platform verification report, raw performance report, reviewed price sheet, and
  hardware/profile description.

The verifier resolves each path below an immutable artifact root, rejects traversal and duplicate
paths, streams and re-hashes every regular file, checks its signed size, and detects mutation during
the read. A digest-looking string without matching bytes is rejected.

An independent custodian then signs the **exact release-envelope bytes** with Ed25519. The
promotion system must pin both the custodian public key and its expected SHA-256 key ID outside the
candidate repository. The candidate system must never receive the private key. The existing
`benchmark_governance.py sign-report` command can define the interoperable signature-envelope
format, but signing must run in the custodian account or independent harness—not in the evaluated
deployment.

Run verification from that independently controlled promotion environment:

```powershell
python scripts/validate_release_evidence.py release-evidence.json `
  --artifact-root D:\immutable-release-artifacts `
  --signature D:\custodian\release-evidence.signature.json `
  --trusted-public-key D:\promotion-trust\release-custodian.pub.pem `
  --expected-signer-key-id sha256:<pinned-64-hex-key-id>
```

Verification is ordered as follows:

1. Strictly parse the signed v2 envelope and signature envelope.
2. Derive the Ed25519 public-key ID and compare it with the independently configured pin.
3. Verify the envelope SHA-256 and signature over its exact bytes.
4. Re-hash every bound artifact under the immutable root.
5. Strictly parse the bound performance report and cross-check its profile, run ID, measurement
   window, scopes, sample counts, error rate, price-sheet provenance, latency percentiles, and
   operation-cost percentiles against the signed load claims.
6. Apply freshness, HA, security, identity, platform, load, cost, pilot, RPO/RTO, and SLO policy.

Promotion fails unless load evidence names immutable production model revisions, binds the hardware
profile and price sheet, declares USD cost bases, contains no zero-cost operations, runs at at least
2x expected peak, and includes at least 1,000 observations for each phase and each query/document
cost distribution. `query` and `ingestion` must be end-to-end; internal phases must be core scope.
The signed load claims are not trusted as a second source of truth: they must exactly match the
bound, schema-v2 performance-report aggregates. The gate also requires positive ordered p50/p95/p99
costs and latency, complete accounting, and the configured p95/p99/error thresholds.

The remaining HA and security requirements are:

- at least two ready PostgreSQL replicas in distinct zones, verified TLS, denied runtime DDL,
  denied cross-tenant RLS access, and fresh passing failover/restore drills within policy RPO/RTO;
- encrypted, versioned, cross-region object replication, exact-version deletion testing, bounded
  lag, and a fresh passing restore;
- Qdrant replication across zones, encrypted replicated backups, a fresh snapshot, and a passing
  restore;
- fresh DAST, malformed-media, dependency, parser-isolation, prompt-injection, OIDC, RBAC, tenant
  isolation, key rotation/revocation, audit-chain, and retention evidence;
- a completed measured analyst pilot with at least two analysts and twenty tasks, bounded
  unsupported claims, no severe incident, and a strictly positive median evidence-discovery time
  reduction. The default gate requires at least a 1% reduction (reported as
  `median_time_change_percent <= -1.0`); a zero or slower result cannot pass.

`platform.report` is a mandatory, byte-bound artifact. Its signed evidence must attest to the
observed zones, autoscaling, enforced NetworkPolicy and destination-level egress denial, STRICT
mTLS and plaintext denial, External Secret synchronization and rotation rollout, OpenTelemetry trace
delivery, Prometheus SLO series, and alert delivery. Manifests and reference topology alone do not
satisfy this evidence requirement.

All envelope, component, drill, snapshot, and price timestamps are timezone-aware. Freshening the
outer envelope cannot freshen an old component report. Placeholder hashes, missing files, extra or
missing bindings, wrong signer keys, stale evidence, and malformed signatures are rejected.

## What source code cannot prove

Repository tests prove only schema, calculation, byte-binding, and gate behavior. They do not create
real percentiles, real provider invoices, independent signatures, multi-zone failover, restores,
security scans, or analyst outcomes. Promotion remains blocked until production-model staging runs
produce the raw samples and artifacts and an organizationally independent harness verifies them.
Publish the raw per-profile report, price/hardware provenance, signer key ID, and verification result
alongside any public latency or cost claim.
