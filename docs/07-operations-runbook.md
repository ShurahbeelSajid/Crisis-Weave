# Operations runbook

## Service-level indicators

Monitor request rate/error/p50-p95-p99 latency, rate-limit rejects, complete HTTP-query latency,
enqueue-to-terminal ingestion latency, core query/tool latency, tool rejects,
no-evidence rate, citation coverage, concordance distribution, ingestion success/duration/backlog,
lease age/dead letters, parser timeout, PostgreSQL/S3/Qdrant health, disk/RAM/CPU/GPU, model
tokens/cost and provider error rate.
API metrics are at authenticated `/metrics`. Dedicated workers expose a separate network-restricted
metrics port without tenant/content labels; it includes lifecycle-status and ready/retry queue gauges.

Suggested initial objectives after baseline load testing:

- API availability 99.9% monthly, excluding declared maintenance.
- Less than 1% server errors at expected load.
- 100% citation-ID authorization/validity.
- 100% blocked unsafe SQL corpus.
- Backup RPO at most 1 hour and RTO at most 2 hours, matching the release validator defaults. If the
  business approves different targets, pass them explicitly to the validator and update every runbook,
  alert and restore drill consistently.

## Start and readiness

1. Export every required variable listed in `06-deployment.md`, then run
   `docker compose -f deploy/compose.production.yaml config` and review the rendered configuration
   without copying secrets into tickets/logs.
2. Run the one-shot `migrate` service and require exit code 0 before API/worker rollout. Confirm the
   migration log contains no DSN/key, schema version 5 exists, forced RLS is enabled, and API/worker
   roles are neither owners nor `SUPERUSER`/`BYPASSRLS`, have schema
   `USAGE`, `SELECT`-only access to `schema_migrations`, and only their documented per-table DML, but
   no schema/database `CREATE`, object ownership, broad all-table or future-table grant. The migration also provisions/validates the
   Qdrant collection marker and payload indexes. Then start the exact immutable image digests and
   confirm ClamAV definitions, bundled models and model manifest are present.
3. `/health/live` proves only API process liveness. Production API `/health/ready` reports its
   PostgreSQL, versioned object-storage and Qdrant dependencies; it deliberately does not possess
   parser/ClamAV credentials. Require every value to be `ok` before traffic. Independently require
   worker/parser/ClamAV health and prove queue leases are advancing before enabling ingestion.
4. Confirm the parser has no application-data volume and no general egress. In Compose, prove each
   pair-specific network permits only its worker/parser hop. In Kubernetes, prove parser pods are
   separate from workers, strict mesh mTLS is active and NetworkPolicy is enforced; labels/YAML alone
   are insufficient.
5. Run OIDC user and service-key authentication canaries, every critical RBAC denial, a
   cross-tenant RLS/Qdrant negative, one maker-checker review, and a canary upload/query/delete using
   a dedicated tenant. Verify the streamed parser exchange, parser-private temporary cleanup and
   explicit source freshness.
6. Fetch API `/metrics` with the distinct metrics credential and fetch each worker's metrics only
   from the monitoring network. Confirm metrics/logs/traces contain no
   planted canary secret, prompt, evidence content or tenant label. Reconcile one query and document
   core-operation cost against the configured price sheet without duplicated child charges, and
   separately reconcile the end-to-end performance-v2 sample against infrastructure/provider
   billing. Confirm
   `crisisweave_ingestion_jobs`, `crisisweave_ingestion_queue_ready` and refresh-failure metrics move
   with a canary job. A reachable worker metrics port proves only process/listener health.
7. Verify destination-policy logs: API can reach only PostgreSQL/S3/Qdrant/approved model-search
   endpoints, worker only PostgreSQL/S3/Qdrant plus internal parser/ClamAV, and migration only
   PostgreSQL/Qdrant. Prove denied cross-role destinations; separate Docker networks alone are not
   evidence of an allowlist.

## Common incidents

### Qdrant unavailable

Readiness degrades. Stop new ingestion/query traffic, confirm TLS/DNS/key/quota, restore service or
snapshot, then run vector ownership/citation canary tests. Do not silently recreate an empty production
collection unless index rebuild is an approved recovery action.

### PostgreSQL unavailable or migration failure

Stop new jobs and drain writes; do not switch production to DuckDB. Check TLS hostname/CA, scoped
role, pool exhaustion, locks, disk/WAL and replica state. Preserve logs without DSNs, restore/PITR
into isolation if required, then reconcile PostgreSQL document/job state with Qdrant and exact object
references before reopening. A schema rollback requires the documented expand/contract procedure.
Never grant DDL to an API/worker role to bypass a migration failure. Fix or roll forward with the
short-lived migration identity, then revoke/disable that credential after the rollout.

### Object store unavailable, unversioned or integrity mismatch

Readiness and ingestion must fail closed. Verify private endpoint/TLS, workload identity, bucket
versioning, SSE/KMS access and prefix policy. Do not replace an exact `versionId` with the mutable
latest key. Quarantine integrity-mismatched versions, retain audit metadata, assess all documents
sharing the hash and restore the exact version from replication/backup. Run upload/read/delete and
cross-tenant negative canaries before traffic resumes.

### LLM/search provider outage

Disable web search or provider keys via configuration/egress. The service falls back to heuristic
routing/extractive answers and returns warnings. If fallback quality violates policy, fail queries at
the gateway instead. Track provider status without leaking keys or prompts.

### Suspected prompt/vector poisoning

Disable ingestion, identify hashes/document IDs from audit and source provenance, quarantine/delete
affected points and artifacts, rebuild the index from trusted manifests, rotate provider credentials
if disclosure is possible, and rerun the adversarial/citation suite before reopening.

### Malicious upload/parser alert

Preserve the quarantine hash and security logs under incident policy; never open the file on an
operator workstation. Drain ingestion, isolate affected worker/parser replicas, preserve authorized
forensic artifacts outside the live parser, and rotate the parser-service token. Parser request temp
is intentionally ephemeral and there is no shared exchange volume. The parser has no application/
provider credentials in the reference topology, but investigate the worker and rotate additional
secrets if the network boundary was violated. Patch parser/image dependencies, update AV, rebuild
from a clean signed base, and replay the malformed-media corpus in an isolated environment before
reopening.

### Parser unavailable or parser temporary cleanup concern

The production API can remain ready and can still enqueue jobs because it deliberately has no parser
credential. Pause new ingestion at the gateway/operator layer, monitor retry/dead-letter and queue
gauges, and do not bypass the parser service by enabling in-process parsing. Parser request
directories use `TemporaryDirectory` cleanup, but an abrupt container/runtime failure discards its
ephemeral `/tmp`; unexpected persistent files indicate a deployment-policy violation. Recover the
parser, run an authenticated health/capability canary, then retry only integrity-bound jobs.

### Secret exposure

Revoke first, then rotate OIDC signing/session material as coordinated with the identity owner,
service/metrics/parser/model/search/Qdrant keys, invalidate sessions/caches, search logs,
traces, images and git history using a canary-safe process, notify impacted parties, and document root
cause. Removing a secret from the current file does not remove it from history.

### Identity, RLS or review-control failure

Disable affected login/key and consequential-query release first. Preserve identity/review audit
events in the external immutable sink. Verify issuer/audience/claim mapping, JWKS rotation, proxy
header replacement, principal roles and database session tenant binding. A service identity or the
requester must never approve its own candidate. Treat any cross-tenant row/vector/review visibility,
runtime `BYPASSRLS`/ownership or directly reachable forwarded-bearer UI as a high-severity incident;
isolate the workload and rotate all affected database/vector credentials before reopening.

### Telemetry or cost-accounting failure

Stop publishing performance/cost claims and fail the release evidence gate. Verify the dedicated
OTLP CA/header, exporter destination, core-operation accounting, end-to-end Prometheus histograms,
independent performance-v2 raw samples, token usage, price-sheet digest, sampling and clock
synchronization. Never infer per-operation evidence from aggregate histogram buckets or solve
collector TLS by replacing the process-wide trust store. Backfill only from independently retained
provider/infrastructure billing records and label any incomplete interval explicitly. Alert on
lifecycle outbox backlog, delivery failures and `clock_skew`/`older_than_30_days` exclusions;
deduplicate at-least-once lifecycle exports by stable operation ID, and exclude
`measurement_quality=estimated` recovery/backfill cost from release accounting. Verify API,
workers, PostgreSQL and the independent harness use authenticated time synchronization before
reopening publication. The concrete backlog series are
`crisisweave_ingestion_lifecycle_outbox_pending` and
`crisisweave_ingestion_lifecycle_outbox_oldest_pending_seconds`; delivery failures use
`crisisweave_ingestion_lifecycle_delivery_failures_total{stage}` with only `claim`, `emit`, `ack`,
or `prune`. The checked-in critical alert fires when the oldest pending event exceeds 300 seconds
for ten minutes.

## Backup and restore drill

1. Drain writes or establish an application-consistent checkpoint; capture PostgreSQL/PITR position
   and the corresponding versioned-bucket inventory. Exclude worker and parser ephemeral temp data.
2. Snapshot Qdrant with its supported API and record collection/model schema/version.
3. Encrypt, checksum and store database, object and vector backups in separate failure domains with
   tested access controls and retention/legal-hold policy.
4. Restore into an isolated environment; verify row/object/vector counts, exact version IDs,
   SHA-256 metadata, tenant-negative cases, queue leases and golden queries.
5. Exercise tenant deletion plus noncurrent-version/orphan expiry, record achieved RPO/RTO, and
   securely delete the drill environment.

## Rotation and maintenance

- Rotate service keys with overlapping explicit key IDs, then revoke the old ID after clients move;
  rehearse OIDC signing-key rotation/cache refresh and organizational session revocation. Rotate
   metrics, parser, model, search and Qdrant credentials independently on a documented cadence and
   immediately after exposure; the parser token must never equal another credential.
- External Secrets refreshes Kubernetes Secret objects but does not update process environment by
  itself. Install and pin Stakater Reloader or an equivalent controlled rollout mechanism, verify the
  annotated workload actually rolls, then prove the new credential succeeds and the revoked old
  credential fails. An annotation without the controller is not rotation evidence.
- Rotate API/worker/migration PostgreSQL, Qdrant, and S3 identities independently. Keep the migration
  identities disabled or unavailable to runtime pods between approved schema changes.
- Weekly dependency/image/model advisories; monthly restore and adversarial canary; quarterly VAPT.
- Re-evaluate after model, prompt, parser, format, vector schema, provider or policy changes.
- Reindex through a new Qdrant collection and alias; retain rollback until evaluation passes.
- Dedicated ingestion workers process one bounded recovery batch on startup and every 60 seconds;
  alert if `processing`, `deleting`, or `cleanup_pending` age keeps growing across intervals.
- Attach fresh DAST, malformed-media, p50/p95/p99 load/cost, multi-zone failover, object/Qdrant
  replication/restore, OIDC/RBAC/rotation/audit and analyst-pilot artifacts to the release validator;
  passing manifest/unit tests does not renew operational evidence.
