# Local and production deployment

## Profiles

| Profile | Purpose | Providers |
|---|---|---|
| Test | Offline CI, temporary data | in-memory Qdrant, hash embeddings, lexical reranker, no LLM/web |
| Development | Local demo and pipeline validation | embedded or Compose Qdrant; optional local OpenAI-compatible model |
| Production | Shared durable topology | PostgreSQL, versioned S3, HTTPS external Qdrant, real models, AV, dedicated workers/no-egress parsers |

## Native local setup

1. Install Python 3.12 or 3.13. Install FFmpeg/ffprobe only for video. Tesseract is optional for
   Windows development because the launcher can use Windows Runtime OCR; parser/production profiles
   require the configured executable.
2. Create `.venv313` and run
   `& .\.venv313\Scripts\python.exe -m pip install -e ".[dev,ui,telemetry]"` (add `ml` for real
   embeddings, reranking, or transcription).
3. Copy `.env.example` to `.env` and keep `CRISISWEAVE_APP_ENV=development`.
4. Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_local.ps1"` to start
   the API and Streamlit together, or use the manual two-process commands in
   [Start here](start-here.md).
5. Use `CRISISWEAVE_DATA_DIR` on a volume with sufficient space. Do not share an embedded Qdrant
   path across processes.

The Windows launcher supplies process-level safe defaults for local providers when variables are
absent. Set any LLM/embedding/reranker/transcription overrides in PowerShell before invoking it; an
already-running healthy copy keeps its existing configuration. Exact OCR, provider canary, and
fresh-index steps are in [OCR, vision, and model setup](ocr-vision-and-models.md).

Development defaults `CRISISWEAVE_INGESTION_WORKER_ENABLED=true`, so the API consumes durable jobs
locally. To exercise the split-worker topology, set it to `false` for the API and run
`crisisweave ingestion-worker`; `--once` processes at most one available job for smoke tests.

## Compose development

`docker compose up --build` starts private Qdrant, one API process and Streamlit. Loopback bindings
prevent LAN exposure. The development API image includes FFmpeg and Tesseract but uses hash
embeddings, a lexical reranker, disabled transcription/LLM by default, and no ClamAV service. The UI
uses its dedicated runtime target. Containers run as non-root with read-only roots, tmpfs scratch,
dropped capabilities and resource limits.

The default Compose credentials are development-only. Docker is not installed in every developer
environment; validate the image and Compose health checks in CI/staging before release.

## Production Compose contract

`deploy/compose.production.yaml` is a standalone production reference, not an overlay for
`compose.yaml`. Build and promote four immutable project images first:

- `CRISISWEAVE_API_IMAGE`: the Dockerfile `model-bundle` target with four immutable model revisions;
  this same image runs the API and parser service.
- `CRISISWEAVE_UI_IMAGE`: the Dockerfile `runtime-ui` target.
- `CRISISWEAVE_CADDY_IMAGE`: the Dockerfile `gateway` target, which binds the reviewed Caddyfile to
  the promoted image digest instead of loading mutable host configuration.
- `CRISISWEAVE_CLAMAV_IMAGE`: the Dockerfile `clamav-runtime` target, which derives from an official
  ClamAV 1.5 base digest and binds the reviewed `StreamMaxLength` to the promoted image.

An illustrative build is below. Replace every digest/revision placeholder, scan the resulting images,
then push/sign them and use the registry digests—not the mutable build tags—in Compose.

```bash
docker build --target model-bundle \
  --build-arg PYTHON_IMAGE='python:3.12.13-slim-bookworm@sha256:<base-digest>' \
  --build-arg TEXT_REVISION='<40-char-commit>' \
  --build-arg VISUAL_REVISION='<40-char-commit>' \
  --build-arg RERANKER_REVISION='<40-char-commit>' \
  --build-arg WHISPER_REVISION='<40-char-commit>' \
  -t crisisweave-api:release-candidate .

docker build --target runtime-ui \
  --build-arg PYTHON_IMAGE='python:3.12.13-slim-bookworm@sha256:<base-digest>' \
  -t crisisweave-ui:release-candidate .

docker build --target gateway \
  --build-arg CADDY_IMAGE='caddy:2.11.4-alpine@sha256:<base-digest>' \
  -t crisisweave-gateway:release-candidate .

docker build --target clamav-runtime \
  --build-arg CLAMAV_IMAGE='clamav/clamav:1.5.2_base@sha256:<base-digest>' \
  -t crisisweave-clamav:release-candidate .
```

All four promoted image values must contain an `@sha256:<64-hex-digest>` reference. Compose's
required-variable syntax checks presence,
while `scripts/validate_production_config.py` rejects mutable tags, all-zero placeholders, reused
service references, unsafe gateway domains and a gateway/CORS/trusted-host mismatch. Registry
signature, attestation and digest-to-approved-version verification remain promotion-system gates.

The `model-bundle` build writes a schema-v2 `/models/bundle.json` containing the immutable repository
revision, relative path, byte size and SHA-256 of every bundled model file. The build verifies it once,
and the image entrypoint verifies it again before executing either the API or parser command. Any
extra, missing, linked or modified model file fails closed before application startup. Hugging Face's
disposable `local_dir` metadata is removed from the Whisper directory before the manifest is created.

The following is the complete set of host-supplied variables required by the production Compose
file. Placeholder credentials must be replaced with distinct secret-manager values of at least 24
characters where the application enforces that minimum.

```bash
export CRISISWEAVE_CLAMAV_IMAGE='registry.example/crisisweave-clamav@sha256:<64-hex-digest>'
export CRISISWEAVE_API_IMAGE='registry.example/crisisweave-api@sha256:<64-hex-digest>'
export CRISISWEAVE_UI_IMAGE='registry.example/crisisweave-ui@sha256:<64-hex-digest>'
export CRISISWEAVE_CADDY_IMAGE='registry.example/crisisweave-gateway@sha256:<64-hex-digest>'

export CRISISWEAVE_DOMAIN='crisis.example.org'
export CRISISWEAVE_CORS_ORIGINS='https://crisis.example.org'
export CRISISWEAVE_TRUSTED_HOSTS='crisis.example.org,api'
export CRISISWEAVE_GATEWAY_IPV4='172.30.77.10'
export CRISISWEAVE_API_GATEWAY_SUBNET='172.30.77.0/24'
# Trust only Caddy's fixed address. A subnet or 0.0.0.0/0 is rejected by preflight.
export CRISISWEAVE_FORWARDED_ALLOW_IPS='172.30.77.10/32'
export CRISISWEAVE_AUTH_MODE='hybrid'
export CRISISWEAVE_OIDC_ISSUER_URL='https://identity.example.org/realms/crisisweave'
export CRISISWEAVE_OIDC_AUDIENCE='crisisweave-api'
export CRISISWEAVE_OIDC_JWKS_URL='https://identity.example.org/realms/crisisweave/jwks'
export CRISISWEAVE_OIDC_TENANT_CLAIM='tenant_id'
export CRISISWEAVE_OIDC_ROLES_CLAIM='roles'
export CRISISWEAVE_OIDC_IDENTITY_TYPE_CLAIM='identity_type'
# The standalone Streamlit reference accepts this scoped service identity. Omit both values and use
# auth_mode=oidc for an API-only deployment, or use the Kubernetes auth-proxy/BFF browser topology.
export CRISISWEAVE_API_KEYS='research@ui-2026=<high-entropy-service-key>'
export CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS='research@ui-2026=operator'
export CRISISWEAVE_METRICS_API_KEY='<distinct-high-entropy-metrics-key>'
export CRISISWEAVE_PARSER_SERVICE_TOKEN='<distinct-high-entropy-parser-key>'
# SHA-256 of the reviewed, rendered firewall/network-policy artifact applied to this release.
export CRISISWEAVE_EGRESS_POLICY_SHA256='<64-hex-policy-digest>'

export CRISISWEAVE_DATABASE_BACKEND='postgresql'
export CRISISWEAVE_POSTGRES_API_ROLE='crisisweave_api'
export CRISISWEAVE_POSTGRES_WORKER_ROLE='crisisweave_worker'
export CRISISWEAVE_API_POSTGRES_DSN='postgresql://crisisweave_api:<secret>@<host>/<database>?sslmode=verify-full'
export CRISISWEAVE_WORKER_POSTGRES_DSN='postgresql://crisisweave_worker:<secret>@<host>/<database>?sslmode=verify-full'
export CRISISWEAVE_MIGRATION_POSTGRES_DSN='postgresql://crisisweave_migrator:<secret>@<host>/<database>?sslmode=verify-full'
export CRISISWEAVE_OBJECT_STORE_BACKEND='s3'
export CRISISWEAVE_S3_BUCKET='crisisweave-production-evidence'
export CRISISWEAVE_S3_PREFIX='crisisweave'
export CRISISWEAVE_S3_REGION='<approved-region>'
# Set only for a private S3-compatible service; production validation requires HTTPS.
export CRISISWEAVE_S3_ENDPOINT_URL=''
export CRISISWEAVE_API_S3_ACCESS_KEY_ID='<api-prefix-identity>'
export CRISISWEAVE_API_S3_SECRET_ACCESS_KEY='<api-prefix-secret>'
export CRISISWEAVE_WORKER_S3_ACCESS_KEY_ID='<worker-prefix-identity>'
export CRISISWEAVE_WORKER_S3_SECRET_ACCESS_KEY='<worker-prefix-secret>'

export CRISISWEAVE_QDRANT_URL='https://qdrant.private.example.org'
export CRISISWEAVE_API_QDRANT_API_KEY='<api-scoped-qdrant-key>'
export CRISISWEAVE_WORKER_QDRANT_API_KEY='<worker-scoped-qdrant-key>'
export CRISISWEAVE_MIGRATION_QDRANT_API_KEY='<schema-scoped-qdrant-key>'
export CRISISWEAVE_LLM_BASE_URL='https://llm-gateway.private.example.org/v1'
export CRISISWEAVE_LLM_API_KEY='<scoped-model-gateway-key>'
export CRISISWEAVE_LLM_ROUTER_MODEL='approved-tool-capable-model'
export CRISISWEAVE_LLM_ANSWER_MODEL='approved-vision-capable-model'
export CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT='https://otel.private.example.org/v1/traces'
# Absolute host path to the CA bundle that verifies only this OTLP destination. Compose mounts it
# read-only at /run/crisisweave/otel-ca.crt in the API and workers.
export CRISISWEAVE_OTEL_CA_HOST_PATH='/etc/crisisweave/otel-ca.crt'
export CRISISWEAVE_QUERY_COMPUTE_COST_PER_HOUR_USD='2.50'
export CRISISWEAVE_INGESTION_COMPUTE_COST_PER_HOUR_USD='4.25'

# Optional; leave disabled unless Tavily and its official-domain policy are approved.
export CRISISWEAVE_WEB_SEARCH_PROVIDER='disabled'
export CRISISWEAVE_TAVILY_API_KEY=''

python scripts/validate_production_config.py
docker compose -f deploy/compose.production.yaml config
docker compose -f deploy/compose.production.yaml up -d
docker compose -f deploy/compose.production.yaml logs migrate
docker compose -f deploy/compose.production.yaml ps
curl --fail --show-error "https://${CRISISWEAVE_DOMAIN}/api/health/ready"
```

Preflight verifies that all three PostgreSQL DSNs target the same database while using distinct
users, that the API/worker DSN users match the two roles granted by the migration, and that S3 and
Qdrant identities are distinct. It also requires Caddy's fixed private gateway address to belong to
the configured `/24`–`/28` subnet and requires `CRISISWEAVE_FORWARDED_ALLOW_IPS` to equal only that
address as a `/32`; trusting the entire bridge would let another attached container spoof forwarding
headers. Compose first runs the idempotent `migrate` service and starts API
and ingestion workers only after it exits successfully. Compose supplies role-specific production settings. The API receives query/auth configuration but
no parser or ClamAV credential; each ingestion worker receives parser/scan configuration but no
tenant-auth, metrics, LLM or web-search secret. The reference has two worker/parser pairs (`a` and
`b`), each with its own internal parser network and no shared filesystem. The API and UI have no
direct host ports; Caddy exposes TLS. Worker metrics are loopback-published on ports 9101 and 9102 by
default. Use a secret manager or Compose secrets in a real deployment rather than shell history.

### Identity, browser SSO and oversight

The standalone Compose UI intentionally stays in scoped-service-key mode. Its API defaults to
`hybrid`, so direct API clients may use OIDC while an explicitly role-bound service key can exercise
the thin UI. Use the `operator` role when the UI must upload, cancel jobs or reset evidence; `viewer`
is read/query-only and those controls will receive 403. That key represents a service, not an
individual, and cannot approve a human-review decision. Compose does not contain an OIDC login proxy
and must not be described as a complete multi-user SSO deployment.

For browser SSO, use the Kubernetes reference or an equivalent platform with a trusted
organizational auth proxy/BFF. It authenticates the browser, removes any client-supplied
`Authorization` header, injects its validated bearer on the private Streamlit hop, and prevents
direct access to Streamlit. Keep `CRISISWEAVE_UI_AUTH_MODE=forwarded_bearer` only behind that trust
boundary. The API still validates the JWT signature/claims itself. Pin issuer, audience, accepted
algorithms, tenant/roles/identity-type claim names and the JWKS destination; allow private JWKS only
when the URL is a reviewed internal egress-gateway route.

Production requires oversight and PostgreSQL RLS. Tune the high-risk vocabulary, confidence,
conflict and source-age thresholds with domain owners; unknown source time always remains explicit
and is mandatory review for high-risk queries. Retain review records and hash-chained identity events
according to policy, export audit events to independently administered immutable storage, and test
service-key overlap/revocation plus identity-provider key rotation before promotion.

### Telemetry, cost and SLO evidence

API and workers require an HTTPS OTLP/HTTP `/v1/traces` exporter and explicit model/compute prices.
The Compose contract requires `CRISISWEAVE_OTEL_CA_HOST_PATH` and mounts it read-only at the fixed
in-container `CRISISWEAVE_OTEL_EXPORTER_CA_FILE`; do not replace the process trust store used by
OIDC, S3, Qdrant or model endpoints. OpenTelemetry spans cover bounded core stages such as
`Agent.ask`, OCR/transcription, retrieval, reranking and generation; the `query` stage span is not the
full HTTP lifecycle. Separate Prometheus histograms measure query receipt-to-final-response and
ingestion enqueue-to-terminal lifecycle, but aggregated buckets cannot supply signed raw
per-operation evidence.

The lifecycle outbox is delivered at least once. Use its stable pseudonymous operation ID to
deduplicate external exports, alert on delivery backlog/failures, and never treat an
`estimated` lease-recovery/backfill cost as complete accounting. Clock-skewed and over-30-day
samples are excluded and counted rather than reported as zero. Production API credentials have
INSERT-only access to this global outbox; workers alone claim, acknowledge and prune delivered rows
after `CRISISWEAVE_INGESTION_LIFECYCLE_RETENTION_DAYS` (default 14, allowed 7–365 days).

Run an independently controlled load harness that emits performance-v2 raw samples: `query` and
`ingestion` roots must be `end_to_end`, while child stages are `core_operation`. Generate p50/p95/p99
and per-query/document costs with `scripts/performance_report.py`, then bind the raw samples, report,
price sheet, hardware, model bundle and load profile in the signed release evidence. In-response cost
capture covers the core query/document operation and prevents duplicated child charges; the external
harness must account for the complete boundary. Synthetic tests validate only schema/calculation;
only a real staging run supplies operational numbers.

### Durable ingestion workers

Production API replicas set `CRISISWEAVE_RUNTIME_ROLE=api` and
`CRISISWEAVE_INGESTION_WORKER_ENABLED=false`; they accept uploads
only through `/v1/ingestion-jobs` and reject synchronous `/v1/documents` ingestion. Run one or more
dedicated services with `CRISISWEAVE_RUNTIME_ROLE=ingestion_worker`:

```bash
crisisweave ingestion-worker
```

Workers share PostgreSQL queue/metadata state and exact-version S3-compatible inputs. PostgreSQL
claims use `FOR UPDATE SKIP LOCKED`; progress heartbeats renew leases, expired leases resume, and
three unsuccessful attempts enter `dead_letter` for an explicit authenticated retry. A worker
handles one job at a time, performs ClamAV scanning, and streams hostile media to its authenticated
no-egress parser. Its slim composition does not initialize the LLM gateway/canary, reranker, web
client or query agent. Scale workers and parser capacity from measured queue/CPU behavior. API
processes may use multiple Uvicorn workers only with PostgreSQL; DuckDB remains fixed to one process.

Each production worker serves unauthenticated Prometheus metrics on its network-restricted port
9100 (loopback host ports 9101/9102 in Compose). It exports
`crisisweave_ingestion_jobs{status=...}`, `crisisweave_ingestion_queue_ready` and metric-refresh
failures without tenant/content labels. Lifecycle delivery adds
`crisisweave_ingestion_lifecycle_outbox_pending`,
`crisisweave_ingestion_lifecycle_outbox_oldest_pending_seconds`, and the bounded
`crisisweave_ingestion_lifecycle_delivery_failures_total{stage}` counter (`claim`, `emit`, `ack`,
or `prune`). The port health check proves that the worker and metrics listener started; it is not a
continuous parser, ClamAV, database or object-store readiness check. Alert on queue/dead-letter
growth, a lifecycle event pending over five minutes, and delivery failures; exercise dependency
failures in staging.

The production settings validator is role-aware and rejects cross-role secrets. Common blocks contain
only non-secret endpoints, model paths, limits and bucket/collection names. Each trust role then gets
its own credentials:

| API only | Ingestion worker only | Migration job only |
|---|---|---|
| API PostgreSQL DSN; API S3 identity; API Qdrant key; tenant/metrics keys; LLM/reranker and optional web credentials; public proxy/origin settings | Worker PostgreSQL DSN; worker S3 identity; worker Qdrant key; parser token/service URL and ClamAV settings; LLM/web disabled and provider canary off | Migration PostgreSQL DSN; API/worker database role names; Qdrant schema key; no S3, tenant, LLM, web, parser or scanner credential |

The worker role rejects tenant/metrics/LLM/web keys, a model reranker and trusted-proxy mode. The API
role rejects parser and malware-scanner credentials. This prevents a parser/worker compromise from
inheriting query-provider or tenant-auth secrets and prevents the public API from owning hostile-media
credentials or parser-local storage. Scope each database role, bucket-prefix policy and collection key to the
operations listed below; identity separation does not replace tenant predicates inside the service.

### PostgreSQL and object-storage contract

Create three PostgreSQL `NOINHERIT`, `NOCREATEDB`, `NOCREATEROLE` login roles: API, ingestion worker
and migrator. Revoke `CREATE` on the database and `public` schema from runtime roles. Only the
short-lived migrator may own/alter the `crisisweave` schema. `crisisweave migrate` takes an advisory
transaction lock, applies idempotent tables/indexes (including the document status/created recovery
index, cleanup and lifecycle outboxes, usage-quality provenance, identity audit and review
workflow), records schema version 5, revokes schema
creation, and grants only schema `USAGE` plus explicit per-table operations. RLS is enabled and
forced on every tenant table. Migration rejects API/worker roles that are `SUPERUSER`, have
`BYPASSRLS`, or own schema objects. API connections bind one tenant per transaction; application
predicates remain defense in depth. The worker policy is deliberately cross-tenant so a global queue
can be consumed; choose tenant-specific workers/roles or separate databases where worker-credential
compromise must not cross tenants. Both roles can only `SELECT` `schema_migrations`; API owns
document read/update/delete, evidence reads, query-audit, reviews/audit, tenant-scoped job and
orphan-cleanup operations, plus INSERT-only lifecycle-event creation. It cannot read, claim,
acknowledge, delete or prune the global lifecycle outbox. The worker owns evidence/document,
job/cleanup and lifecycle-outbox DML but no query/review access. No future-table default grant exists.
The migration fails if either runtime role owns a schema object, requiring an administrator to
transfer it to the migrator before rollout. Runtime stores execute only a schema-version `SELECT` at
startup and fail closed if migration is missing; they never run DDL.
All DSNs must use `sslmode=verify-full`. Back up with a database-native consistent snapshot and test
point-in-time restore. DuckDB is accepted only in local/test mode and must never be shared by workers.

Qdrant follows the same lifecycle: the migration identity alone creates the collection, payload
indexes and schema marker. API/worker startup validates those objects without creating or repairing
them. Grant the API key query/delete permissions needed for retrieval and authenticated reset; grant
the worker key point upsert/delete permissions; reserve collection/index administration for the
migration key.

The S3-compatible bucket must have versioning enabled before startup; readiness checks both access
and versioning. Block public access, deny plaintext transport, require the configured SSE policy,
restrict the workload identity to its bucket/prefix and exact-version operations, and log data-plane
access without object contents. The application records `s3://...?...versionId=...` references and
verifies SHA-256 metadata when reading. Test conditional `If-None-Match`, checksum, version-ID,
server-side-encryption and exact-version delete behavior against the chosen S3 implementation before
promotion; S3-compatible products differ. Configure noncurrent-version retention, orphan cleanup,
replication and legal-hold rules to match the deletion/RPO policy. Static AWS keys, if unavoidable,
must come from the deployment secret manager and rotate independently of application credentials.

Ingestion input deletion is an object-first, durable workflow. Terminal jobs retain the exact object
version while `input_cleanup_pending` is true; workers retry it after restart and remove a job row
only after exact-version deletion is acknowledged. Inputs created by rejected or deduplicated
enqueue attempts use the PostgreSQL orphan-cleanup outbox. Keep a delayed bucket lifecycle rule as a
last-resort backstop for the unavoidable crash window between an object-store PUT response and the
first database write; its delay must exceed the maximum job and reconciliation window.

If web search is enabled, set `CRISISWEAVE_WEB_SEARCH_PROVIDER=tavily` and provide a scoped Tavily
key. Pin `CRISISWEAVE_TAVILY_ENDPOINT` to the exact credential-free HTTPS provider URL, or to the
reviewed destination-enforcing egress-gateway path in a default-deny cluster. The API sends the key
as a Bearer header, follows neither redirects nor ambient proxies, limits response bytes, validates
the response schema, and accepts snippets only from the configured domain suffix allowlist; it
never fetches result URLs.

### Parser transport and topology constraints

The ingestion worker authenticates with a distinct parser token, supplies bounded integrity/lineage
metadata and streams one validated object body. The parser stores it only in a newly created
request-private directory under its bounded `/tmp`, rechecks hash/size/type, runs the secret-free
child and returns bounded JSON plus encoded derivative bytes. The worker independently validates
artifact names, sizes and lineage before publication. No worker/parser exchange volume exists.

Compose fixes each worker and parser to one active ingestion/extraction and gives each pair a
different internal network. The hop is plain HTTP plus the service token and therefore depends on
that Docker-network boundary and host destination policy. If the parser moves outside this boundary,
use authenticated TLS/mTLS. The Kubernetes reference already requires a separate parser Service,
strict Istio mTLS and an enforcing no-general-egress NetworkPolicy; those controls must be proved in
the live cluster rather than inferred from YAML.

The API, ingestion workers, migration job, gateway and ClamAV updater use separate egress networks
(`api-provider-egress`, `worker-storage-egress`, `migration-storage-egress`, `gateway-egress`, and
`clamav-egress`), and
worker-to-ClamAV traffic uses a dedicated internal malware network. Pair-specific parser networks
carry only the authenticated streaming exchange. The UI reaches the API only
through Caddy's unexposed port 8080
listener; separate `frontend` and `api-gateway` networks prevent a direct UI-to-API bypass. Both public
and internal API proxy paths actively poll `/health/ready` and stop selecting the API after two
failures. Docker networks prevent accidental service-level lateral paths; they do not implement
destination allowlists. Enforce approved Qdrant/model/search/ACME/ClamAV destinations with the host
firewall, an egress proxy or the deployment platform's network policy. Release evidence must show
destination-level rules: API to PostgreSQL/S3/Qdrant plus approved LLM/search endpoints; worker only
to PostgreSQL/S3/Qdrant (and internal parser/ClamAV); migration only to PostgreSQL/Qdrant; gateway to
approved ACME endpoints; updater to approved ClamAV mirrors. Deny and alert on every other destination.
`validate_production_config.py` requires the non-placeholder SHA-256 of that reviewed policy artifact;
promotion must additionally compare it with the live rendered policy and execute allow/deny probes.

### ClamAV database lifecycle

The updater is the only service with egress and the only writer of `clamav-db`; `clamd` mounts the
same database read-only on the internal malware network. The updater is healthy only while its
FreshClam process is present and a
`daily.cvd` or `daily.cld` was written within 72 hours, and `clamd` will not start until that condition
is met. Each ingestion worker checks the signature timestamp and runs the full-limit clean/EICAR
canaries before its metrics listener starts; the public API deliberately has no ClamAV credential and
does not report scanner health. The official image's `clamd` self-check notices files written by the
separate updater, so a short reload delay is expected.

ClamAV 1.5.2 defaults `StreamMaxLength` to 100 MiB, but the INSTREAM protocol rejects a stream that
exceeds the daemon setting. The `clamav-runtime` target therefore makes the limit an explicit 64 MiB
inside the signed image instead of depending on an implicit upstream default or a mutable host mount.
Production Compose fixes the API, worker, parser and UI object limit to 50 MiB (52,428,800 bytes). At
worker startup, a sparse clean object of exactly that size is sent through INSTREAM before the EICAR canary;
an INSTREAM limit/protocol error is not accepted as a malware detection. The daemon still runs as
`clamav`, its config is root-owned mode `0444`, and the root filesystem remains read-only. See the
[official protocol contract](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) and
[official container configuration guidance](https://docs.clamav.net/manual/Installing/Docker.html).

For the promoted digest, confirm `clamconf -n` reports `StreamMaxLength = "67108864"`, then exercise a
valid 50 MiB upload and a 50 MiB-plus-one-byte rejection in staging. If the application limit changes,
review and rebuild the ClamAV target, align the API/worker/parser/UI limits, resize the
daemon temporary filesystem with scan-expansion headroom, and rerun both boundary tests. A successful
image build and sparse startup canary do not replace malformed/archive-bomb tests for the exact
deployed image and resource policy.

Docker marks unhealthy containers but does not restart them solely because of health status. Route
Compose health events to monitoring and an authorized recovery action, alert before the 72-hour
threshold, and test updater death, CDN failure, stale databases and reload behavior for the exact
pinned ClamAV image. Keep `CLAMAV_MAX_SIGNATURE_AGE_MINUTES` and
`CRISISWEAVE_MAX_MALWARE_SIGNATURE_AGE_HOURS` aligned if policy changes.

## Kubernetes production reference

`deploy/kubernetes/base` provides restricted Pod Security, dedicated service accounts with disabled
token automount, External Secrets, an ephemeral one-shot migration, independent API/worker/parser
Deployments and HPAs, disruption budgets, topology spread, strict Istio mTLS, default-deny policies,
explicit egress-gateway hops, OpenTelemetry collection, ServiceMonitor and SLO alerts. Validate the source manifests
with `python scripts/validate_kubernetes_release.py deploy/kubernetes/base`, and validate the fully
rendered overlay again with `--rendered` before applying it.

The base intentionally contains `REPLACE_*` values and does not deploy PostgreSQL, object storage,
Qdrant, the organizational auth proxy/BFF, Istio, a NetworkPolicy-enforcing CNI, External Secrets,
Stakater Reloader (or equivalent rollout automation), Prometheus Operator/metrics services, or
destination-enforcing gateways. The checked-in Reloader annotations do nothing without that external
controller, and refreshed Secret data does not update environment variables until pods restart. Supply managed
multi-zone PostgreSQL, versioned replicated object storage and a Qdrant topology with an explicit
replication factor/load balancer plus per-node snapshot/restore. NetworkPolicy requires enforcement
by the selected CNI and is L3/L4 policy, not proof of DNS/FQDN destination control. See
[`deploy/kubernetes/README.md`](../deploy/kubernetes/README.md) and the artifact-bound gates in
[`12-performance-ha-and-release-evidence.md`](12-performance-ha-and-release-evidence.md).

## Mandatory pre-production work

1. **Lock artifacts:** resolve `pyproject.toml` for the deployment platform into a hash-checked lock,
   pin base/service images by digest, generate CycloneDX/SPDX SBOM, and sign/attest the image.
2. **Models:** pre-download an immutable revision, verify checksums/license, set offline cache, benchmark
   CPU/GPU/RAM, and disable remote code. Do not download weights during request handling.
3. **Qdrant:** private TLS, scoped read/write keys, strict mode/limits, replication if required, snapshots
   and tested restore. The Compose development key is not acceptable.
4. **Malware:** update ClamAV signatures in a writable controlled stage or use an external scanner;
   fail readiness/ingestion when definitions exceed the organization's freshness threshold.
5. **Object/metadata durability:** take consistent PostgreSQL/PITR backups and versioned-bucket
   backups/replication, exclude ephemeral worker/parser temporary directories, and complete a
   cross-store restore and orphan/deletion drill against the exact promoted topology.
6. **Egress/sandbox:** apply and test separate destination allowlists for API, worker, migration,
   gateway and ClamAV-updater networks; prove the worker cannot reach model/search endpoints or
   receive their credentials; verify the parser has no default route/general egress and apply/test
   seccomp/AppArmor/PID/resource policy. Docker bridge separation alone does not pass this gate.
7. **Gateway:** validate TLS/HSTS, body/time limits, access-log redaction and upstream timeouts.
8. **Tests:** execute the environment gates in `09-qa-vapt.md`, including authorized ZAP and load tests.
9. **Identity/tenancy:** integrate the organizational OIDC proxy/BFF, test claim mapping, MFA policy,
   signing-key and service-key rotation, every RBAC denial, forced RLS and audit export/retention.
10. **Evaluation/oversight:** complete blind domain annotation/adjudication, seal test labels, add
    private events, execute all six systems identically, publish per-event confidence intervals, and
    run a limited analyst pilot including consequential-query review quality.
11. **Release evidence:** attach fresh DAST, malformed-media, load/cost/latency, failover, replication,
    backup/restore and pilot artifacts to `scripts/validate_release_evidence.py`; schema-valid
    placeholders are not evidence that a drill occurred.

## Capacity and scaling

Development DuckDB permits exactly one API process. Production PostgreSQL permits multiple API
replicas; API replicas do not parse. Long videos run as durable asynchronous jobs. Autoscale workers
and the separate parser Deployment using measured queue depth, lease age and parser/CPU saturation,
not API CPU alone. The base HPAs are CPU-only; queue-driven scaling requires an external metrics
adapter and reviewed metric/query credentials. Maintain a GPU worker pool separately if using unified
vision-language embeddings.

## Rollback

Build once and promote the same signed image digest. Keep the previous prompt/model/index schema and
Qdrant alias. Database schema changes require backward-compatible expand/contract steps. Roll back
application, alias and prompt/model bundle together; never point an old binary at a silently changed
vector dimension.
