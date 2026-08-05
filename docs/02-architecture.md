# Architecture and trust boundaries

## Design principles

1. The model proposes; application code authorizes.
2. Every tool is read-only and bounded.
3. The router sees only the authenticated user's question—not retrieved content.
4. The answer model sees untrusted evidence but has no tools.
5. Tenant scope comes from the validated OIDC/service principal, never request/model fields.
6. Every returned citation must belong to the evidence set from that request.

## Runtime components

| Component | Owns | Must not own |
|---|---|---|
| Streamlit | Presentation and API calls; local scoped-key mode or a trusted ingress-forwarded bearer | DB/model/search credentials, token validation or authorization decisions |
| FastAPI | OIDC/service authentication, RBAC, tenant principal, validation, quotas, oversight and orchestration | Public raw object serving or human-review decisions |
| Parser service | One authenticated streamed job at a time, request-private temporary extraction, OCR/frame/transcript artifacts | API/Qdrant/LLM keys, application data volumes, shared exchange storage, or general egress |
| LangGraph | Typed bounded state transitions | Open-ended ReAct loops or executable model output |
| Parser subprocess | Secret-free extraction settings, scrubbed environment, resource-bounded native parsers | Service credentials, arbitrary paths, network tools, or shell expansion |
| Qdrant | Named-vector evidence and payload metadata | Authentication/jobs/original binaries |
| PostgreSQL (production) | RLS-protected metadata, durable jobs, reviews/audit events, tenant advisory locks and constrained event analytics | Original/derived binaries or model-controlled SQL |
| DuckDB (local) | Single-process metadata and constrained event analytics | Multiple API workers, distributed locks or arbitrary SQL/files |
| Versioned S3-compatible store | Exact-version originals, derivatives and durable job inputs | Authorization decisions or public object URLs |
| Ingestion worker | Leased job execution, ClamAV scanning and one bounded parser exchange at a time | API request serving, LLM/web credentials or access to parser-private temporary storage |
| Migration job | PostgreSQL schema/index ownership and Qdrant collection/index provisioning | Tenant/API, LLM/web, parser/AV or S3 data-plane credentials |
| Model gateway | Tool proposal and tool-less synthesis | Direct DB, filesystem or network tools |
| Search provider | Official-domain result snippets | Arbitrary page fetching by the agent |
| OpenTelemetry collector | Bounded operational traces/metrics and SLO inputs | Prompts, evidence contents, credentials or tenant labels |
| Evaluation custodian | Blind labels, private events, escrow/signing keys and independently executed release harness | Serving credentials or developer-accessible test plaintext |

## Query sequence

```mermaid
sequenceDiagram
    participant U as Authenticated client
    participant A as FastAPI
    participant G as LangGraph
    participant R as Router model/heuristic
    participant T as Read-only tools
    participant M as Answer model
    U->>A: Query + allow_web + top_k
    A->>A: verify principal/RBAC, derive tenant, rate/concurrency limits
    A->>G: strict QueryRequest
    G->>G: direct-injection guard
    G->>R: question only
    R-->>G: typed tool proposals
    G->>G: schema + authorization policy
    G->>T: tenant-injected vector/SQL/search calls
    T-->>G: bounded untrusted evidence
    G->>G: rerank + diversify
    G->>M: question + tagged evidence, no tools
    M-->>G: cited draft
    G->>G: remove unknown citations, calculate concordance
    G-->>A: candidate response + audit metadata
    A->>A: assess confidence, conflicts, risk and source freshness
    alt review required
        A-->>U: 202 review ID; answer withheld
    else routine research
        A-->>U: cited answer
    end
```

## Identity, tenant isolation and human oversight

Production validates asymmetric OIDC JWTs against an explicitly configured, bounded JWKS endpoint.
Issuer, audience, algorithm, expiry, subject, tenant, roles and an explicit `user`/`service` claim are
required. Hybrid mode adds rotatable `tenant@key_id` service credentials with explicit role bindings
and revocation. Supplying two authentication methods is rejected. The browser SSO flow is completed
by an organizational auth proxy/BFF; Streamlit only forwards that trusted bearer and never validates
or stores an identity-provider secret.

RBAC permissions cover query, evidence read/write/delete, job control, review read/decision and audit
read. PostgreSQL production startup requires RLS; migrations enable and force policies, and reject
runtime roles that own schema objects or have `SUPERUSER`/`BYPASSRLS`. Application tenant predicates
remain defense in depth. The global ingestion worker needs cross-tenant queue access, so deployments
requiring compromise-resistant isolation should use tenant-specific workers/roles or separate tenant
databases.

The agent exposes claim/evidence conflict, conservative cross-source conflict and source freshness
separately from concordance. High-risk subjects, low confidence, detected conflicts, stale sources,
or policy-selected unknown freshness create a pending review and withhold the candidate answer.
Only a distinct OIDC user with review permission may decide it; service identities and self-approval
are rejected. These deterministic signals triage work but do not replace a domain expert.

## Ingestion sequence

1. FastAPI authenticates before multipart parsing, reserves ingestion/disk capacity, streams the
   upload to a generated quarantine name, and independently counts body and file bytes.
2. Content signature must match an allowlisted extension; archives/SVG/office formats are excluded.
   The API/job service hashes the accepted bytes, publishes an immutable exact-version quarantine
   object and commits the tenant-scoped queue record before returning `202`.
3. A leased ingestion worker reads that exact version, verifies its size/hash/type and performs the
   mandatory production ClamAV scan. The public API has no parser or scanner credential.
4. The worker sends bounded lineage/hash/size metadata in an authenticated header and streams the
   input body to the parser. There is no worker/parser filesystem exchange or shared volume.
5. The no-egress parser writes the stream into a request-private temporary directory, rechecks the
   byte count, hash, signature and media type, then spawns a secret-free child with scrubbed
   environment and memory/CPU/time/IPC limits. Fixed subprocess argument arrays are used; no shell is
   invoked.
6. The parser returns bounded JSON containing lineage plus encoded derivative bytes, then its
   request-private directory is deleted. The worker bounds and validates the response, artifact
   names/bytes and lineage before writing worker-local staging and publishing exact object versions.
7. Qdrant/PostgreSQL visibility changes only after validation; failures are cleaned or remain
   retryable with bounded error codes.

### Parser trust-zone boundary

The production parser container has a read-only root, dropped capabilities, no application data
volume, and only the distinct parser-service token as a service credential. The native parser child
receives `ExtractionConfig`, not the API `Settings` object, and its environment is reduced to a small
runtime allowlist. Each request gets a newly created private directory under the parser's bounded
`/tmp`; input and derivatives are deleted when the request exits.

The transport is still a privileged trust boundary: a compromised parser can inspect the current
request and return hostile output. Both sides enforce independent byte/time/schema/hash/lineage
limits, the parser permits one extraction per replica, and the worker never trusts returned paths.
Compose isolates each worker/parser pair on its own internal network and uses the service token over
plain HTTP inside that network. The Kubernetes reference runs parsers as a separate Deployment and
requires an injected service mesh with namespace-wide strict mTLS. The checked-in mesh and network
policy objects are configuration contracts, not proof that a live CNI/mesh enforces them.

## Persistence and scaling

Local development uses embedded DuckDB and content-addressed files and therefore permits one API
process. Production fails configuration validation unless PostgreSQL and versioning-enabled
S3-compatible storage are selected. PostgreSQL is the shared system of record for documents,
analytics, jobs, leases, reviews and audit records; forced RLS and per-tenant advisory locks protect
and serialize ingest/reset/delete across processes. Every query remains parameterized, and
model-proposed analytics receives
server-injected tenant and `ready` predicates plus statement/result budgets.

Object metadata records exact `versionId` references. Reads request that exact version and verify the
stored SHA-256 metadata; production readiness fails when bucket versioning is not enabled. Originals
are content-addressed within each tenant, derivatives are tenant/document namespaced, and intentional
deletion targets an exact version. Bucket IAM, encryption, lifecycle, replication and backup policy
remain deployment controls rather than application authorization.

For ingestion, API replicas only authenticate, validate, quarantine and enqueue. Dedicated workers
lease idempotent jobs; their external egress is limited to storage gateways, with separate internal
parser/ClamAV/telemetry paths. The migration job alone changes PostgreSQL/Qdrant schema.
Runtime startup performs schema reads, never DDL. API, worker and migration use distinct PostgreSQL
and Qdrant identities, while API and worker also use distinct S3 identities. Dedicated workers run
bounded nonblocking recovery periodically; API replicas never scan global recovery state. Qdrant
remains the vector store. DuckDB/local files remain a smooth local adapter, not a production fallback.

The Kubernetes reference adds independent service accounts, External Secrets, separate worker and
parser Deployments/autoscaling, topology spread, disruption budgets, default-deny network policies,
strict mesh mTLS, a collector, ServiceMonitor and SLO alerts. It intentionally references externally
managed multi-zone PostgreSQL, replicated/versioned object storage, Qdrant replication/snapshots, an
OIDC proxy/BFF and destination-enforcing egress gateways. A compatible Istio control plane/sidecar
injector, enforcing CNI, External Secrets controller/store, secret-triggered rollout controller,
Prometheus Operator and metrics services are external prerequisites. Manifests prove the contract
shape, not that those services or recovery objectives work; fresh staging evidence is required for
promotion.

## Failure behavior

- Planner/provider failure: deterministic router records a warning.
- Synthesis failure: an extractive, cited answer records a warning.
- Unsafe SQL: rejected, traced, and omitted; never repaired through repeated autonomous attempts.
- Search unavailable: local tools continue, with a warning.
- Parser unavailable: the public API can remain ready because it does not own parser/scanner checks;
  affected jobs fail safely and follow the bounded retry/dead-letter path. Parser/worker health and
  queue growth require separate monitoring.
- No evidence: explicit abstention and concordance 0.
- Partial ingestion: staged rows/vectors/artifacts are removed and error text is reduced to a bounded
  code. If vector deletion cannot be confirmed, status remains `cleanup_pending`; startup retries
  cleanup and retrieval excludes all non-`ready` document IDs.

## Technology rationale

Qdrant provides named vectors and a simple local-to-service path; its self-hosted instance must be
secured explicitly per [Qdrant security guidance](https://qdrant.tech/documentation/security/).
DuckDB remains useful for local analytical reads but documents its single-process write model and
SQL security controls in its [concurrency](https://duckdb.org/docs/stable/connect/concurrency) and
[security](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview) guidance.
LangGraph's explicit graph/state API keeps agent steps inspectable; see the official
[Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api).
