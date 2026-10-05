# Security threat model

## Scope and assets

Protected assets include tenant originals, derivatives, OCR/transcripts, embeddings, queries,
answers, source metadata, API/model/search/vector credentials, audit logs, model weights, prompts,
and service availability/cost. Trust boundaries exist at the client/API, API/durable queue,
worker/parser, API/providers, API/Qdrant, model/tool proposal, and answer/evidence interfaces.

The assessment is informed by the [OWASP GenAI risks](https://genai.owasp.org/llm-top-10/),
[AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html),
[REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html),
and [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).

This is a design/source review, not evidence that the deployed topology passed VAPT. The supported
local test/static-analysis environment was exercised, but production containers, real models, the
malformed-media corpus, DAST, load and restore drills were not executed in the delivery workspace;
[the QA/VAPT report](09-qa-vapt.md) records the exact evidence and release blockers.

## Non-negotiable invariants

1. Models never directly execute SQL, network, shell, Python or filesystem operations.
2. Tools are read-only, typed, allowlisted and budgeted.
3. The router never sees retrieved content; the answer model has no tools.
4. Tenant identity is server-derived from the authenticated credential.
5. Every database/vector access injects tenant scope; every retrieved payload is rechecked.
6. No arbitrary URL fetch exists in the agent.
7. Every file, entity count, model context, tool count, request, command and concurrency path is bounded.
8. Raw sensitive content is excluded from default logs/audit.
9. Unsupported citations are removed and missing evidence results in abstention.

## Threat/control matrix

| Threat | Impact | Implemented controls | Residual/production control |
|---|---|---|---|
| BOLA/cross-tenant access | Confidentiality breach | OIDC/service principal derives tenant and permissions; application predicates, Qdrant filters, forced PostgreSQL RLS and tenant-safe 404s | Live RLS/role-negative tests; tenant-specific roles/databases when a shared worker or shared app credential is outside risk tolerance |
| Malicious upload/parser exploit | RCE/DoS/data access | API-side signature/quarantine/queue bounds; worker-side ClamAV; authenticated hash-bound streaming to a separate no-egress parser without `/data`; request-private parser temp; secret-free child config/environment; format/resource/time/IPC/artifact limits | Validate custom seccomp/AppArmor/PID policy, current AV, transport policy and parser isolation in staging; run the malformed-media corpus against the exact image |
| Direct prompt injection | Policy/tool abuse | Early guard plus typed/bounded tool authorization | Continuously red-team variants; never make regex the authority boundary |
| Indirect multimodal injection | Tool abuse/data disclosure | Router isolation; answer has no tools; untrusted tags; flags/downranking | Multimodal adversarial eval including hidden layers, frames, QR/audio and metadata |
| NL-to-SQL injection | File/secret read or mutation | One parsed SELECT; view/column/function allowlists; no join/subquery/CTE/comment; forced limit; external access/extensions disabled | Execute in killable read-only process over immutable Parquet with OS limits |
| SSRF | Cloud metadata/internal access | Search provider query API only; result HTTPS/domain validation; no result fetch | Egress proxy/domain policy, DNS monitoring, provider contract review |
| Vector poisoning | Manipulated answers | Tenant ownership, hashes, dedupe, per-document diversity, provenance, indirect-injection flags | Ingestion quotas, signed source manifests, source reputation and anomaly monitoring |
| Citation hallucination | Misinformation | Allowed-label verifier, number/overlap/polarity checks, typed visual/time locators, structured citations and abstention | Parser regions prove lineage, not semantic entailment; independently adjudicated region-level evaluation and human review remain required |
| XSS/Markdown exfiltration | Session/key leakage | Streamlit `unsafe_allow_html=False`; URLs opened only when HTTPS; security headers | Markdown sanitizer/CSP at gateway; adversarial UI test suite |
| Denial of service/cost | Outage/wallet drain | Size/entity/context/tool/time/rate/concurrency limits; no agent loop | Distributed rate limiter, queues/backpressure, provider budgets/circuit breakers, load test |
| Credential leakage | Provider/data compromise | Settings secrets, no key output, log redactor, `.env` ignored, rotatable/revocable role-bound service keys; parser gets only a distinct token and its native child gets no service settings | External Secrets/workload identity, short-lived provider keys, rehearsed rotation, Gitleaks and canary scans |
| Supply-chain/model compromise | RCE/backdoor | `trust_remote_code=False`, dependency ranges/scanners, containers non-root | Exact lock/hashes, signed images/SBOM, immutable model revision/checksum, legal/license review |
| Qdrant default exposure | Vector theft/mutation | No published Qdrant port; API key in Compose; production HTTPS/external required | Private network, TLS, read/write key split, strict mode, backup/audit per [Qdrant guidance](https://qdrant.tech/documentation/security/) |
| Sensitive provider retention | Privacy/legal exposure | Bounded context; raw prompts not logged locally by default | Approved enterprise provider terms, region/retention/no-training policy, PII redaction/DLP |
| OIDC/JWKS abuse | Auth bypass or SSRF | Asymmetric algorithm allowlist; issuer/audience/time/subject/tenant/role/identity-type validation; HTTPS bounded JWKS, no redirects or ambient proxies, public-address check by default | Pin the organizational issuer/gateway and enforce destination egress; DNS rebinding cannot be disproved by an application pre-resolution check alone |
| Review bypass | Consequential unsupported action | High-risk/conflict/confidence/freshness policy with withheld candidate, maker-checker subject check, human OIDC identity requirement, terminal decisions and tenant-safe result access | Validate risk taxonomy/thresholds with domain owners; deterministic lexical signals are triage, not a safety proof |
| Audit deletion/tampering | Lost accountability | Retention/row caps, append-only triggers, per-scope hash chain and separate audit permission | Export/anchor to independently administered immutable storage; a database owner or compromised privileged maintenance path remains trusted |
| Telemetry leakage or double billing | Privacy/cost error | No prompt/evidence metric labels, bounded core-stage spans, operation-scoped cost capture, low-cardinality end-to-end histograms and measured/estimated lifecycle provenance | Bind the price sheet in independently collected performance-v2 evidence; reconcile billing against selected providers/hardware and deduplicate at-least-once lifecycle events by stable operation ID because histograms cannot reconstruct per-operation public evidence |

## Authentication model

Local configuration accepts one development key and maps it to `default`. Production requires OIDC
or hybrid authentication. OIDC validates an asymmetric signature, explicit algorithm, issuer,
audience, expiry/issued-at, subject, tenant, roles and an explicit `user`/`service` claim. The JWKS
client uses a configured HTTPS endpoint, bounded response/cache/time, no redirects or ambient proxy,
and rejects non-public resolution unless an operator explicitly selects a controlled internal
gateway. An organizational SSO deployment must also enforce its own MFA/conditional-access policy.

Hybrid service credentials use `tenant@key_id=secret`, at least 24 characters, explicit role
bindings and revocation. Overlapping old/new IDs support rotation; comparisons are constant-time.
Tenant storage IDs are one-way hashes of the configured label. The standalone Compose UI accepts a
scoped service key; the Kubernetes browser flow instead requires a trusted OIDC proxy/BFF and
`forwarded_bearer` mode. Never expose that Streamlit mode directly, because the ingress is the
authority that must authenticate and replace the header.

## Parser trust zone

The parser has no application data mount or general egress; its distinct token is the only service
credential injected. A worker sends integrity/lineage metadata plus a bounded byte stream. The
parser writes it into a newly created request-private temporary directory, verifies size/hash/type,
and invokes a child that receives only a secret-free `ExtractionConfig` and environment allowlist.
It returns bounded encoded artifact bytes, not filesystem paths. The worker independently validates
response schema, artifact names/bytes, vector shape and exact chunk lineage before publication.

These controls reduce blast radius but do not make parser output trusted. A compromised parser can
read the active request, consume its resource budget or craft a response, so one extraction is
allowed per parser replica and worker-side validation remains mandatory. Compose uses a service
token over a pair-specific internal HTTP network. Kubernetes uses a separate parser Deployment/
Service and declares namespace-wide strict Istio mTLS; promotion must prove sidecar injection,
certificate rotation, strict peer policy and CNI enforcement in the live cluster. Rotate the parser
token and rebuild affected workloads after compromise; use workload identity and a sandboxed runtime
where the threat model requires stronger containment.

## Security headers and transport

FastAPI emits `nosniff`, clickjacking denial, no-referrer, restrictive permissions/CSP and no-store.
Production rejects HTTP model/Qdrant endpoints. Caddy terminates TLS and adds HSTS. Exact trusted
hosts and CORS origins are mandatory; wildcard production settings fail startup. The standalone
Compose parser hop is authenticated but plain HTTP on an isolated internal network; the Kubernetes
contract requires mesh mTLS. Qdrant and DuckDB must not be directly exposed.

## Data privacy and retention

Classify all derivatives like originals. Do not put secrets in system prompts. Default audit data is
a query SHA-256, routes, count, latency and policy flags; raw query logging is disabled. A pending
human review necessarily stores the query and candidate response/evidence under restricted review
permissions, so configure and enforce its separate retention period as sensitive tenant data.
Identity events are bounded and hash-chained, but the chain is tamper-evident rather than an external
immutable anchor. Define a tenant deletion SLA covering live stores, caches, snapshots, backups,
review records and external providers. Rotate credentials and invalidate provider caches during an
incident.

## Release security gates

The following are promotion criteria, not completed results for this repository snapshot:

- No exploitable unresolved Critical/High dependency, SAST, container or DAST finding.
- Cross-tenant negative tests pass for list/get/delete/query/citations/vectors/analytics.
- OIDC signature/claim, RBAC, service-key rotation/revocation, human-only review and forced-RLS role
  tests pass against the selected identity provider and PostgreSQL service.
- Unsafe SQL and upload corpus rejection is 100%; no forbidden tool call executes.
- Canary secrets never appear in response, log, trace or another tenant.
- Model/prompt/index/dataset versions and SBOM are recorded.
- Backup/restore, deletion, key rotation, provider/tool kill switches and load budgets are rehearsed,
  with fresh artifact-bound evidence accepted by the release validator.

No VAPT can certify “vulnerability-free.” Re-run risk, abuse, model and parser tests after every
dependency, model, prompt, tool, ingestion format or provider change.
