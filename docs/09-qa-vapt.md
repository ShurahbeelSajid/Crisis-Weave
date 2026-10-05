# QA, evaluation, and VAPT report

**Assessment date:** 2026-08-06  
**Scope:** repository source, configuration, local deterministic adapters, API contracts, benchmark
governance, Kubernetes/reference-topology policy and abuse cases  
**Out of scope on this host:** Docker/Compose runtime, FFmpeg/Tesseract executables, ClamAV definitions,
real PostgreSQL/S3/Qdrant/OIDC services, embedding/reranker/LLM weights, GPU, public deployment,
independent human annotation/private events and active DAST/load/failover/restore testing  
**Authorization:** active security tests must run only against an environment the operator owns or is
explicitly authorized to test.

**Current release decision:** **NO-GO for production promotion.** The current deterministic local
tree passes its repository gates, but exact production containers, real models, external services,
independent benchmark work, active DAST/load testing, malformed-media exercise, failover/restore and
an analyst pilot were not completed in the delivery workspace. Nothing below is a VAPT certificate.

## Test strategy

| Layer | Coverage |
|---|---|
| Unit | production/parser config invariants, filename/signature/pixel/prompt controls, tenant principal, router, reranker diversity, SQL allow/deny corpus, numeric/polarity citation policy |
| Integration | CSV normalization, parser-service auth/hash/stream/private-temp/artifact validation, Qdrant named-vector ingest/search, DuckDB analytics/provenance, graph routes, citations, dedupe/deletion, image visual evidence; live PostgreSQL/S3 remains a staging gate |
| API/E2E | health, auth/RBAC, streaming upload, async jobs, list/get/query/review/reset, security headers, strict request schema, request ID, tenant-negative access and isolated API/Streamlit startup |
| Security regression | direct injection has zero tools, polyglot/traversal upload reject, unsafe source URI reject, OIDC/JWKS boundary, service-key rotation/revocation, human-only maker-checker review, tenant-safe results and invalid IDs return bounded errors |
| Static/supply chain | `.github/workflows/ci.yml` defines Ruff, mypy, tests, runtime/UI/gateway/ClamAV builds, gateway and ClamAV stream-limit validation, production preflight/Compose rendering, image Trivy gates and a runtime SBOM artifact. `.github/workflows/security.yml` defines Bandit, pip-audit, Gitleaks and Trivy filesystem checks. `.github/workflows/promote.yml` defines an exact model-bundle build, offline boot verification, Trivy/SBOM, rendered-Kubernetes validation and keyless signing/attestation. These workflow definitions were source-reviewed; no run result from the exact release candidate is asserted here |
| Quality eval | deterministic API gate plus a composed 46-event global source registry, region/time scorer and publication gate for Recall@K, nDCG/MRR, routing, SQL, citations, visual groundedness, abstention, injection, cost/latency and five baselines; real labels/private events/six-system results remain unavailable |

## Repository verification results

The rows below are current-tree local evidence refreshed on 2026-08-06. They establish deterministic source
and contract behavior only; they do not replace the external staging gates in the next section.

| Check | Result | Evidence/qualification |
|---|---|---|
| Python syntax compilation | Passed | Python 3.13.14 completed `python -m compileall -q src apps scripts tests` |
| Unit/integration/security tests | Passed | 834/834 passed in 91.60 seconds across unit, integration, evaluation, performance and security suites on Python 3.13.14 |
| Test warnings | Passed with one non-failing warning | The Starlette TestClient/httpx deprecation remains a dependency-upgrade regression item |
| Coverage | Passed in the preceding source run | Branch-aware total was 83.00% against the configured 80% gate; documentation-only cleanup did not change measured Python source |
| Ruff format/lint | Passed | 96 application/test-scope files were already formatted; all lint checks passed with cache disabled |
| Mypy strict | Passed | No issues in 28 source files |
| Bandit SAST | Passed | Full `src`, `apps` and `scripts` scan completed with no findings; narrowly scoped reviewed suppressions remain visible in source |
| Documentation integrity | Passed | 20 Markdown files had no broken local links; 27 PowerShell examples parsed successfully; all 20 user-guide environment variables mapped to implemented settings or documented UI/launcher variables |
| pip-audit | Not executed locally | The advisory lookup would disclose installed package names/versions to a public service and explicit approval was not available. CI defines the gate; release still requires its result and a platform-resolved, hash-checked lock |
| Dependency installation | Passed for the installed environment; not release-locked | `pip check` reported no broken requirements. A platform-resolved hash lock and exact-image advisory/container result remain release gates |
| Dependency contracts | Passed locally | The full current-tree suite passed; live product-specific service and exact-image checks remain open |
| PostgreSQL/S3 adapter contracts | Unit contracts passed; live gate open | No live PostgreSQL or S3-compatible endpoint was available; unit contracts and source review cannot establish service behavior |
| Deterministic API/UI evaluation | Passed locally | Current API, ingestion, pipeline and isolated Streamlit integration tests passed; hash/lexical/disabled-LLM modes prove plumbing only, not real-model quality |
| Supplied scanned-report acceptance | Passed as a manual local acceptance run | The externally supplied 51-page report (not committed to the repository) ingested in 44.06 seconds as 103 OCR-backed chunks using the Windows en-US fallback. Live queries returned 94.13 million affected people (page 19), 64.8% direct-loss share (page 20), and USD 62.9 billion / 5.51 times direct losses (page 39); absent hospital-bed evidence abstained, the burn-scar pixel question abstained, and a direct override/fabrication prompt ran no tools. Reproduction requires the same source bytes and environment |
| Benchmark/governance contract | Validated; publication blocked | The 46-event/50-source registry and all 37 evaluation tests passed, and the leak scanner found no custodian-only material. No independently completed annotations, adjudication, developer-inaccessible private events or signed real-system result is available; the public plan also has only two sealed-test SQL cases and one injection case, below the enforced five-event minimum |
| Visual-region contract | Framework present; semantic labels open | Typed image/PDF boxes, chart elements and video intervals are implemented. Runtime parser locators remain provenance-only; independently adjudicated tight regions and visual entailment results are unavailable |
| Production/Kubernetes preflight | Static structure passed; live gate open | The production-reference validator passed and all 22 repository YAML files parsed. Compose rendering, rendered overlays, container startup and live Istio/CNI/External Secrets/Reloader behavior were not executed on this host |
| Docker build/Compose | Not executable on host | CI definitions build and scan runtime/UI/gateway/ClamAV targets and validate Caddy/ClamAV configuration; exact model-bundle and deployed-topology validation remain staging gates |
| Media/OCR runtime | Partially exercised | Windows Runtime OCR processed the supplied scanned PDF locally with bounded fixed-script invocation and path/output/time limits. FFmpeg, Tesseract, ClamAV, the production parser image and malformed-media behavior remain staging gates |
| Real-model quality | Not executed | Requires pinned weights/hardware; deterministic hash mode makes no quality claim |
| Active DAST/load test | Not executed | Requires authorized running staging endpoint |
| Backup/restore and deletion drill | Not executed | Required against the promoted storage topology before release |

## VAPT findings and disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| V-01 | High if ignored | Model-generated SQL can be executable code | Mitigated in source: AST allowlist, user placeholders rejected, bound server-injected tenant/ready predicates, forced limit, PostgreSQL statement/result budgets and restricted DuckDB local connection; live PostgreSQL abuse/timeout tests remain required |
| V-02 | High if exposed | Qdrant self-hosted defaults can be publicly unsecured | Production config requires authenticated HTTPS and publishes no local Qdrant port; strict mode, TLS policy, backup and restore were **not** verified here |
| V-03 | High | Indirect prompt injection could invoke tools in a conventional agent | Mitigated by design/source: router sees question only; evidence enters only a tool-less answer node; server authorizes typed calls; multimodal red-team gate remains unexecuted |
| V-04 | High | Parser exploit/DoS from hostile media | Mitigated in source/reference topology by API quarantine, worker-side AV, authenticated hash-bound streaming, parser-private temp, no-egress parser containers, secret-free child config/environment and resource/path/output bounds; custom OS sandbox policy and malformed-media runtime tests remain mandatory |
| V-05 | Medium | Multi-user identity, revocation and authorization can be confused with service authentication | Mitigated in source: asymmetric OIDC, explicit user/service claim, RBAC, rotatable/revocable role-bound service keys and tenant-safe resources. Organizational MFA/conditional access, real issuer integration and the browser auth proxy/BFF remain deployment gates |
| V-06 | Medium | DuckDB is a single-process writer | Production now fails closed unless PostgreSQL, versioned object storage and dedicated durable workers are configured; DuckDB remains local-only. Live failover/load validation is open |
| V-07 | Medium | An authenticated parser is still a privileged hostile-media boundary | Shared exchange storage was removed: each request uses parser-private temp and returns bounded artifact bytes. A compromised parser can still inspect the active request or craft output, so one-job capacity, independent worker validation, mTLS/network enforcement and sandbox testing remain required |
| V-08 | Medium | Model/source updates can change quality or licensing | Model/dataset manifest, checksum/license review, frozen eval and collection-version migration are release gates |
| V-09 | Low | Development API docs need relaxed browser CSP | Restrict docs to development; production startup forces docs off |
| V-10 | Medium | A page/frame locator can be mistaken for proof that a specific region entails a claim | Typed boxes/chart elements/video intervals and one-to-one annotated-region scoring are implemented, but runtime parser regions are provenance-only. Tight human regions, real visual entailment evaluation and high-impact review remain release gates |
| V-11 | Medium | Demo dataset's first provenance lock is trust-on-first-use | Review the initial download out of band and preserve its hash lock as a controlled release artifact; `--refresh-lock` requires explicit review |
| V-12 | Medium | A matching number could previously launder an invented unit/currency | Fixed: claimed percent, currency and adjacent unit must match each cited source independently; regression cases cover people/units/currencies and equivalent numeric formats |
| V-13 | High if ignored | A ClamAV protocol/stream error could be mistaken for successful EICAR detection | Fixed in source: only an explicit `FOUND` verdict/exit 1 is malware; startup streams the full application limit before EICAR. Exact-image runtime boundary tests remain mandatory |
| V-14 | Medium | Transitive dependencies are not release-locked and the local advisory lookup was not authorized | Block promotion until a platform-resolved hash lock and successful advisory/container scans are attached to the exact promoted artifacts |
| V-15 | Medium | CI's illustrative builds are not release evidence | A separate promotion workflow now defines digest-pinned model-bundle input, exact output scan/SBOM, rendered-manifest binding and keyless signature/attestation. It still must be executed under protected release controls, and every promoted companion image needs equivalent signed evidence |
| V-16 | Medium | Qdrant, PostgreSQL and object storage cannot share one transaction | Mitigated with non-`ready` visibility, exact references, idempotent cleanup and startup reconciliation. Tenant-scoped original keys plus database tenant locks close the cross-tenant publish/delete race. Configure/test delayed orphan-version lifecycle cleanup and cross-store restore before promotion |
| V-17 | High until tested | S3-compatible products vary in conditional writes, checksums, version IDs, encryption and exact-version deletion | Application fails when an immutable version ID is absent and verifies digest metadata; execute the complete adapter contract against the selected product and bucket policy before promotion |
| V-18 | Medium | Shared database/runtime identities can weaken tenant isolation | Production now requires forced PostgreSQL RLS, rejects runtime owners/SUPERUSER/BYPASSRLS, binds the API tenant per transaction and keeps application/Qdrant predicates. The global worker intentionally has cross-tenant queue/data policy; use tenant-specific workers/roles or separate databases for a stronger compromise boundary and prove it live |
| V-19 | High if roles share secrets | A compromised ingestion worker/parser could expose tenant-auth or query-provider credentials | Mitigated in configuration/composition: role-aware production validation rejects cross-role secrets, and the slim worker omits LLM/canary/reranker/web/agent components. Verify the deployed container environments and workload identities independently |
| V-20 | Medium | A crash around object upload, enqueue rejection, cancellation or terminal cleanup could leave an immutable input version orphaned | Fixed for durable states: cleanup intent and an orphan-cleanup outbox survive restarts, deletion is exact-version and object-first, and bounded periodic worker reconciliation retries failures. A process death between the initial object PUT and first durable database write remains an unavoidable gap; configure and test a delayed noncurrent/orphan bucket lifecycle before promotion |
| V-21 | High if misconfigured | Runtime schema creation or shared database credentials would turn an API/worker compromise into DDL authority | Fixed in configuration/source: an explicit advisory-locked migration command owns DDL, runtime startup validates schema without creating it, granular grants are role-specific, and preflight rejects shared identities or runtime ownership. Live privilege-negative tests against the selected PostgreSQL service remain required |
| V-22 | Medium | Benchmark contamination, pretraining knowledge or evaluator-controlled telemetry could overstate quality and safety | Contract now separates closed-book/retrieved and historical/recent/private strata, seals test labels, requires private events, identical six-system runs, per-event intervals, complete price-bound cost/trace artifacts and an external Ed25519 signature. Humans/private data/custodian keys and real runs are absent, so publication remains blocked |
| V-23 | Medium | Separate Compose networks and Kubernetes YAML do not prove destination-level egress policy | The reference topology separates API, worker and parser trust zones and gates a reviewed policy digest, but staging must prove actual firewall/proxy/CNI destination rules, denied worker model/search access, parser no-general-egress behavior and strict mesh mTLS |
| V-24 | High if ingress is bypassed | Streamlit forwarded-bearer mode trusts an upstream identity boundary | Kubernetes keeps Streamlit private and requires an organizational auth proxy/BFF that replaces the header; the standalone Compose UI stays service-key-only. Prove no direct UI route and test header spoofing in staging |
| V-25 | Medium | JWKS pre-resolution cannot alone eliminate DNS rebinding/egress abuse | Client enforces HTTPS, fixed URL, no redirects/proxies, bounded body/time/cache and public-address resolution by default. Destination-enforcing network egress and a pinned organizational gateway remain mandatory |
| V-26 | Medium | Local hash-chained audit is tamper-evident, not tamper-proof | Mutating rows is blocked and retention is bounded, but the database owner/maintenance path remains trusted and pruning removes old chain material. Export and externally anchor events in independently administered immutable storage |
| V-27 | High until exercised | Kubernetes/HA manifests can be mistaken for a working multi-zone platform | Structural validation covers HPA/PDB/topology/secrets/network policy/telemetry, but Istio injection/mTLS, CNI enforcement, External Secrets/Reloader rotation, metrics adapters, managed-store replication, Qdrant snapshots, failover/RPO/RTO and egress enforcement require fresh environment evidence |
| V-28 | Medium | At-least-once lifecycle telemetry can duplicate after emit-before-ack or overstate recovered historical usage | Stable pseudonymous operation IDs support collector deduplication; recovery/backfill records are marked estimated; invalid clock samples are excluded; API roles are insert-only; worker retention, backlog age and bounded failure metrics are monitored. Prove deduplication and independent raw-sample collection under crash/recovery tests before using the series for release cost claims |

## Automated abuse cases present in the test suite

The current supported-Python suite executes the cases below successfully. The staging corpus still
needs the external service, malformed-media and real-model expansion described later.

- Wrong/missing key; cross-tenant document ID; client-supplied tenant field.
- Path traversal filename, signature/extension mismatch, active-PDF markers, unsafe source URI.
- Stacked/DDL SQL, comments, joins, CTEs, subqueries, file reader, forbidden table/column/function.
- Direct prompt override/fabrication requests; indirect evidence injection exclusion; unknown
  citation label removal; irrelevant-evidence and pixel-without-vision abstention.
- Oversized/empty upload, pixel bound and malformed IDs (expand corpus in staging).

## Staging VAPT plan

1. Build the exact production image; scan OS/Python/IaC with Trivy, Grype/OSV or organizational
   equivalent; create/sign SBOM and provenance attestation.
2. Run ZAP API/baseline and Schemathesis OpenAPI fuzzing against an authorized staging hostname.
3. Run malformed PDF/image/video corpus under cgroup/seccomp limits: polyglots, truncated streams,
   huge dimensions/page trees/durations, metadata/QR/hidden-layer instructions and frame/audio
   attacks. Confirm the parser has no general egress or `/data` mount, receives no API/provider
   secrets, deletes request-private temp, rejects cross-job/path/lineage attempts, and never receives
   a shared exchange volume.
4. Run promptfoo/PyRIT cases for direct/indirect injection, tool forgery, SQL exfiltration, RAG
   poisoning, canary leakage, fabricated citations and unanswerable questions.
5. Run k6 at 2x expected peak plus slow uploads/provider faults; have an independent harness emit
   performance-v2 raw samples with end-to-end query/ingestion roots and core-operation child stages.
   Record p50/p95/p99, error/RAM and price-sheet-bound per-query/per-document cost; verify
   backpressure/rate limits. Prometheus histogram buckets alone are not publishable raw evidence.
6. Test Qdrant auth/TLS/private binding/strict mode and prove only the migration key can alter schema;
   prove API/worker PostgreSQL roles have DML but cannot execute `CREATE/ALTER/DROP`, while the
   migration role is absent from runtime; test PostgreSQL TLS/pool/timeout/tenant-negative
   behavior; and S3 versioning, conditional writes, checksum, SSE/KMS, exact-version read/delete,
   bucket policy, distinct API/worker identities and orphan lifecycle. Also test gateway bounds,
   destination allowlists for each separate egress network, denied worker model/search access, and
   log redaction. Compose network names without firewall/proxy policy are insufficient evidence.
7. Perform coordinated PostgreSQL/S3/Qdrant backup/restore, derived-data and noncurrent-version
   deletion, key rotation, provider/tool kill switch and rollback.
8. Integrate the real OIDC issuer/proxy, test MFA/claim/key rotation, every RBAC denial, service-key
   overlap/revocation, RLS tenant negatives, reviewer maker-checker behavior and immutable audit export.
9. Obtain two qualified blind domain annotations, third-person adjudication and pre-adjudication IAA;
   add at least three lawful private events, keep test plaintext/keys from developers, execute all six
   variants identically and publish per-event results plus event-bootstrap confidence intervals.
10. Run a limited analyst pilot with routine and consequential questions; measure evidence-discovery
    time, unsupported-claim rate, review/escalation workload and source-freshness usefulness. Obtain
    an independent security review mapped to OWASP ASVS Level 2 and LLMSVS before high-impact use.

Bind every staging result to image/model/config/dataset digests and aware timestamps, then run
`scripts/validate_release_evidence.py`. The validator proves schema, freshness, thresholds and
artifact binding; it cannot prove that an assessor, drill or pilot actually occurred.

Every item above is currently unexecuted in this workspace. A future operator must attach dated
reports for the exact image digests, configuration, model bundle and environment; a passing CI run on
a different artifact is insufficient.

The automatic CI evaluator deliberately uses hash embeddings, lexical reranking, embedded Qdrant and
a disabled LLM over synthetic text/CSV fixtures. It is a deterministic plumbing/grounding regression
gate, not evidence of real-model quality. A promotion workflow defines model-bundle construction and
attestation, but an executed protected run is not present here. ClamAV freshness/canaries, external
PostgreSQL/S3/Qdrant policy, parser sandbox/malformed-media tests, DAST, load and restore remain
authorized staging gates.

## Release decision rule

Do not promote with any exploitable unresolved Critical/High finding, cross-tenant access, forbidden
tool/SQL execution, canary leakage, invalid citation, stale/missing malware controls, untested restore,
or failure of agreed performance/quality thresholds. VAPT reduces risk; it does not prove the system
is vulnerability-free.

Under this rule, the current snapshot is **not approved for production** because the exact
production images/external services/models/identity provider, independent benchmark/private-event
work, malformed-media corpus, DAST/load/cost, failover/restore, advisory/lock, egress and
analyst-pilot gates listed above have not been executed.
