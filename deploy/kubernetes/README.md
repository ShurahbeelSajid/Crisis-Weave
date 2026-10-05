# Kubernetes production reference

This directory is a hardened deployment contract, not a one-command claim of production
readiness. The base deploys stateless CrisisWeave workloads across failure zones and assumes
PostgreSQL, versioned object storage and Qdrant are managed, replicated services. Their actual
replication and restore evidence is checked separately by `scripts/validate_release_evidence.py`.

Do not apply `base` directly. It deliberately contains image and proxy-CIDR placeholders which the
release validator rejects in rendered mode.

## Required cluster capabilities

- Kubernetes Pod Security Admission in `restricted` mode and a NetworkPolicy-enforcing CNI.
- A compatible Istio control plane and automatic sidecar injection for the `crisisweave` namespace.
  `mesh-security.yaml` declares namespace-wide `STRICT` peer authentication; prove injection,
  certificate rotation and plaintext rejection in the live cluster.
- Metrics Server for the checked-in CPU HPAs, Prometheus Operator for `ServiceMonitor`/
  `PrometheusRule` and an ingress controller in a namespace labeled
  `crisisweave.io/network-role=ingress`. Queue-driven autoscaling is not included; it additionally
  requires a reviewed external/custom metrics adapter and narrowly scoped metric access.
- External Secrets Operator and a reviewed `ClusterSecretStore` named
  `crisisweave-secret-store`; no credential value belongs in this repository.
- A pinned Stakater Reloader controller or equivalent GitOps rollout automation. The checked-in
  annotations do not restart pods by themselves, and Secret updates do not refresh environment
  variables in a running process.
- cert-manager plus an internal `ClusterIssuer` named `crisisweave-internal-ca`. Publish only its
  CA certificate as the `crisisweave-internal-ca` ConfigMap; never mount the issuer private key into
  an application pod.
- A trusted organizational OIDC authentication proxy or backend-for-frontend in the ingress path.
  It must complete login, reject unauthenticated requests, strip any client-supplied
  `Authorization` header, and inject the validated user access token when proxying to Streamlit.
  The repository does not supply or configure that identity component.
- API, storage/migration and observability egress gateways in separately administered namespaces
  carrying the labels required by `network-policies.yaml`. Those gateways must enforce destination,
  SNI/DNS, port and TLS policy; a namespace label alone is not that enforcement.
- At least three schedulable failure-zone nodes for the API spread constraint and two each for worker
  and parser spread constraints.

## Release process

1. Build the API/model, UI and OpenTelemetry Collector images; scan them, generate SBOMs, sign them
   and pin each by immutable `@sha256` digest in a private overlay.
2. Replace `REPLACE_WITH_INGRESS_PROXY_CIDRS` with the exact trusted proxy ranges. Route every
   external application endpoint through its assigned egress gateway; direct public destinations
   will be blocked by the default-deny policies.
   Keep `CRISISWEAVE_UI_AUTH_MODE=forwarded_bearer`; the UI forwards only the ingress-injected
   bearer JWT to FastAPI and does not validate or persist it. Never expose Streamlit directly.
3. Populate separate central-secret records for API, worker, parser, migration and telemetry.
   Parser material must contain only its mutual service token and offline model settings. It must
   not contain PostgreSQL, S3, Qdrant, OIDC, LLM or web-search credentials.
   In this gateway-only topology, pin `CRISISWEAVE_OIDC_JWKS_URL` to the reviewed internal API
   egress-gateway JWKS route. `CRISISWEAVE_OIDC_ALLOW_PRIVATE_JWKS=true` exists only for that route;
   the token issuer claim remains the organizational issuer. If Tavily is enabled, similarly pin
   `CRISISWEAVE_TAVILY_ENDPOINT` to the gateway's credential-free HTTPS request path. The gateway
   must enforce upstream destination and TLS identity; neither client follows redirects or honors
   ambient proxy variables.
   Prove secret rotation end to end: External Secrets refreshes the Kubernetes Secret, the rollout
   controller replaces affected pods, the new credential succeeds and the revoked old credential
   fails. A changed Secret object alone is not evidence of rotation.
4. Render with `kubectl kustomize` or the controlled GitOps renderer, then run:

   ```bash
   python scripts/validate_kubernetes_release.py rendered-directory --rendered
   kubectl apply --server-side --dry-run=server -k rendered-directory
   ```

5. `base/kustomization.yaml` intentionally excludes `migration.yaml`, so the privileged migration
   identity cannot enter the steady-state release. In a controlled one-shot pipeline, apply that
   exact file, wait for `job/crisisweave-migrate` to succeed, then delete the file's two resources
   and verify both `externalsecret/crisisweave-migration` and
   `secret/crisisweave-migration-runtime` are absent before applying the base. Its ExternalSecret
   uses `CreatedOnce` plus owner deletion; do not turn it into a refreshing runtime secret. API and
   worker startup validate the schema but cannot create it. GitOps users should model this as a
   separately administered PreSync migration application with mandatory post-success cleanup.
6. Prove default-deny behavior from each workload, including denied direct internet, model-provider
   access from workers and arbitrary egress from the parser. Prove the separate parser Service accepts
   authenticated worker traffic only through strict mesh mTLS and rejects plaintext/non-worker calls.
7. Execute failover, restore, DAST, malformed-media, load and analyst-pilot exercises against the
   exact image/config/model digests. Validate the independently produced evidence before promotion:

   ```bash
   python scripts/validate_release_evidence.py release-evidence.json
   ```

## Scaling and isolation

- API replicas start at three and scale from 3–12. Worker and parser Deployments each start at two
  and scale independently from 2–20. Tune requests and HPA thresholds only from measured profiles.
  CPU scaling is the portable base; production environments should add a reviewed queue-depth/
  lease-age external metric without exposing a broad PostgreSQL credential to the autoscaler.
- Each worker processes one ingestion and streams the bounded input to the separate
  `crisisweave-parser` Service. Each parser replica processes one extraction, uses request-private
  memory-backed `/tmp`, returns bounded encoded artifact bytes and has no worker storage credential
  or shared exchange volume.
- Kubernetes NetworkPolicy applies to pods and L3/L4 destinations, not HTTP paths or FQDN identity.
  Istio sidecars also share each workload pod's network namespace. High-assurance deployments should
  use a sandboxed runtime and prove both CNI and mesh policy, including sidecar/control-plane traffic,
  rather than infer isolation from labels.
- The API, worker, parser and UI have disruption budgets and zone/host spread constraints. Multi-zone
  application pods do not make a single-zone database, object store or vector cluster highly
  available; release evidence must prove those services separately.

The API HTTP readiness probe covers only its database, exact-version object store and Qdrant. Worker
and parser Kubernetes probes are TCP listener checks; worker startup performs its model/ClamAV
canaries before opening metrics, and parser startup performs its extraction capability canary before
serving, but neither TCP probe continuously revalidates downstream dependencies. Monitor queue/
dead-letter behavior and run authenticated parser plus ClamAV canaries from an authorized controller.

## Telemetry and SLOs

Applications emit bounded, content-free OpenTelemetry spans over internal TLS. The internal CA is
passed only through `CRISISWEAVE_OTEL_EXPORTER_CA_FILE` to the OTLP exporter; it never replaces the
system trust store used for OIDC, model, database, vector or object-storage HTTPS. If the internal
issuer is subordinate to a private root, the mounted file must contain the complete verification
chain required for the collector certificate. The collector removes
authorization, end-user and query attributes before forwarding through the observability gateway.
The checked-in Prometheus rules calculate p50/p95/p99 from the dedicated HTTP-receipt-to-final-body
query and enqueue-to-terminal ingestion histograms, retain a separate core-pipeline error ratio, and
alert on p95 breaches, pipeline errors, durable dead letters, queue-metric refresh failures, and a
lifecycle event pending over five minutes for ten minutes. Workers also expose global
lifecycle-outbox pending-count, oldest-age and bounded delivery-failure metrics. Prove
series presence, scrape authorization, alert delivery and threshold suitability under target load;
manifest validation alone does not establish an SLO. API `/metrics` remains authenticated. Worker
metrics are unauthenticated at the application layer but reachable only through the monitoring
NetworkPolicy; they expose lifecycle-status and ready/retry queue gauges with no tenant/content
label. The portable HPAs remain CPU-based and the current rules do not alert on sustained job-queue
growth—add a reviewed external/custom metrics adapter and queue saturation alert after load testing.
Cost figures use provider token usage
plus operator-controlled compute allocation rates; unset or zero prices must never be presented as
free operation.

Suggested initial objectives are complete HTTP-query p95 below 10 seconds, enqueue-to-terminal
ingestion p95 below 10 minutes and a pipeline error ratio below 1%. These are starting policies to
implement against the end-to-end series, not current-rule results or measured guarantees.
