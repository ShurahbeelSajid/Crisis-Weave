# API contract

All `/v1` requests require exactly one supported credential: `Authorization: Bearer <OIDC JWT>` or
`X-API-Key: <service key>`. Production requires OIDC or hybrid mode. Hybrid service credentials use
`tenant@key_id=secret`, explicit role bindings and a revocation list; the tenant, roles and
`user`/`service` identity type are never accepted from request fields. Supplying both authentication
methods is rejected. JSON models reject unknown fields, and error bodies contain a generic or
bounded validation `detail`, never a stack trace.

Roles map to named permissions for query, evidence read/write/delete, job control, review
read/decision and audit read. Service identities can automate authorized evidence workflows but
cannot make a human-review decision. Production `/metrics` requires its separate constant-time
credential in `X-Metrics-Key` or `Authorization: Bearer`; it is not an OIDC user token.

## Health

- `GET /health/live` — process/version, no authentication.
- `GET /health/ready` — cached dependency checks for the API's configured metadata store, object
  store and Qdrant. A development API with its embedded ingestion worker enabled also checks its
  scanner/parser configuration and reports if that worker exits. Production API replicas disable the
  embedded worker and deliberately have no parser/ClamAV credential, so their readiness does not
  prove ingestion-worker, parser or scanner health. Any required API check failure returns 503
  without exposing credentials.
- `GET /metrics` — Prometheus format; the distinct metrics credential is mandatory in production.

## Ingestion jobs

### `POST /v1/ingestion-jobs`

Uses the same bounded multipart fields as document ingestion: required `file` and optional
credential-free HTTPS `source_uri`. It validates the extension/signature, durably stores an immutable
quarantine input and returns `202` after the queue record commits. The object is not yet evidence:
the dedicated worker verifies it and performs ClamAV scanning before parser extraction.

```json
{
  "job": {
    "id": "uuid",
    "filename": "report.pdf",
    "source_uri": "https://agency.gov/report",
    "size_bytes": 1234,
    "status": "queued",
    "progress": 0,
    "stage": "queued",
    "attempt_count": 0,
    "max_attempts": 3,
    "cancel_requested": false,
    "document_id": null,
    "error_code": null,
    "created_at": "2026-08-03T00:00:00Z",
    "updated_at": "2026-08-03T00:00:00Z",
    "available_at": "2026-08-03T00:00:00Z"
  },
  "deduplicated": false
}
```

An active same-tenant SHA returns the existing job with `deduplicated=true`. Public responses never
contain tenant IDs, hashes, object-store references, lease owners or provider exception messages.

- `GET /v1/ingestion-jobs?limit=100` — latest tenant jobs, limit 1–500.
- `GET /v1/ingestion-jobs/{uuid}` — progress/status or tenant-safe 404.
- `POST /v1/ingestion-jobs/{uuid}/cancel` — requests cooperative cancellation. Queued jobs cancel
  immediately; a running job becomes `cancelling` until its worker reaches a safe checkpoint.
- `POST /v1/ingestion-jobs/{uuid}/retry` — resets only a `dead_letter` job after revalidating its
  immutable input; returns 202, 404 or state-conflict 409.
- `DELETE /v1/ingestion-jobs/{uuid}` — removes terminal history only after exact-version input
  deletion succeeds. Active jobs or a temporarily unavailable object store return 409; the latter
  remains durably pending and is retried by workers.

States are `queued`, `running`, `retry_wait`, `cancelling`, `succeeded`, `cancelled`, and
`dead_letter`. On success, `document_id` selects the normal document endpoint. A worker crash is
resumable after lease expiry; an attempt that published before losing its final acknowledgement is
safe because document ingestion is SHA-idempotent.

## Documents

### `POST /v1/documents`

This synchronous compatibility endpoint is available only outside production. Production returns
409 and directs callers to `/v1/ingestion-jobs`, preventing API processes from parsing untrusted
media inline.

Multipart fields: required `file`; optional credential-free HTTPS `source_uri`. Returns `201`:

```json
{
  "document": {
    "id": "uuid",
    "tenant_id": "server-derived-hash",
    "filename": "report.pdf",
    "media_type": "application/pdf",
    "sha256": "hex",
    "size_bytes": 1234,
    "derived_size_bytes": 5678,
    "status": "ready",
    "source_uri": "https://agency.gov/report",
    "created_at": "2026-08-02T00:00:00Z",
    "error": null,
    "chunk_count": 12,
    "warnings": []
  },
  "deduplicated": false
}
```

Same-tenant SHA duplicates return the existing document with `deduplicated=true`. The upload boundary
authenticates and acquires ingestion capacity before multipart parsing, rejects an invalid negative
`Content-Length` with 400 when supplied, pre-rejects oversized declared bodies, and independently
counts streamed bytes for chunked/misdeclared bodies. Absolute body and per-chunk deadlines reject
slow uploads with 408 and close incomplete connections. Typical failures are auth 401, body 413,
validation/security 422, rate limit 429, capacity 503, disk reservation 422, and bounded ingestion
timeout 504. Internal recovery may retain `cleanup_pending` metadata until vector cleanup succeeds;
such documents are never queryable as ready evidence.

- `GET /v1/documents?limit=100` — latest tenant documents, limit 1–500.
- `GET /v1/documents/{uuid}` — metadata or tenant-safe 404.
- `DELETE /v1/documents?confirmation=RESET` — deletes every evidence item belonging to the
  authenticated tenant and returns `{"deleted_count": N}`. The exact confirmation value is required;
  other tenants are unaffected. Existing queued/running ingestion jobs are cancelled and drained
  before deletion, preventing late publication; their terminal job history is retained. If the
  bounded drain cannot finish, the API returns 409 without deleting evidence; retry after workers
  finish cooperative cancellation.
- `DELETE /v1/documents/{uuid}` — vectors, rows, metadata and derivatives; 204 or tenant-safe 404.

## Query

`POST /v1/query`:

```json
{
  "query": "Compare visible fire indicators with total property damage by state",
  "top_k": 8,
  "allow_web": false,
  "include_modalities": ["pdf_page", "image", "video_frame", "table"]
}
```

`include_modalities` is optional; allowed values are `text`, `pdf_page`, `image`, `video_frame`,
`transcript`, `table`, `web`. The model cannot broaden a caller-specified modality filter. `allow_web`
is request-specific and still requires server provider configuration. Before JSON parsing, the query
boundary authenticates, reserves query capacity, requires `application/json`, enforces the 64 KiB
default streamed-body cap and body/chunk deadlines, and closes rejected incomplete connections.
`include_modalities` accepts at most the seven unique enum values. Validation responses expose at
most 20 errors.

The response contains answer, routes, structured citations/evidence, tool trace (input summary/count/
latency/status), concordance, source freshness, claim/evidence and cross-source conflict signals,
price-aware usage, warnings and request ID. Tool trace is operational metadata, never hidden
chain-of-thought. A source timestamp explicitly distinguishes publication/observation time from
ingestion time; absent source time remains `unknown`. For non-empty analytics, table evidence
preserves up to ten filenames/source URIs
and contains only rows to which each cited `ready` document contributed. The response warns when
provenance is capped or its source count is a lower bound. This is result-row-to-document provenance,
not proof that every cited document determined every aggregate cell.

Visual evidence and citations may contain a `regions` list with typed normalized image/PDF boxes,
chart-element references or video time ranges. Each locator identifies its source as
`derived_provenance`, `human_annotation` or `model_proposal`. Runtime parser locators are
provenance-only and do not claim semantic entailment. Coordinate, trust and scoring details are in
[region-level grounding](12-region-level-grounding.md).

## Human-review workflow

When production oversight classifies a query as high risk, low confidence, contradictory, stale or
otherwise policy-selected for review, `POST /v1/query` returns `202` with `review_id`, `risk_level`,
`reasons` and `request_id`; the candidate answer is withheld.

- `GET /v1/reviews?status=pending&limit=100` and `GET /v1/reviews/{uuid}` require `reviews:read`.
- `POST /v1/reviews/{uuid}/decision` accepts `approve` or `reject` plus a substantive reason. It
  requires `reviews:decide`, an OIDC `user` identity, and a subject different from the requester.
  Decisions are terminal; races or self-approval return 409.
- `GET /v1/reviews/{uuid}/result` returns an approved answer only to the requester or a review reader.
  Pending is 409, rejected is 410, and unrelated/cross-tenant access is indistinguishable from 404.
- `GET /v1/audit/identity-events` requires `audit:read` and returns retained tenant-scoped,
  hash-chained identity/authorization events without raw credentials.

## Security semantics

- Foreign/unknown document IDs are indistinguishable (404).
- Source and citation URLs are metadata only; the server does not fetch them.
- Direct policy-override text can return a normal 200 blocked answer with no routes/evidence.
- Unsafe model SQL is a rejected trace plus warning; it never executes.
- Security headers and `Cache-Control: no-store` apply to responses.
- Use gateway request/body/time limits in addition to application limits.

The parser service's `/health/*` and `/v1/extract` endpoints are internal implementation interfaces,
not public API. Do not route or publish port 8001; a dedicated ingestion worker calls it with a
distinct parser token, a bounded integrity/lineage metadata header and a streamed octet body. The
parser writes only to request-private temporary storage and returns bounded encoded artifact bytes;
there is no worker/parser exchange volume. Compose relies on pair-specific internal networks, while
Kubernetes promotion additionally requires live strict mesh mTLS and enforced NetworkPolicy.

Development OpenAPI is generated at `/openapi.json` and Swagger at `/docs`. Production startup
requires docs disabled; publish a reviewed static contract to developers instead.
