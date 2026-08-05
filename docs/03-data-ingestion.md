# Data ingestion and lineage

## Supported formats and default limits

| Type | Extraction | Default limit |
|---|---|---|
| PDF | Sorted text, every page rendered to JPEG, OCR for sparse pages | 50 MB, 250 pages, 40 MP/render |
| JPEG/PNG/WebP | EXIF transpose, RGB JPEG derivative, OCR, visual vector | 50 MB, 40 MP input |
| MP4/WebM | ffprobe duration, fixed-interval frames, OCR, optional Whisper | 50 MB, 30 min, 120 frames |
| CSV | UTF-8 header/rows, batched text chunks, normalized NOAA fields | 50 MB, 250 columns, 50k rows |
| JSON | Object/list/event records, batched text and normalized fields | 50 MB, 50k records |
| TXT/MD/SRT/VTT | UTF-8 chunking with overlap | 50 MB |

Proxy limits should be only slightly above application limits so neither layer is the sole control.
Video deployments commonly raise the byte limit while preserving duration/frame/CPU quotas.

## Evidence schema

Every evidence unit has a UUID, server-derived `tenant_id`, document ID, source name and optional
HTTPS URI, modality, text/OCR/transcript, page or timecode, derivative path, metadata, vector score,
reranker score and bounded typed visual locators. Image/PDF locators use normalized top-left
coordinates; video locators use bounded time ranges and may include a frame box. Parser-created
locators are explicitly `derived_provenance` and identify the source extent without asserting that
it entails an answer claim. See [region-level grounding](12-region-level-grounding.md).
Qdrant points repeat authorization metadata so every vector query injects tenant
filtering, but search returns only point IDs/scores. The API then hydrates content from authoritative
tenant-scoped PostgreSQL rows in production (DuckDB locally) and retains only `ready` documents
before synthesis.

## NOAA normalization

CSV/JSON rows retain their original JSON and map common Storm Events columns to a restricted table:
event/year/state/type/county-zone, direct injuries/deaths, property/crop damage, magnitude and
narrative. `K`, `M`, and `B` damage suffixes are converted to numeric values. Unknown columns remain
in raw lineage but are unavailable to model-written SQL. Every structured text cell and retained raw
record is normalized and capped before persistence/chunking; non-standard `NaN`/`Infinity` JSON is
rejected.

## OCR and transcription

OCR and visual understanding are separate. OCR extracts characters during ingestion; it does not
interpret objects, colors, chart geometry, burn scars, or spatial relationships. A vision-language
model can interpret selected pixels later at query time, but it is not the OCR engine.

In development on Windows, the extractor automatically uses the fixed
`scripts/windows_ocr.ps1` Windows Runtime helper when Tesseract is unavailable. The helper uses a
compatible OCR language from the current Windows user profile and returns text without confidence or
tight word boxes. This fallback is not used in parser or production profiles. `crisisweave doctor`
reports Tesseract availability only, so `tesseract: false` is not by itself proof that Windows OCR
will fail.

When configured, Tesseract takes precedence. It is invoked by a fixed executable path, fixed
`stdout --psm 3` arguments, no shell, and a timeout. The application currently does not pass a
language option, so operators must manage and validate the executable's installed/default language
data. If Tesseract is found but produces no text, the extractor does not retry with Windows OCR.
Missing or failed OCR produces a visible document warning; the system does not silently claim text
was read.

Faster Whisper is optional in development and required by the production/parser profiles; it runs
CPU/int8 by default and produces timestamped transcript chunks. Production must pin the model
revision/checksum and benchmark language/domain accuracy. FFmpeg/ffprobe are required to inspect and
sample video before transcription.

PDF pages and sampled frames are visually embedded even if OCR is empty. Development hash vectors
encode available text to validate plumbing; they do not claim pixel semantics.
When OCR is empty, image and PDF evidence receives a provenance-only fallback such as
`Visual evidence from <filename>` or `Rendered page N from <filename>` so local retrieval and
citations remain intelligible without claiming what the pixels contain.

OCR, embeddings, and transcription are ingestion-time operations. Documents must be deleted/reset
and re-ingested after changing any of them. Exact local and model-enabled setup steps are in
[OCR, vision, and model setup](ocr-vision-and-models.md).

## Durable asynchronous jobs

`POST /v1/ingestion-jobs` first rejects unsupported or extension/signature-mismatched media, then
persists the bounded upload as an immutable quarantine job object and creates a tenant-scoped queue
record before returning `202`. Development uses a SQLite WAL queue and an
embedded worker for a zero-service local experience. Production fails closed unless metadata/jobs
use PostgreSQL and objects use an exact-version S3-compatible reference; API replicas set
`CRISISWEAVE_INGESTION_WORKER_ENABLED=false`, and dedicated `crisisweave ingestion-worker`
processes claim work with `FOR UPDATE SKIP LOCKED`.

The Streamlit batch uploader submits every validated selection before it waits for completion, then
polls the jobs as one batch. Multiple worker and parser replicas can therefore make progress in
parallel while the UI preserves each file's result, source URI, quota, and cancellation state.

Claims have an owner and bounded lease. Progress checkpoints extend the lease through validation,
scanning, extraction, persistence, indexing and publication. A crashed worker's expired job returns
to `retry_wait` until its attempt budget is exhausted, then moves to `dead_letter`. Retrying a
dead-letter job reuses the integrity-checked immutable input. Active and dead-letter inputs share
the tenant document/byte quota, so repeated malware or parser failures cannot create unbounded
object-storage retention; operators can delete terminal jobs and should also apply a reviewed
quarantine lifecycle policy. Cancellation is cooperative at safe
publication checkpoints; a cancellation racing final publication removes the resulting document.
Only opaque job IDs, stages, progress, attempts and bounded error codes cross the public API—tenant
IDs, object references, provider errors and local paths do not.

The existing synchronous `POST /v1/documents` and direct CLI ingestion remain available for local
development and compatibility tests. Production rejects synchronous HTTP ingestion so API workers
never parse untrusted media. Multi-worker coordination still relies on the metadata tenant lock,
Qdrant's document visibility rules and the isolated parser-service boundary.

## Immutable object publication

Local development publishes originals under a tenant-scoped SHA-256 path and derivatives under
their generated document directory. Production publishes originals, derivatives and queued job
inputs to an S3-compatible bucket with versioning enabled and stores an opaque reference containing
the exact `versionId`. Retrieval never follows a mutable latest-object key: it requests the recorded
version, enforces a byte cap and checks SHA-256 object metadata before pixels or parser input are used.

Extraction still uses bounded temporary storage, but it is not shared: the worker has local object/
derivative staging and the parser creates a request-private temporary directory. The worker validates
all returned artifact names, bytes and lineage before upload, rewrites chunk lineage to exact object
references, indexes those references in Qdrant, and removes local staging. Object keys are
application-generated; tenant IDs and document/job UUIDs namespace tenant artifacts, while content
hashes make original publication idempotent. Unscanned queued inputs are quarantine objects and must
never be publicly served or treated as evidence. The bucket must deny public access and unencrypted
writes; use scoped workload identity, server-side encryption (KMS when required), object-version
lifecycle rules and a separately tested backup/restore policy.

## Quarantine and malicious media

- User filenames never become storage paths; generated UUID/SHA paths are used.
- Magic bytes and extension must agree. SVG, archives and office containers are excluded.
- PDF active-action markers (`JavaScript`, `JS`, `Launch`) are rejected as defense in depth.
- PDFium's default non-V8 build renders pages; its liberal binary/dependency license bundle must be
  retained in redistributed images.
- Pillow verifies images and enforces decompression limits.
- FFmpeg/ffprobe receive no network URL, no shell and `-nostdin`; duration/frame/time limits apply.
- Development can use an absolute administrator-configured scanner executable. Production requires
  network `clamd`; its signed image sets a 64 MiB INSTREAM ceiling above the explicit 50 MiB object
  limit. Startup verifies definition freshness, streams a full-limit clean canary, and requires an
  explicit EICAR `FOUND` verdict; ingestion fails closed on every scanner/protocol error.
- The production parser is a separate service with no general egress or application data mount. It
  has a read-only root, dropped capabilities, container resource limits, a one-job-per-replica
  semaphore, and a killable resource-limited extraction child with a scrubbed environment.

### Authenticated parser streaming and private scratch

The worker sends a bounded, base64url-encoded metadata header containing the job UUID, expected
SHA-256/size/type and lineage, then streams the input as `application/octet-stream` with the distinct
parser token. The parser counts and hashes the stream while writing it to a newly created private
temporary directory, re-sniffs its media type and rejects a stalled, short, oversized or mismatched
body before extraction.

Derivative files never cross as filesystem paths. The parser returns bounded JSON with safe artifact
names and base64-encoded bytes; the worker decodes within document and IPC budgets, requires exact
chunk-to-artifact lineage, writes its own staging files and publishes immutable versions. The parser
temporary directory is removed when the request exits. No worker/parser exchange volume exists in
the production Compose or Kubernetes reference.

The service token does not make a compromised parser trustworthy. Retain the one-job semaphore,
independent worker response validation, strict destination policy and resource limits. Compose uses
pair-specific internal networks; Kubernetes requires a separate parser Deployment plus live strict
mesh mTLS and enforcing NetworkPolicy. Custom seccomp/AppArmor policy, workload identity,
malformed-media testing and proof of transport enforcement remain staging release gates.

These controls follow the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

## Deletion and retention

`DELETE /v1/documents/{id}` is tenant-scoped and deletes vectors, analytics rows, metadata and
derived artifacts. Tenant-scoped content-addressed originals are deleted only after no document
references the exact object. Operators must include object backups, Qdrant snapshots, audit retention and provider logs
in the formal deletion SLA; a database delete alone is not proof of erasure from backups.

`DELETE /v1/documents?confirmation=RESET` applies the same cleanup path to every document owned by
the authenticated tenant. Before deletion it atomically cancels queued work, cooperatively cancels
running work, waits for leases to drain, and then takes the tenant ingestion lock as a final
publication barrier. Terminal job records remain as audit history; delete them separately with the
job-history endpoint. Cleanup across Qdrant, metadata and objects is not transactionally atomic, so
a failed request must be retried after the underlying dependency recovers.

In production the same limitation spans Qdrant, PostgreSQL and S3: there is no distributed
transaction. Exact references remain in metadata while cleanup is pending, deletion is idempotent,
and non-`ready` documents are excluded. A bucket lifecycle rule must also expire unreferenced upload
versions after a reviewed safety window because a process can fail in the narrow interval between an
object write and its metadata commit.

If a vector cleanup fails, metadata remains in `cleanup_pending` instead of being purged. Dedicated
ingestion workers process indexed, bounded recovery batches for interrupted `processing`, `deleting`
and `cleanup_pending` records at startup and periodically; API replicas never run this global scan.
Already-cleaned `failed` records are retained without being repeatedly selected. Retrieval also
excludes every non-`ready` document ID at the Qdrant query boundary,
so partially published or orphaned points cannot crowd authorized ready evidence while repair is
pending.

## Adding an extractor

1. Add a signature/extension pair; never trust request MIME alone.
2. Define byte/entity/pixel/time/CPU bounds before parsing.
3. Produce `Chunk` values with complete lineage and deterministic document-scoped IDs.
4. Ensure the parser has no general egress (only its authenticated internal service channel) and
   does not execute macros/scripts.
5. Add valid, malformed, oversized, active-content, timeout and deletion tests.
6. Update the threat model, SBOM/license review and dataset/model cards.
