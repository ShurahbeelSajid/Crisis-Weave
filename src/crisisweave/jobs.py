"""Durable asynchronous ingestion orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import re
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import structlog

from crisisweave.config import Settings
from crisisweave.ingestion import IngestionCancelled, IngestionService
from crisisweave.job_store import (
    EnqueueJobResult,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobStore,
    JobRecord,
    build_ingestion_job_store,
    new_job_record,
)
from crisisweave.object_store import ObjectStore, build_object_store
from crisisweave.observability import (
    JOB_QUEUE_REFRESH_FAILURES,
    record_ingestion_job_completion,
    record_ingestion_lifecycle_delivery_failure,
    record_ingestion_lifecycle_exclusion,
    record_ingestion_lifecycle_outbox_state,
    record_ingestion_lifecycle_span,
    record_job_queue_depth,
)
from crisisweave.security import SecurityError, safe_filename, sha256_file, sniff_media_type

MAX_JOB_ATTEMPTS = 3
WORKER_POLL_SECONDS = 0.25
logger = structlog.get_logger()
_LIFECYCLE_OPERATION_DOMAIN = b"crisisweave:ingestion-lifecycle-operation:v1\x00"
_MAX_OBSERVABLE_LIFECYCLE_SECONDS = 30 * 24 * 60 * 60
_MIN_LIFECYCLE_RETENTION_DAYS = 7
_MAX_LIFECYCLE_RETENTION_DAYS = 365
_LIFECYCLE_PRUNE_INTERVAL_SECONDS = 60 * 60
_LIFECYCLE_PRUNE_BATCH = 500


def utc_now() -> datetime:
    return datetime.now(UTC)


def lifecycle_operation_id(event_id: str) -> str:
    """Return a non-reversible, content-free 128-bit trace correlation identifier."""

    try:
        event_bytes = uuid.UUID(event_id).bytes
    except ValueError as exc:
        raise ValueError("Lifecycle event identifier must be a UUID") from exc
    return hashlib.sha256(_LIFECYCLE_OPERATION_DOMAIN + event_bytes).hexdigest()[:32]


class JobNotFoundError(LookupError):
    pass


class JobStateConflictError(ValueError):
    pass


class JobCleanupDurabilityError(RuntimeError):
    """Raised only when neither durable cleanup state nor immediate deletion succeeds."""


class IngestionJobService:
    """Own a durable spool and execute one leased job at a time.

    Development can run an embedded API worker with SQLite and local objects. Production
    uses PostgreSQL ``SKIP LOCKED`` leases, versioned object references, and dedicated
    worker processes; hostile-media extraction still crosses the authenticated no-egress
    parser-service boundary.
    """

    def __init__(
        self,
        settings: Settings,
        ingestion: IngestionService,
        *,
        store: IngestionJobStore | None = None,
        object_store: ObjectStore | None = None,
        clock: Callable[[], datetime] = utc_now,
        lifecycle_retention_days: int = 14,
    ) -> None:
        if (
            isinstance(lifecycle_retention_days, bool)
            or not _MIN_LIFECYCLE_RETENTION_DAYS
            <= lifecycle_retention_days
            <= _MAX_LIFECYCLE_RETENTION_DAYS
        ):
            raise ValueError("Lifecycle retention must be between 7 and 365 days")
        self.settings = settings
        self.ingestion = ingestion
        self.store = store or build_ingestion_job_store(settings)
        self.object_store = object_store or build_object_store(settings)
        self._owns_object_store = object_store is None
        self.clock = clock
        self.work_dir = settings.data_dir / "ingestion-job-work"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.owner = f"worker-{uuid.uuid4()}"
        self.lease_seconds = float(settings.ingestion_timeout_seconds + 30)
        self._closed = False
        self._close_lock = threading.Lock()
        self._next_metrics_refresh = 0.0
        self._next_lifecycle_metrics_refresh = 0.0
        self._next_lifecycle_prune = 0.0
        self._lifecycle_retention_days = lifecycle_retention_days
        self._lifecycle_worker = (
            settings.app_env != "production" or settings.runtime_role == "ingestion_worker"
        )

    def drain_lifecycle_events(self, *, limit: int = 100) -> int:
        """Deliver durable terminal events at least once with stable deduplication IDs."""

        if not self._lifecycle_worker:
            return 0

        try:
            events = self.store.claim_lifecycle_events(
                self.owner,
                now=self.clock(),
                lease_seconds=30.0,
                limit=limit,
            )
        except Exception as exc:
            self._record_lifecycle_delivery_failure("claim")
            logger.warning(
                "ingestion_lifecycle_outbox_claim_failed",
                error_type=type(exc).__name__,
            )
            return 0
        delivered = 0
        for event in events:
            try:
                operation_id = lifecycle_operation_id(event.event_id)
                duration = event.duration_seconds
                exclusion_reason = None
                if duration < 0:
                    exclusion_reason = "clock_skew"
                elif duration > _MAX_OBSERVABLE_LIFECYCLE_SECONDS:
                    exclusion_reason = "older_than_30_days"
                if exclusion_reason is not None:
                    try:
                        record_ingestion_lifecycle_exclusion(exclusion_reason)
                    except Exception as exc:
                        logger.warning(
                            "ingestion_lifecycle_exclusion_counter_failed",
                            lifecycle_event_id=event.event_id,
                            exclusion_reason=exclusion_reason,
                            error_type=type(exc).__name__,
                        )
                    logger.warning(
                        "ingestion_lifecycle_sample_excluded",
                        lifecycle_event_id=event.event_id,
                        operation_id=operation_id,
                        lifecycle_generation=event.lifecycle_generation,
                        terminal_status=event.status.value,
                        enqueue_to_terminal_seconds=duration,
                        processing_seconds=event.processing_seconds,
                        compute_cost_usd=event.compute_cost_usd,
                        measurement_quality=("estimated" if event.usage_estimated else "measured"),
                        exclusion_reason=exclusion_reason,
                    )
                else:
                    measurement_quality: Literal["measured", "estimated"] = (
                        "estimated" if event.usage_estimated else "measured"
                    )
                    record_ingestion_job_completion(event.status.value, duration)
                    record_ingestion_lifecycle_span(
                        operation_id,
                        event.status.value,
                        lifecycle_started_at=event.lifecycle_started_at,
                        terminal_at=event.terminal_at,
                        processing_seconds=event.processing_seconds,
                        compute_cost_usd=event.compute_cost_usd,
                        measurement_quality=measurement_quality,
                    )
                    logger.info(
                        "ingestion_lifecycle_terminal",
                        lifecycle_event_id=event.event_id,
                        operation_id=operation_id,
                        lifecycle_generation=event.lifecycle_generation,
                        terminal_status=event.status.value,
                        enqueue_to_terminal_seconds=duration,
                        processing_seconds=event.processing_seconds,
                        compute_cost_usd=event.compute_cost_usd,
                        measurement_quality=measurement_quality,
                        delivery_attempt=event.delivery_attempts,
                    )
            except Exception as exc:
                self._record_lifecycle_delivery_failure("emit")
                # Keep terminal API and worker paths available. The lease expires and
                # the same stable event_id is retried for downstream deduplication.
                logger.warning(
                    "ingestion_lifecycle_emit_failed",
                    lifecycle_event_id=event.event_id,
                    error_type=type(exc).__name__,
                )
                continue
            try:
                acknowledged = self.store.complete_lifecycle_event(
                    event.event_id,
                    self.owner,
                    now=self.clock(),
                )
            except Exception as exc:
                self._record_lifecycle_delivery_failure("ack")
                logger.warning(
                    "ingestion_lifecycle_outbox_ack_failed",
                    operation_id=operation_id,
                    error_type=type(exc).__name__,
                )
                continue
            if not acknowledged:
                self._record_lifecycle_delivery_failure("ack")
                logger.warning(
                    "ingestion_lifecycle_outbox_ack_raced",
                    operation_id=operation_id,
                )
                continue
            delivered += 1
        return delivered

    @staticmethod
    def _record_lifecycle_delivery_failure(
        stage: Literal["claim", "emit", "ack", "prune"],
    ) -> None:
        try:
            record_ingestion_lifecycle_delivery_failure(stage)
        except Exception as exc:
            logger.warning(
                "ingestion_lifecycle_delivery_failure_counter_failed",
                delivery_stage=stage,
                error_type=type(exc).__name__,
            )

    def _prune_delivered_lifecycle_events(self) -> int:
        """Run bounded worker-only retention without touching pending evidence."""

        if not self._lifecycle_worker:
            return 0
        monotonic_now = time.monotonic()
        if monotonic_now < self._next_lifecycle_prune:
            return 0
        self._next_lifecycle_prune = monotonic_now + _LIFECYCLE_PRUNE_INTERVAL_SECONDS
        before = self.clock() - timedelta(days=self._lifecycle_retention_days)
        try:
            return self.store.prune_delivered_lifecycle_events(
                before=before,
                limit=_LIFECYCLE_PRUNE_BATCH,
            )
        except Exception as exc:
            self._record_lifecycle_delivery_failure("prune")
            logger.warning(
                "ingestion_lifecycle_outbox_prune_failed",
                error_type=type(exc).__name__,
            )
            return 0

    def _refresh_lifecycle_outbox_metrics(self) -> None:
        """Refresh worker-only global outbox gauges without exposing identifiers."""

        if not self._lifecycle_worker:
            return
        now = time.monotonic()
        if now < self._next_lifecycle_metrics_refresh:
            return
        self._next_lifecycle_metrics_refresh = now + 5.0
        try:
            pending_count, oldest_pending_seconds = self.store.lifecycle_outbox_stats(
                now=self.clock()
            )
            record_ingestion_lifecycle_outbox_state(pending_count, oldest_pending_seconds)
        except Exception as exc:
            logger.warning(
                "ingestion_lifecycle_outbox_metric_refresh_failed",
                error_type=type(exc).__name__,
            )

    def _refresh_queue_metrics(self) -> None:
        now = time.monotonic()
        if now < self._next_metrics_refresh:
            return
        self._next_metrics_refresh = now + 5.0
        status_counts = getattr(self.store, "status_counts", None)
        if not callable(status_counts):
            return
        try:
            record_job_queue_depth(status_counts())
        except Exception as exc:
            JOB_QUEUE_REFRESH_FAILURES.inc()
            logger.warning(
                "job_queue_metric_refresh_failed",
                error_type=type(exc).__name__,
            )

    @staticmethod
    def _cleanup_error_code(exc: Exception) -> str:
        name = re.sub(r"[^A-Z0-9_]", "_", type(exc).__name__.upper())[:60]
        return f"OBJECT_DELETE_{name}"[:80]

    def _finalize_requested_delete(self, job: JobRecord) -> bool:
        if not job.delete_requested or job.input_cleanup_pending:
            return False
        try:
            deleted = self.store.delete_terminal(job.tenant_id, job.id)
        except Exception as exc:
            logger.warning(
                "job_delete_finalization_failed",
                job_id=job.id,
                error_type=type(exc).__name__,
            )
            return False
        if deleted is not None:
            return True
        current = self.store.get(job.tenant_id, job.id)
        return current is None

    def _remove_input(self, job: JobRecord) -> bool:
        if not job.input_cleanup_pending:
            return self._finalize_requested_delete(job) if job.delete_requested else True
        try:
            self.object_store.delete(job.input_object_ref)
        except Exception as exc:
            # The job row remains a durable exact-version deletion intent. A later
            # worker pass retries it; never erase the only reference on failure.
            logger.warning(
                "job_input_cleanup_failed",
                job_id=job.id,
                error_type=type(exc).__name__,
            )
            return False
        try:
            cleaned = self.store.complete_input_cleanup(
                job.id,
                job.input_object_ref,
                now=self.clock(),
            )
        except Exception as exc:
            logger.warning(
                "job_input_cleanup_completion_failed",
                job_id=job.id,
                error_type=type(exc).__name__,
            )
            return False
        if cleaned is None:
            # Concurrent cleaners are harmless because both local and exact-version
            # S3 deletion are idempotent. Re-read to distinguish that race from a
            # durable-state failure without discarding the reference ourselves.
            current = self.store.get(job.tenant_id, job.id)
            if current is None:
                return True
            if current.input_cleanup_pending:
                logger.error("job_input_cleanup_state_not_committed", job_id=job.id)
                return False
            cleaned = current
        if cleaned.delete_requested:
            return self._finalize_requested_delete(cleaned)
        return True

    def _remove_orphan_input(self, input_object_ref: str) -> bool:
        try:
            self.object_store.delete(input_object_ref)
        except Exception as exc:
            try:
                self.store.record_orphan_cleanup_failure(
                    input_object_ref,
                    self._cleanup_error_code(exc),
                    now=self.clock(),
                )
            except Exception as state_exc:
                # The cleanup row was already durably committed by the scheduler;
                # failing to update diagnostic counters does not lose the reference.
                logger.error(
                    "orphan_cleanup_failure_record_failed",
                    error_type=type(state_exc).__name__,
                )
            logger.warning("orphan_input_cleanup_failed", error_type=type(exc).__name__)
            return False
        try:
            completed = self.store.complete_orphan_cleanup(input_object_ref)
        except Exception as exc:
            logger.warning(
                "orphan_input_cleanup_completion_failed",
                error_type=type(exc).__name__,
            )
            return False
        if not completed:
            logger.warning("orphan_input_cleanup_completion_raced")
        return True

    def _discard_unowned_input(self, input_object_ref: str) -> None:
        """Persist an orphan reference before best-effort immediate deletion."""

        try:
            self.store.schedule_orphan_cleanup(input_object_ref, now=self.clock())
        except Exception as state_exc:
            # If durable state is unavailable, immediate deletion is the only safe
            # fallback. Surface the compound failure rather than silently leaking.
            try:
                self.object_store.delete(input_object_ref)
            except Exception as delete_exc:
                raise JobCleanupDurabilityError(
                    "Could not persist or execute orphan input cleanup"
                ) from ExceptionGroup(
                    "Orphan input cleanup failed",
                    [state_exc, delete_exc],
                )
            return
        self._remove_orphan_input(input_object_ref)

    def reconcile_input_cleanup(self, *, limit: int = 100) -> int:
        """Retry durable job and orphan deletion intents without losing references."""

        completed = 0
        for job in self.store.cleanup_candidates(limit=limit):
            completed += int(self._remove_input(job))
        remaining = max(1, limit - completed)
        for input_object_ref in self.store.orphan_cleanup_candidates(limit=remaining):
            completed += int(self._remove_orphan_input(input_object_ref))
        return completed

    def _materialize_input(self, job: JobRecord) -> tuple[Path, Path]:
        root = self.work_dir.resolve()
        job_root = root / job.id
        if job_root.exists():
            if job_root.is_symlink() or job_root.resolve().parent != root:
                raise SecurityError("Ingestion job work directory is unsafe")
            shutil.rmtree(job_root)
        job_root.mkdir(mode=0o700)
        target = job_root / f"input{Path(job.filename).suffix.lower()}"
        try:
            self.object_store.materialize(
                job.input_object_ref,
                target,
                max_bytes=job.size_bytes,
                expected_sha256=job.sha256,
            )
            if target.stat().st_size != job.size_bytes:
                raise SecurityError("Queued ingestion object size changed")
        except Exception:
            shutil.rmtree(job_root, ignore_errors=True)
            raise
        return target, job_root

    def enqueue(
        self,
        upload_path: Path,
        *,
        tenant_id: str,
        filename: str,
        source_uri: str | None,
    ) -> EnqueueJobResult:
        filename = safe_filename(filename)
        suffix = Path(filename).suffix.lower()
        try:
            size = upload_path.stat().st_size
            if size <= 0 or size > self.settings.max_upload_bytes:
                raise SecurityError(
                    f"File must be between 1 and {self.settings.max_upload_bytes} bytes"
                )
            if upload_path.suffix.lower() != suffix:
                raise SecurityError("Upload extension does not match the declared filename")
            # Reject unsupported and extension/content-mismatched uploads before they
            # consume durable object-storage or dead-letter capacity.
            sniff_media_type(upload_path)
            digest = sha256_file(upload_path)
            job_id = str(uuid.uuid4())
            object_reference = self.object_store.put_job_input(
                upload_path,
                tenant_id=tenant_id,
                job_id=job_id,
                sha256=digest,
                suffix=suffix,
            )
        finally:
            upload_path.unlink(missing_ok=True)

        try:
            now = self.clock()
            record = new_job_record(
                job_id=job_id,
                tenant_id=tenant_id,
                filename=filename,
                source_uri=source_uri,
                input_object_ref=object_reference,
                sha256=digest,
                size_bytes=size,
                max_attempts=MAX_JOB_ATTEMPTS,
                compute_cost_per_hour_usd=self.settings.ingestion_compute_cost_per_hour_usd,
                now=now,
            )
        except Exception as record_exc:
            try:
                self._discard_unowned_input(object_reference)
            except Exception as cleanup_exc:
                raise JobCleanupDurabilityError(
                    "Job construction failed and input cleanup could not be made durable"
                ) from ExceptionGroup(
                    "Job construction and cleanup failed",
                    [record_exc, cleanup_exc],
                )
            raise

        try:
            with self.ingestion.tenant_operation(tenant_id):
                document_count, document_bytes = self.ingestion.store.tenant_usage(tenant_id)
                remaining_jobs = max(0, self.settings.max_documents_per_tenant - document_count)
                remaining_bytes = max(
                    0, self.settings.max_storage_bytes_per_tenant - document_bytes
                )
                stored, duplicate = self.store.enqueue(
                    record,
                    max_retained_jobs=remaining_jobs,
                    max_retained_bytes=remaining_bytes,
                )
        except Exception as enqueue_exc:
            try:
                committed = self.store.get(tenant_id, job_id)
            except Exception as read_exc:
                # The INSERT may have committed even though its acknowledgement was
                # lost. Retain the object rather than risking deletion under a live
                # job; delayed bucket lifecycle is the final orphan backstop.
                raise JobCleanupDurabilityError(
                    "Queue outcome is unknown; the exact input version was retained"
                ) from ExceptionGroup(
                    "Queue insertion and outcome verification failed",
                    [enqueue_exc, read_exc],
                )
            if committed is not None:
                if committed.input_object_ref != object_reference or committed.sha256 != digest:
                    raise JobCleanupDurabilityError(
                        "Queue outcome is inconsistent; the exact input version was retained"
                    ) from enqueue_exc
                return EnqueueJobResult(job=committed.public(), deduplicated=False)
            try:
                self._discard_unowned_input(object_reference)
            except Exception as cleanup_exc:
                raise JobCleanupDurabilityError(
                    "Queue insertion failed and input cleanup could not be made durable"
                ) from ExceptionGroup(
                    "Queue insertion and cleanup failed",
                    [enqueue_exc, cleanup_exc],
                )
            raise
        if duplicate:
            self._discard_unowned_input(object_reference)
        return EnqueueJobResult(job=stored.public(), deduplicated=duplicate)

    def get(self, tenant_id: str, job_id: str) -> IngestionJob:
        record = self.store.get(tenant_id, job_id)
        if record is None:
            raise JobNotFoundError
        return record.public()

    def list(self, tenant_id: str, *, limit: int) -> list[IngestionJob]:
        return [record.public() for record in self.store.list(tenant_id, limit=limit)]

    def cancel(self, tenant_id: str, job_id: str) -> IngestionJob:
        record = self.store.request_cancel(tenant_id, job_id, now=self.clock())
        if record is None:
            raise JobNotFoundError
        if record.status == IngestionJobStatus.CANCELLED:
            self._remove_input(record)
        return record.public()

    def cancel_all(self, tenant_id: str, *, timeout_seconds: float | None = None) -> int:
        """Cancel and drain all active work that precedes a tenant reset.

        Immediate queued cancellations and cooperative running cancellations retain their
        terminal history. ``reset`` then takes the shared tenant operation guard for a
        final cancellation sweep and evidence deletion at one linearization point.
        """
        timeout = self.lease_seconds + 5.0 if timeout_seconds is None else timeout_seconds
        if timeout <= 0:
            raise ValueError("Cancellation timeout must be positive")
        deadline = time.monotonic() + timeout
        affected_ids: set[str] = set()
        while True:
            affected = self.store.request_cancel_all(tenant_id, now=self.clock())
            affected_ids.update(record.id for record in affected)
            for record in affected:
                if record.status == IngestionJobStatus.CANCELLED:
                    self._remove_input(record)
            self.store.recover_expired(now=self.clock())
            if self.store.active_count(tenant_id) == 0:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JobStateConflictError(
                    "Timed out waiting for active ingestion jobs to stop; reset was not run"
                )
            time.sleep(min(WORKER_POLL_SECONDS, remaining))

        # A crashed worker can be converted from CANCELLING to CANCELLED by lease
        # recovery, so perform the input cleanup after the drain as well.
        for job_id in affected_ids:
            terminal = self.store.get(tenant_id, job_id)
            if terminal is not None and terminal.status == IngestionJobStatus.CANCELLED:
                self._remove_input(terminal)
        return len(affected_ids)

    def reset(self, tenant_id: str, *, timeout_seconds: float | None = None) -> int:
        """Cancel preceding work and atomically cancel race entrants before evidence deletion."""

        self.cancel_all(tenant_id, timeout_seconds=timeout_seconds)

        def cancel_since_drain() -> None:
            affected = self.store.request_cancel_all(tenant_id, now=self.clock())
            for record in affected:
                if record.status == IngestionJobStatus.CANCELLED:
                    self._remove_input(record)

        return self.ingestion.reset_tenant(tenant_id, cancel_since_drain)

    def retry(self, tenant_id: str, job_id: str) -> IngestionJob:
        current = self.store.get(tenant_id, job_id)
        if current is None:
            raise JobNotFoundError
        if current.status != IngestionJobStatus.DEAD_LETTER:
            raise JobStateConflictError("Only dead-letter jobs can be retried")
        work_root: Path | None = None
        try:
            _path, work_root = self._materialize_input(current)
        except (FileNotFoundError, SecurityError) as exc:
            raise JobStateConflictError("Dead-letter input is unavailable or changed") from exc
        finally:
            if work_root is not None:
                shutil.rmtree(work_root, ignore_errors=True)
        retried = self.store.retry(
            tenant_id,
            job_id,
            now=self.clock(),
            compute_cost_per_hour_usd=self.settings.ingestion_compute_cost_per_hour_usd,
        )
        if retried is None:
            raise JobStateConflictError("Job state changed before retry")
        return retried.public()

    def delete(self, tenant_id: str, job_id: str) -> None:
        current = self.store.get(tenant_id, job_id)
        if current is None:
            raise JobNotFoundError
        if current.status not in {
            IngestionJobStatus.SUCCEEDED,
            IngestionJobStatus.CANCELLED,
            IngestionJobStatus.DEAD_LETTER,
        }:
            raise JobStateConflictError("Cancel the active job before deleting it")
        requested = self.store.request_delete(tenant_id, job_id, now=self.clock())
        if requested is None:
            raise JobStateConflictError("Job state changed before deletion")
        if not self._remove_input(requested):
            remaining = self.store.get(tenant_id, job_id)
            if remaining is None or not remaining.input_cleanup_pending:
                raise JobStateConflictError("Job state changed before deletion")
            raise JobStateConflictError(
                "Input deletion is durably pending; retry after storage dependencies recover"
            )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        name = re.sub(r"[^A-Z0-9_]", "_", type(exc).__name__.upper())[:60]
        return f"INGESTION_{name}"[:80]

    def process_next(self) -> bool:
        now = self.clock()
        self.store.recover_expired(now=now)
        self.drain_lifecycle_events()
        self._prune_delivered_lifecycle_events()
        self.reconcile_input_cleanup()
        self._refresh_queue_metrics()
        self._refresh_lifecycle_outbox_metrics()
        job = self.store.claim(self.owner, now=now, lease_seconds=self.lease_seconds)
        if job is None:
            return False
        attempt_started = time.perf_counter()

        def attempt_usage() -> tuple[float, float]:
            seconds = max(0.0, time.perf_counter() - attempt_started)
            return (
                seconds,
                seconds * job.compute_cost_per_hour_usd / 3600,
            )

        def cancelled() -> bool:
            return self.store.cancellation_requested(job.id, self.owner)

        def progress(stage: str, percentage: int) -> None:
            if not self.store.heartbeat(
                job.id,
                self.owner,
                progress=percentage,
                stage=stage,
                now=self.clock(),
                lease_seconds=self.lease_seconds,
            ):
                raise IngestionCancelled("Ingestion job lease was lost")

        work_root: Path | None = None
        try:
            path, work_root = self._materialize_input(job)
            if cancelled():
                raise IngestionCancelled("Ingestion cancellation was requested")
            result = self.ingestion.ingest_path(
                path,
                tenant_id=job.tenant_id,
                filename=job.filename,
                source_uri=job.source_uri,
                progress_callback=progress,
                cancel_requested=cancelled,
            )
            processing_seconds, compute_cost_usd = attempt_usage()
            if not self.store.succeed(
                job.id,
                self.owner,
                result.document.id,
                now=self.clock(),
                processing_seconds=processing_seconds,
                compute_cost_usd=compute_cost_usd,
            ):
                # Cancellation can race the final READY transition. Honour it by
                # removing the newly published document before completing the job.
                current = self.store.get(job.tenant_id, job.id)
                if current is not None and current.cancel_requested:
                    if not result.deduplicated:
                        self.ingestion.delete(job.tenant_id, result.document.id)
                    self.store.mark_cancelled(
                        job.id,
                        self.owner,
                        now=self.clock(),
                        processing_seconds=processing_seconds,
                        compute_cost_usd=compute_cost_usd,
                    )
                else:
                    raise IngestionCancelled("Ingestion job lease was lost")
            final = self.store.get(job.tenant_id, job.id)
            if final is not None and final.status in {
                IngestionJobStatus.SUCCEEDED,
                IngestionJobStatus.CANCELLED,
            }:
                self._remove_input(final)
        except IngestionCancelled as exc:
            processing_seconds, compute_cost_usd = attempt_usage()
            self.store.fail(
                job.id,
                self.owner,
                self._error_code(exc),
                retryable=False,
                retry_delay_seconds=0,
                now=self.clock(),
                processing_seconds=processing_seconds,
                compute_cost_usd=compute_cost_usd,
            )
            current = self.store.get(job.tenant_id, job.id)
            if current is not None and current.status == IngestionJobStatus.CANCELLED:
                self._remove_input(current)
        except SecurityError as exc:
            processing_seconds, compute_cost_usd = attempt_usage()
            failed = self.store.fail(
                job.id,
                self.owner,
                self._error_code(exc),
                retryable=False,
                retry_delay_seconds=0,
                now=self.clock(),
                processing_seconds=processing_seconds,
                compute_cost_usd=compute_cost_usd,
            )
            if failed is not None and failed.status == IngestionJobStatus.CANCELLED:
                self._remove_input(failed)
        except Exception as exc:
            processing_seconds, compute_cost_usd = attempt_usage()
            failed = self.store.fail(
                job.id,
                self.owner,
                self._error_code(exc),
                retryable=True,
                retry_delay_seconds=float(2 ** max(0, job.attempt_count - 1)),
                now=self.clock(),
                processing_seconds=processing_seconds,
                compute_cost_usd=compute_cost_usd,
            )
            if failed is not None and failed.status == IngestionJobStatus.CANCELLED:
                self._remove_input(failed)
        finally:
            if work_root is not None:
                shutil.rmtree(work_root, ignore_errors=True)
        self.drain_lifecycle_events()
        return True

    async def run(
        self,
        stop: asyncio.Event,
        capacity: asyncio.Semaphore | None = None,
    ) -> None:
        await asyncio.to_thread(self.store.recover_expired, now=self.clock())
        await asyncio.to_thread(self.drain_lifecycle_events)
        while not stop.is_set():
            if capacity is not None:
                await capacity.acquire()
            try:
                processed = await asyncio.to_thread(self.process_next)
            finally:
                if capacity is not None:
                    capacity.release()
            if processed:
                continue
            try:
                await asyncio.wait_for(stop.wait(), timeout=WORKER_POLL_SECONDS)
            except TimeoutError:
                continue

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self.drain_lifecycle_events()
            self.store.close()
            if self._owns_object_store:
                self.object_store.close()
            self._closed = True


def create_job_service(
    settings: Settings,
    ingestion: IngestionService,
    object_store: ObjectStore | None = None,
) -> IngestionJobService:
    return IngestionJobService(
        settings,
        ingestion,
        object_store=object_store,
        lifecycle_retention_days=settings.ingestion_lifecycle_retention_days,
    )
