from __future__ import annotations

import asyncio
import inspect
import re
import sqlite3
import sys
import threading
import time
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import crisisweave.jobs as jobs_module
from crisisweave.config import Settings
from crisisweave.ingestion import IngestionCancelled
from crisisweave.job_store import (
    IngestionJobStatus,
    JobQueueFullError,
    PostgresIngestionJobStore,
    SQLiteIngestionJobStore,
    build_ingestion_job_store,
    new_job_record,
)
from crisisweave.jobs import (
    IngestionJobService,
    JobCleanupDurabilityError,
    JobNotFoundError,
    JobStateConflictError,
    create_job_service,
    lifecycle_operation_id,
)
from crisisweave.models import Document, DocumentStatus, IngestionResult
from crisisweave.object_store import LocalObjectStore
from crisisweave.security import SecurityError

TENANT = "a" * 32
OTHER_TENANT = "b" * 32


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 3, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


class FakeMetadata:
    def tenant_usage(self, _tenant_id: str) -> tuple[int, int]:
        return (0, 0)


class FakeIngestion:
    def __init__(self) -> None:
        self.store = FakeMetadata()
        self.failures: list[Exception] = []
        self.calls = 0
        self.deleted: list[tuple[str, str]] = []
        self.before_result: Any = None
        self.deduplicated = False
        self._operation_lock = threading.RLock()

    @contextmanager
    def tenant_operation(self, _tenant_id: str) -> Iterator[None]:
        with self._operation_lock:
            yield

    def delete_all_locked(self, _tenant_id: str) -> int:
        return 0

    def reset_tenant(self, tenant_id: str, cancel_pending: Callable[[], None]) -> int:
        with self.tenant_operation(tenant_id):
            cancel_pending()
            return self.delete_all_locked(tenant_id)

    def ingest_path(
        self,
        path: Path,
        *,
        tenant_id: str,
        filename: str,
        source_uri: str | None,
        progress_callback: Any,
        cancel_requested: Any,
    ) -> IngestionResult:
        self.calls += 1
        assert path.read_bytes()
        assert not cancel_requested()
        progress_callback("extracting", 35)
        if self.failures:
            raise self.failures.pop(0)
        document = Document(
            id="11111111-1111-4111-8111-111111111111",
            tenant_id=tenant_id,
            filename=filename,
            media_type="text/plain",
            sha256="0" * 64,
            size_bytes=path.stat().st_size,
            status=DocumentStatus.READY,
            source_uri=source_uri,
            chunk_count=1,
        )
        progress_callback("ready", 100)
        if self.before_result is not None:
            self.before_result()
        return IngestionResult(document=document, deduplicated=self.deduplicated)

    def delete(self, tenant_id: str, document_id: str) -> bool:
        self.deleted.append((tenant_id, document_id))
        return True


class BlockingFakeIngestion(FakeIngestion):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.reset_tenants: list[str] = []

    def ingest_path(
        self,
        path: Path,
        *,
        tenant_id: str,
        filename: str,
        source_uri: str | None,
        progress_callback: Any,
        cancel_requested: Any,
    ) -> IngestionResult:
        del path, tenant_id, filename, source_uri
        self.calls += 1
        progress_callback("extracting", 35)
        self.started.set()
        deadline = time.monotonic() + 2
        while not cancel_requested():
            if time.monotonic() >= deadline:
                raise TimeoutError("test worker was not cancelled")
            time.sleep(0.005)
        raise IngestionCancelled("reset cancelled the running ingestion")

    def delete_all_locked(self, tenant_id: str) -> int:
        self.reset_tenants.append(tenant_id)
        return 0


class ResetBarrierFakeIngestion(FakeIngestion):
    def __init__(self) -> None:
        super().__init__()
        self.delete_started = threading.Event()
        self.allow_delete = threading.Event()

    def delete_all_locked(self, _tenant_id: str) -> int:
        self.delete_started.set()
        if not self.allow_delete.wait(timeout=2):
            raise TimeoutError("test did not release reset deletion")
        return 0


@pytest.fixture
def job_service(settings: Settings) -> tuple[IngestionJobService, FakeIngestion, Clock]:
    configured = settings.model_copy(update={"ingestion_worker_enabled": False})
    clock = Clock()
    ingestion = FakeIngestion()
    object_store = LocalObjectStore(configured.object_dir, configured.artifact_dir)
    store = SQLiteIngestionJobStore(configured.data_dir / "jobs.sqlite3")
    service = IngestionJobService(  # type: ignore[arg-type]
        configured,
        ingestion,
        store=store,
        object_store=object_store,
        clock=clock,
    )
    yield service, ingestion, clock
    service.close()
    object_store.close()


def _upload(tmp_path: Path, content: bytes = b"durable incident evidence") -> Path:
    path = tmp_path / "incident.txt"
    path.write_bytes(content)
    return path


def test_job_runs_to_success_and_hides_internal_object_reference(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri="https://nasa.gov/incident",
    )
    assert queued.job.status == IngestionJobStatus.QUEUED
    assert service.store.status_counts() == {IngestionJobStatus.QUEUED.value: 1}
    assert not queued.deduplicated
    assert "input_object_ref" not in queued.job.model_dump()
    assert "tenant_id" not in queued.job.model_dump()

    internal = service.store.get(TENANT, queued.job.id)
    assert internal is not None
    local_object = Path(internal.input_object_ref)
    assert local_object.is_file()

    assert service.process_next()
    completed = service.get(TENANT, queued.job.id)
    assert completed.status == IngestionJobStatus.SUCCEEDED
    assert completed.progress == 100
    assert completed.document_id == "11111111-1111-4111-8111-111111111111"
    assert service.store.status_counts() == {IngestionJobStatus.SUCCEEDED.value: 1}
    assert ingestion.calls == 1
    assert not local_object.exists()


def test_unsupported_media_is_rejected_before_job_object_persistence(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    put_calls = 0
    original_put = service.object_store.put_job_input

    def recording_put(*args: Any, **kwargs: Any) -> str:
        nonlocal put_calls
        put_calls += 1
        return original_put(*args, **kwargs)

    monkeypatch.setattr(service.object_store, "put_job_input", recording_put)
    upload = tmp_path / "unsupported.exe"
    upload.write_bytes(b"plain text in an unsupported container")

    with pytest.raises(SecurityError, match="allowed extension"):
        service.enqueue(
            upload,
            tenant_id=TENANT,
            filename="unsupported.exe",
            source_uri=None,
        )

    assert put_calls == 0
    assert not upload.exists()
    assert not list((service.settings.object_dir / "jobs").rglob("*"))


def test_enqueue_rejects_empty_and_declared_extension_mismatch_before_persistence(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, _clock = job_service
    empty = tmp_path / "empty.txt"
    empty.touch()
    with pytest.raises(SecurityError, match="between 1"):
        service.enqueue(empty, tenant_id=TENANT, filename="empty.txt", source_uri=None)
    assert not empty.exists()

    mismatch = tmp_path / "report.txt"
    mismatch.write_bytes(b"valid text, wrong declared suffix")
    with pytest.raises(SecurityError, match="declared filename"):
        service.enqueue(mismatch, tenant_id=TENANT, filename="report.csv", source_uri=None)
    assert not mismatch.exists()


def test_enqueue_preserves_queue_error_when_object_cleanup_fails(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    service.settings = service.settings.model_copy(update={"max_documents_per_tenant": 0})

    def fail_cleanup(_reference: str) -> None:
        raise OSError("object store unavailable")

    monkeypatch.setattr(service.object_store, "delete", fail_cleanup)
    with pytest.raises(JobQueueFullError, match="quota exceeded"):
        service.enqueue(
            _upload(tmp_path),
            tenant_id=TENANT,
            filename="incident.txt",
            source_uri=None,
        )


def test_duplicate_enqueue_survives_duplicate_object_cleanup_failure(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    first = service.enqueue(
        _upload(tmp_path, b"duplicate cleanup"),
        tenant_id=TENANT,
        filename="first.txt",
        source_uri=None,
    )

    def fail_cleanup(_reference: str) -> None:
        raise OSError("object store unavailable")

    monkeypatch.setattr(service.object_store, "delete", fail_cleanup)
    duplicate_path = tmp_path / "duplicate.txt"
    duplicate_path.write_bytes(b"duplicate cleanup")
    duplicate = service.enqueue(
        duplicate_path,
        tenant_id=TENANT,
        filename="duplicate.txt",
        source_uri=None,
    )
    assert duplicate.deduplicated
    assert duplicate.job.id == first.job.id


def test_active_duplicate_is_idempotent_and_tenant_scoped(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, _clock = job_service
    first = service.enqueue(
        _upload(tmp_path, b"same"),
        tenant_id=TENANT,
        filename="first.txt",
        source_uri=None,
    )
    second_path = tmp_path / "second.txt"
    second_path.write_bytes(b"same")
    second = service.enqueue(
        second_path,
        tenant_id=TENANT,
        filename="second.txt",
        source_uri=None,
    )
    assert second.deduplicated
    assert second.job.id == first.job.id
    with pytest.raises(JobNotFoundError):
        service.get(OTHER_TENANT, first.job.id)


def test_queued_cancel_is_terminal_and_removes_input(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    internal = service.store.get(TENANT, queued.job.id)
    assert internal is not None
    local_object = Path(internal.input_object_ref)

    cancelled = service.cancel(TENANT, queued.job.id)
    assert cancelled.status == IngestionJobStatus.CANCELLED
    assert not local_object.exists()
    assert not service.process_next()
    assert ingestion.calls == 0


def test_running_cancel_is_cooperative_and_retains_input_until_worker_stops(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
) -> None:
    service, _ingestion, clock = job_service
    upload = service.work_dir.parent / "running.txt"
    upload.write_bytes(b"running cancellation")
    queued = service.enqueue(
        upload,
        tenant_id=TENANT,
        filename="running.txt",
        source_uri=None,
    )
    claimed = service.store.claim("external-worker", now=clock(), lease_seconds=30)
    assert claimed is not None
    local_object = Path(claimed.input_object_ref)

    cancelled = service.cancel(TENANT, queued.job.id)
    assert cancelled.status == IngestionJobStatus.CANCELLING
    assert local_object.exists()


def test_job_service_reports_missing_and_conflicting_retry_delete_states(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, _clock = job_service
    with pytest.raises(JobNotFoundError):
        service.cancel(TENANT, "11111111-1111-4111-8111-000000000000")
    with pytest.raises(JobNotFoundError):
        service.retry(TENANT, "11111111-1111-4111-8111-000000000000")
    with pytest.raises(JobNotFoundError):
        service.delete(TENANT, "11111111-1111-4111-8111-000000000000")

    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    with pytest.raises(JobStateConflictError, match="dead-letter"):
        service.retry(TENANT, queued.job.id)
    with pytest.raises(JobStateConflictError, match="Cancel the active"):
        service.delete(TENANT, queued.job.id)


def test_dead_letter_retry_rejects_missing_input_and_store_race(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, _clock = job_service
    ingestion.failures = [SecurityError("permanent failure"), SecurityError("permanent failure")]

    missing_input = service.enqueue(
        _upload(tmp_path, b"missing dead letter input"),
        tenant_id=TENANT,
        filename="missing.txt",
        source_uri=None,
    )
    assert service.process_next()
    missing_record = service.store.get(TENANT, missing_input.job.id)
    assert missing_record is not None
    service.object_store.delete(missing_record.input_object_ref)
    with pytest.raises(JobStateConflictError, match="unavailable or changed"):
        service.retry(TENANT, missing_input.job.id)

    race_path = tmp_path / "race.txt"
    race_path.write_bytes(b"retry state race")
    raced = service.enqueue(
        race_path,
        tenant_id=TENANT,
        filename="race.txt",
        source_uri=None,
    )
    assert service.process_next()
    monkeypatch.setattr(service.store, "retry", lambda *_args, **_kwargs: None)
    with pytest.raises(JobStateConflictError, match="state changed"):
        service.retry(TENANT, raced.job.id)


def test_cancel_all_validates_timeout_and_reports_drain_timeout(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ingestion, _clock = job_service
    with pytest.raises(ValueError, match="positive"):
        service.cancel_all(TENANT, timeout_seconds=0)

    ticks = iter((10.0, 12.0))
    monkeypatch.setattr(jobs_module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(service.store, "request_cancel_all", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(service.store, "recover_expired", lambda **_kwargs: 0)
    monkeypatch.setattr(service.store, "active_count", lambda _tenant_id: 1)
    with pytest.raises(JobStateConflictError, match="Timed out"):
        service.cancel_all(TENANT, timeout_seconds=1)


def test_reset_final_sweep_cancels_job_that_entered_after_initial_drain(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    monkeypatch.setattr(service, "cancel_all", lambda *_args, **_kwargs: 0)

    assert service.reset(TENANT, timeout_seconds=1) == 0
    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.CANCELLED


def test_materialization_size_mismatch_dead_letters_and_cleans_work_directory(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"expected durable bytes"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )

    def truncated_materialize(
        _reference: str,
        target: Path,
        *,
        max_bytes: int,
        expected_sha256: str,
    ) -> None:
        del max_bytes, expected_sha256
        target.write_bytes(b"x")

    monkeypatch.setattr(service.object_store, "materialize", truncated_materialize)
    assert service.process_next()
    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.DEAD_LETTER
    assert ingestion.calls == 0
    assert not (service.work_dir / queued.job.id).exists()


def test_object_cleanup_failure_is_non_fatal(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None

    def fail_cleanup(_reference: str) -> None:
        raise OSError("object store unavailable")

    monkeypatch.setattr(service.object_store, "delete", fail_cleanup)
    service._remove_input(record)  # noqa: SLF001 - exercises durable cleanup tolerance


def test_cancelled_security_error_race_cleans_durable_input(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"security cancellation race"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None

    def reject_after_cancel(*_args: Any, **_kwargs: Any) -> IngestionResult:
        cancelled = service.store.request_cancel(TENANT, queued.job.id, now=clock())
        assert cancelled is not None
        assert cancelled.status == IngestionJobStatus.CANCELLING
        raise SecurityError("hostile input")

    monkeypatch.setattr(ingestion, "ingest_path", reject_after_cancel)
    assert service.process_next()

    final = service.store.get(TENANT, queued.job.id)
    assert final is not None
    assert final.status == IngestionJobStatus.CANCELLED
    assert not final.input_cleanup_pending
    assert not Path(record.input_object_ref).exists()


def test_failed_terminal_cleanup_is_durable_and_reconciled(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"durable cleanup retry"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None
    original_delete = service.object_store.delete
    monkeypatch.setattr(
        service.object_store,
        "delete",
        lambda _reference: (_ for _ in ()).throw(OSError("storage unavailable")),
    )

    assert service.cancel(TENANT, queued.job.id).status == IngestionJobStatus.CANCELLED
    pending = service.store.get(TENANT, queued.job.id)
    assert pending is not None and pending.input_cleanup_pending
    assert Path(record.input_object_ref).is_file()

    monkeypatch.setattr(service.object_store, "delete", original_delete)
    original_complete = service.store.complete_input_cleanup
    monkeypatch.setattr(
        service.store,
        "complete_input_cleanup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("database unavailable")),
    )
    assert service.reconcile_input_cleanup() == 0
    still_pending = service.store.get(TENANT, queued.job.id)
    assert still_pending is not None and still_pending.input_cleanup_pending
    assert not Path(record.input_object_ref).exists()

    monkeypatch.setattr(service.store, "complete_input_cleanup", original_complete)
    assert service.reconcile_input_cleanup() == 1
    cleaned = service.store.get(TENANT, queued.job.id)
    assert cleaned is not None and not cleaned.input_cleanup_pending
    assert not Path(record.input_object_ref).exists()


def test_terminal_delete_keeps_reference_until_exact_object_delete_succeeds(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, _clock = job_service
    ingestion.failures = [SecurityError("retain dead-letter input")]
    queued = service.enqueue(
        _upload(tmp_path, b"terminal deletion ordering"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    assert service.process_next()
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None and record.status == IngestionJobStatus.DEAD_LETTER
    original_delete = service.object_store.delete

    def unavailable(reference: str) -> None:
        current = service.store.get(TENANT, queued.job.id)
        assert current is not None
        assert current.input_object_ref == reference
        raise OSError("storage unavailable")

    monkeypatch.setattr(service.object_store, "delete", unavailable)
    with pytest.raises(JobStateConflictError, match="durably pending"):
        service.delete(TENANT, queued.job.id)
    pending = service.store.get(TENANT, queued.job.id)
    assert pending is not None
    assert pending.delete_requested and pending.input_cleanup_pending
    assert service.store.delete_terminal(TENANT, queued.job.id) is None

    monkeypatch.setattr(service.object_store, "delete", original_delete)
    assert service.reconcile_input_cleanup() == 1
    assert service.store.get(TENANT, queued.job.id) is None
    assert not Path(record.input_object_ref).exists()


def test_expired_cancelling_job_is_recovered_and_input_is_reconciled(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"expired cancellation"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None
    claimed = service.store.claim("crashed-worker", now=clock(), lease_seconds=1)
    assert claimed is not None
    cancelling = service.store.request_cancel(TENANT, queued.job.id, now=clock())
    assert cancelling is not None and cancelling.status == IngestionJobStatus.CANCELLING
    clock.advance(2)

    assert service.store.recover_expired(now=clock()) == 1
    recovered = service.store.get(TENANT, queued.job.id)
    assert recovered is not None
    assert recovered.status == IngestionJobStatus.CANCELLED
    assert recovered.input_cleanup_pending
    assert service.reconcile_input_cleanup() == 1
    assert not Path(record.input_object_ref).exists()


def test_failed_enqueue_uses_orphan_outbox_and_surfaces_unreconcilable_failure(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    service.settings = service.settings.model_copy(update={"max_documents_per_tenant": 0})
    original_delete = service.object_store.delete
    monkeypatch.setattr(
        service.object_store,
        "delete",
        lambda _reference: (_ for _ in ()).throw(OSError("storage unavailable")),
    )
    with pytest.raises(JobQueueFullError):
        service.enqueue(
            _upload(tmp_path, b"orphan outbox"),
            tenant_id=TENANT,
            filename="incident.txt",
            source_uri=None,
        )
    candidates = service.store.orphan_cleanup_candidates(limit=10)
    assert len(candidates) == 1

    monkeypatch.setattr(service.object_store, "delete", original_delete)
    assert service.reconcile_input_cleanup() == 1
    assert service.store.orphan_cleanup_candidates(limit=10) == []

    monkeypatch.setattr(
        service.store,
        "schedule_orphan_cleanup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("database unavailable")),
    )
    monkeypatch.setattr(
        service.object_store,
        "delete",
        lambda _reference: (_ for _ in ()).throw(OSError("storage unavailable")),
    )
    with pytest.raises(JobCleanupDurabilityError, match="cleanup could not be made durable"):
        service.enqueue(
            _upload(tmp_path, b"unreconcilable orphan"),
            tenant_id=TENANT,
            filename="incident.txt",
            source_uri=None,
        )


def test_enqueue_ack_ambiguity_reuses_committed_job_without_deleting_its_input(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    original_enqueue = service.store.enqueue

    def commit_then_disconnect(*args: Any, **kwargs: Any) -> Any:
        original_enqueue(*args, **kwargs)
        raise ConnectionError("acknowledgement lost")

    monkeypatch.setattr(service.store, "enqueue", commit_then_disconnect)
    queued = service.enqueue(
        _upload(tmp_path, b"committed despite lost acknowledgement"),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    record = service.store.get(TENANT, queued.job.id)
    assert record is not None
    assert Path(record.input_object_ref).is_file()
    assert service.store.orphan_cleanup_candidates(limit=10) == []


def test_enqueue_unknown_outcome_retains_input_and_construction_failure_cleans_it(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    monkeypatch.setattr(
        service.store,
        "enqueue",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionError("write uncertain")),
    )
    monkeypatch.setattr(
        service.store,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionError("read unavailable")),
    )
    with pytest.raises(JobCleanupDurabilityError, match="outcome is unknown"):
        service.enqueue(
            _upload(tmp_path, b"unknown queue outcome"),
            tenant_id=TENANT,
            filename="incident.txt",
            source_uri=None,
        )
    retained = [path for path in service.settings.object_dir.rglob("*") if path.is_file()]
    assert len(retained) == 1

    with monkeypatch.context() as patch:
        patch.setattr(
            jobs_module,
            "new_job_record",
            lambda **_kwargs: (_ for _ in ()).throw(ValueError("invalid durable record")),
        )
        construction_upload = tmp_path / "construction.txt"
        construction_upload.write_bytes(b"construction failure cleanup")
        with pytest.raises(ValueError, match="invalid durable record"):
            service.enqueue(
                construction_upload,
                tenant_id=TENANT,
                filename="construction.txt",
                source_uri=None,
            )
    remaining = [path for path in service.settings.object_dir.rglob("*") if path.is_file()]
    assert remaining == retained


def test_transient_failure_retries_then_dead_letters_and_can_be_requeued(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, ingestion, clock = job_service
    ingestion.failures = [RuntimeError("provider down") for _ in range(3)]
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )

    assert service.process_next()
    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.RETRY_WAIT
    assert not service.process_next()
    clock.advance(2)
    assert service.process_next()
    clock.advance(3)
    assert service.process_next()

    dead = service.get(TENANT, queued.job.id)
    assert dead.status == IngestionJobStatus.DEAD_LETTER
    assert dead.attempt_count == 3
    assert dead.error_code == "INGESTION_RUNTIMEERROR"

    retried = service.retry(TENANT, queued.job.id)
    assert retried.status == IngestionJobStatus.QUEUED
    assert retried.attempt_count == 0
    assert service.process_next()
    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.SUCCEEDED


def test_sqlite_lifecycle_outbox_accumulates_attempts_and_retries_at_least_once(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = SQLiteIngestionJobStore(tmp_path / "lifecycle.sqlite3")
    try:
        job_id = "33333333-3333-4333-8333-333333333333"
        record = new_job_record(
            job_id=job_id,
            tenant_id=TENANT,
            filename="incident.txt",
            source_uri=None,
            input_object_ref="object-version",
            sha256="3" * 64,
            size_bytes=10,
            max_attempts=2,
            compute_cost_per_hour_usd=36.0,
            now=clock(),
        )
        store.enqueue(record, max_retained_jobs=10, max_retained_bytes=100)

        first = store.claim("worker", now=clock(), lease_seconds=30)
        assert first is not None
        retrying = store.fail(
            job_id,
            "worker",
            "TRANSIENT",
            retryable=True,
            retry_delay_seconds=0,
            now=clock(),
            processing_seconds=2.0,
            compute_cost_usd=0.02,
        )
        assert retrying is not None and retrying.status == IngestionJobStatus.RETRY_WAIT
        assert (
            store.claim_lifecycle_events("telemetry-a", now=clock(), lease_seconds=30, limit=10)
            == []
        )

        second = store.claim("worker", now=clock(), lease_seconds=30)
        assert second is not None
        terminal = store.fail(
            job_id,
            "worker",
            "PERMANENT",
            retryable=True,
            retry_delay_seconds=0,
            now=clock(),
            processing_seconds=3.0,
            compute_cost_usd=0.03,
        )
        assert terminal is not None and terminal.status == IngestionJobStatus.DEAD_LETTER
        assert terminal.processing_seconds == pytest.approx(5.0)
        assert terminal.compute_cost_usd == pytest.approx(0.05)

        first_delivery = store.claim_lifecycle_events(
            "telemetry-a", now=clock(), lease_seconds=30, limit=10
        )
        assert len(first_delivery) == 1
        event = first_delivery[0]
        assert event.status == IngestionJobStatus.DEAD_LETTER
        assert event.processing_seconds == pytest.approx(5.0)
        assert event.compute_cost_usd == pytest.approx(0.05)
        assert event.delivery_attempts == 1
        operation_id = lifecycle_operation_id(event.event_id)
        assert re.fullmatch(r"[a-f0-9]{32}", operation_id)
        assert job_id.replace("-", "") not in operation_id

        assert (
            store.claim_lifecycle_events("telemetry-b", now=clock(), lease_seconds=30, limit=10)
            == []
        )
        clock.advance(31)
        redelivery = store.claim_lifecycle_events(
            "telemetry-b", now=clock(), lease_seconds=30, limit=10
        )
        assert [item.event_id for item in redelivery] == [event.event_id]
        assert redelivery[0].delivery_attempts == 2
        assert not store.complete_lifecycle_event(event.event_id, "telemetry-a", now=clock())
        assert store.complete_lifecycle_event(event.event_id, "telemetry-b", now=clock())

        retried = store.retry(
            TENANT,
            job_id,
            now=clock(),
            compute_cost_per_hour_usd=72.0,
        )
        assert retried is not None
        assert retried.lifecycle_generation == 2
        assert retried.lifecycle_started_at == clock()
        assert retried.processing_seconds == 0
        assert retried.compute_cost_usd == 0
        assert retried.compute_cost_per_hour_usd == 72.0
    finally:
        store.close()


def test_sqlite_immediate_cancel_and_expired_lease_create_terminal_events(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = SQLiteIngestionJobStore(tmp_path / "terminal-paths.sqlite3")
    try:
        queued = new_job_record(
            job_id="44444444-4444-4444-8444-444444444444",
            tenant_id=TENANT,
            filename="queued.txt",
            source_uri=None,
            input_object_ref="queued-object",
            sha256="4" * 64,
            size_bytes=1,
            max_attempts=1,
            now=clock(),
        )
        store.enqueue(queued, max_retained_jobs=10, max_retained_bytes=100)
        cancelled = store.request_cancel(TENANT, queued.id, now=clock())
        assert cancelled is not None and cancelled.status == IngestionJobStatus.CANCELLED

        crashed = new_job_record(
            job_id="55555555-5555-4555-8555-555555555555",
            tenant_id=OTHER_TENANT,
            filename="crashed.txt",
            source_uri=None,
            input_object_ref="crashed-object",
            sha256="5" * 64,
            size_bytes=1,
            max_attempts=1,
            compute_cost_per_hour_usd=3600.0,
            now=clock(),
        )
        store.enqueue(crashed, max_retained_jobs=10, max_retained_bytes=100)
        assert store.claim("crashed-worker", now=clock(), lease_seconds=10) is not None
        clock.advance(11)
        assert store.recover_expired(now=clock()) == 1
        recovered = store.get(OTHER_TENANT, crashed.id)
        assert recovered is not None and recovered.status == IngestionJobStatus.DEAD_LETTER
        assert recovered.processing_seconds == pytest.approx(10.0)
        assert recovered.compute_cost_usd == pytest.approx(10.0)

        events = store.claim_lifecycle_events("telemetry", now=clock(), lease_seconds=30, limit=10)
        assert {event.status for event in events} == {
            IngestionJobStatus.CANCELLED,
            IngestionJobStatus.DEAD_LETTER,
        }
        estimated = next(
            event for event in events if event.status == IngestionJobStatus.DEAD_LETTER
        )
        measured = next(event for event in events if event.status == IngestionJobStatus.CANCELLED)
        assert estimated.usage_estimated
        assert not measured.usage_estimated
    finally:
        store.close()


def test_sqlite_upgrade_backfills_terminal_lifecycle_outbox(tmp_path: Path) -> None:
    database = tmp_path / "legacy-jobs.sqlite3"
    timestamp = datetime(2026, 8, 1, tzinfo=UTC).isoformat()
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE ingestion_jobs (
                id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, filename TEXT NOT NULL,
                source_uri TEXT, input_object_ref TEXT NOT NULL, sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL,
                stage TEXT NOT NULL, attempt_count INTEGER NOT NULL, max_attempts INTEGER NOT NULL,
                available_at TEXT NOT NULL, lease_owner TEXT, lease_expires_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0, document_id TEXT, error_code TEXT,
                input_cleanup_pending INTEGER NOT NULL DEFAULT 0,
                delete_requested INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """INSERT INTO ingestion_jobs VALUES (
                ?, ?, ?, NULL, ?, ?, 1, 'cancelled', 0, 'cancelled', 0, 3,
                ?, NULL, NULL, 1, NULL, NULL, 1, 0, ?, ?
            )""",
            [
                "77777777-7777-4777-8777-777777777777",
                TENANT,
                "legacy.txt",
                "legacy-object",
                "7" * 64,
                timestamp,
                timestamp,
                timestamp,
            ],
        )
        connection.commit()
    finally:
        connection.close()

    store = SQLiteIngestionJobStore(database)
    try:
        events = store.claim_lifecycle_events(
            "telemetry", now=datetime(2026, 8, 3, tzinfo=UTC), lease_seconds=30, limit=10
        )
        assert len(events) == 1
        assert events[0].status == IngestionJobStatus.CANCELLED
        assert events[0].lifecycle_generation == 1
        assert events[0].lifecycle_started_at.isoformat() == timestamp
        assert events[0].usage_estimated
    finally:
        store.close()


def test_service_drains_terminal_outbox_once_without_tenant_labels(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"durable telemetry"),
        tenant_id=TENANT,
        filename="telemetry.txt",
        source_uri=None,
    )
    terminal = service.store.request_cancel(TENANT, queued.job.id, now=clock())
    assert terminal is not None and terminal.status == IngestionJobStatus.CANCELLED
    samples: list[tuple[str, float]] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_job_completion",
        lambda status, duration: samples.append((status, duration)),
    )
    spans: list[dict[str, object]] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_span",
        lambda operation_id, status, **kwargs: spans.append(
            {"operation_id": operation_id, "status": status, **kwargs}
        ),
    )

    assert service.drain_lifecycle_events() == 1
    assert samples == [(IngestionJobStatus.CANCELLED.value, 0.0)]
    assert len(spans) == 1
    assert spans[0]["lifecycle_started_at"] == terminal.lifecycle_started_at
    assert spans[0]["terminal_at"] == clock()
    assert spans[0]["measurement_quality"] == "measured"
    assert service.drain_lifecycle_events() == 0


@pytest.mark.parametrize(
    ("clock_delta_seconds", "reason"),
    [(-1.0, "clock_skew"), (31 * 24 * 60 * 60, "older_than_30_days")],
)
def test_invalid_lifecycle_duration_is_excluded_and_acknowledged(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clock_delta_seconds: float,
    reason: str,
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, reason.encode()),
        tenant_id=TENANT,
        filename="invalid-duration.txt",
        source_uri=None,
    )
    clock.advance(clock_delta_seconds)
    assert service.store.request_cancel(TENANT, queued.job.id, now=clock()) is not None
    exclusions: list[str] = []
    valid_samples: list[float] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_exclusion",
        exclusions.append,
    )
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_job_completion",
        lambda _status, duration: valid_samples.append(duration),
    )
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_span",
        lambda *_args, **_kwargs: pytest.fail("excluded event emitted a valid span"),
    )

    assert service.drain_lifecycle_events() == 1
    assert exclusions == [reason]
    assert valid_samples == []
    assert service.drain_lifecycle_events() == 0


def test_recovered_lifecycle_logs_and_traces_estimated_cost_marker(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"estimated recovery"),
        tenant_id=TENANT,
        filename="estimated.txt",
        source_uri=None,
    )
    assert service.store.claim("crashed-worker", now=clock(), lease_seconds=1) is not None
    cancelling = service.store.request_cancel(TENANT, queued.job.id, now=clock())
    assert cancelling is not None and cancelling.status == IngestionJobStatus.CANCELLING
    clock.advance(2)
    assert service.store.recover_expired(now=clock()) == 1

    logs: list[tuple[str, dict[str, object]]] = []

    class CapturingLogger:
        def info(self, event: str, **values: object) -> None:
            logs.append((event, values))

        def warning(self, event: str, **values: object) -> None:
            logs.append((event, values))

    spans: list[dict[str, object]] = []
    monkeypatch.setattr(jobs_module, "logger", CapturingLogger())
    monkeypatch.setattr(jobs_module, "record_ingestion_job_completion", lambda *_args: None)
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_span",
        lambda _operation_id, _status, **kwargs: spans.append(kwargs),
    )

    assert service.drain_lifecycle_events() == 1
    terminal_log = next(values for event, values in logs if event == "ingestion_lifecycle_terminal")
    assert terminal_log["measurement_quality"] == "estimated"
    assert spans[0]["measurement_quality"] == "estimated"


def test_sqlite_prunes_only_old_acknowledged_lifecycle_events(tmp_path: Path) -> None:
    clock = Clock()
    store = SQLiteIngestionJobStore(tmp_path / "lifecycle-retention.sqlite3")
    try:
        for index in (1, 2):
            record = new_job_record(
                job_id=f"99999999-9999-4999-8999-99999999999{index}",
                tenant_id=TENANT,
                filename=f"{index}.txt",
                source_uri=None,
                input_object_ref=f"object-{index}",
                sha256=str(index) * 64,
                size_bytes=1,
                max_attempts=1,
                now=clock(),
            )
            store.enqueue(record, max_retained_jobs=10, max_retained_bytes=100)
            assert store.request_cancel(TENANT, record.id, now=clock()) is not None
        assert store.lifecycle_outbox_stats(now=clock()) == (2, 0.0)
        first = store.claim_lifecycle_events("telemetry", now=clock(), lease_seconds=30, limit=1)
        assert len(first) == 1
        assert store.complete_lifecycle_event(first[0].event_id, "telemetry", now=clock())

        future = clock() + timedelta(days=15)
        assert store.prune_delivered_lifecycle_events(before=future, limit=500) == 1
        pending = store.claim_lifecycle_events("telemetry", now=future, lease_seconds=30, limit=10)
        assert len(pending) == 1
        assert pending[0].event_id != first[0].event_id
        assert store.lifecycle_outbox_stats(now=future) == (
            1,
            15 * 24 * 60 * 60,
        )
    finally:
        store.close()


def test_production_api_cannot_claim_or_prune_global_lifecycle_outbox(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    configured = settings.model_copy(update={"app_env": "production", "runtime_role": "api"})
    store = SQLiteIngestionJobStore(tmp_path / "api-role.sqlite3")
    object_store = LocalObjectStore(configured.object_dir, configured.artifact_dir)
    calls: list[str] = []
    monkeypatch.setattr(
        store,
        "claim_lifecycle_events",
        lambda *_args, **_kwargs: calls.append("claim") or [],
    )
    monkeypatch.setattr(
        store,
        "prune_delivered_lifecycle_events",
        lambda **_kwargs: calls.append("prune") or 0,
    )
    monkeypatch.setattr(
        store,
        "lifecycle_outbox_stats",
        lambda **_kwargs: calls.append("stats") or (0, 0.0),
    )
    service = IngestionJobService(  # type: ignore[arg-type]
        configured,
        FakeIngestion(),
        store=store,
        object_store=object_store,
    )
    try:
        assert service.drain_lifecycle_events() == 0
        assert service._prune_delivered_lifecycle_events() == 0  # noqa: SLF001
        service._refresh_lifecycle_outbox_metrics()  # noqa: SLF001
        assert calls == []
    finally:
        service.close()
        object_store.close()


def test_worker_refreshes_content_free_lifecycle_outbox_gauges(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"gauge backlog"),
        tenant_id=TENANT,
        filename="gauge.txt",
        source_uri=None,
    )
    clock.advance(12)
    assert service.store.request_cancel(TENANT, queued.job.id, now=clock()) is not None
    clock.advance(12)
    samples: list[tuple[int, float]] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_outbox_state",
        lambda count, age: samples.append((count, age)),
    )

    service._refresh_lifecycle_outbox_metrics()  # noqa: SLF001
    assert samples == [(1, 12.0)]


def test_lifecycle_claim_ack_and_prune_failures_use_bounded_stages(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    stages: list[str] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_delivery_failure",
        stages.append,
    )

    monkeypatch.setattr(
        service.store,
        "claim_lifecycle_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("claim failed")),
    )
    assert service.drain_lifecycle_events() == 0
    assert stages == ["claim"]

    monkeypatch.undo()
    stages.clear()
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_delivery_failure",
        stages.append,
    )
    queued = service.enqueue(
        _upload(tmp_path, b"ack failure"),
        tenant_id=TENANT,
        filename="ack.txt",
        source_uri=None,
    )
    assert service.store.request_cancel(TENANT, queued.job.id, now=clock()) is not None
    monkeypatch.setattr(jobs_module, "record_ingestion_job_completion", lambda *_args: None)
    monkeypatch.setattr(jobs_module, "record_ingestion_lifecycle_span", lambda *_a, **_k: None)
    monkeypatch.setattr(
        service.store,
        "complete_lifecycle_event",
        lambda *_args, **_kwargs: False,
    )
    assert service.drain_lifecycle_events() == 0
    assert stages == ["ack"]

    stages.clear()
    service._next_lifecycle_prune = 0.0  # noqa: SLF001
    monkeypatch.setattr(
        service.store,
        "prune_delivered_lifecycle_events",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("prune failed")),
    )
    assert service._prune_delivered_lifecycle_events() == 0  # noqa: SLF001
    assert stages == ["prune"]


def test_lifecycle_emitter_failure_is_non_fatal_and_redelivered(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path, b"telemetry redelivery"),
        tenant_id=TENANT,
        filename="redelivery.txt",
        source_uri=None,
    )
    assert service.store.request_cancel(TENANT, queued.job.id, now=clock()) is not None
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_job_completion",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("metrics unavailable")),
    )
    stages: list[str] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_lifecycle_delivery_failure",
        stages.append,
    )
    assert service.drain_lifecycle_events() == 0
    assert stages == ["emit"]
    assert service.store.get(TENANT, queued.job.id) is not None

    clock.advance(31)
    samples: list[str] = []
    monkeypatch.setattr(
        jobs_module,
        "record_ingestion_job_completion",
        lambda status, _duration: samples.append(status),
    )
    assert service.drain_lifecycle_events() == 1
    assert samples == [IngestionJobStatus.CANCELLED.value]


@pytest.mark.parametrize(
    ("document_limit", "byte_limit", "first_content", "second_content"),
    [
        (1, 1_000, b"retained row", b"another row"),
        (10, 15, b"0123456789", b"abcdef"),
    ],
    ids=("rows", "bytes"),
)
def test_dead_letter_inputs_count_toward_enqueue_quota(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    tmp_path: Path,
    document_limit: int,
    byte_limit: int,
    first_content: bytes,
    second_content: bytes,
) -> None:
    service, ingestion, _clock = job_service
    service.settings = service.settings.model_copy(
        update={
            "max_documents_per_tenant": document_limit,
            "max_storage_bytes_per_tenant": byte_limit,
        }
    )
    ingestion.failures = [SecurityError("permanent parse rejection")]
    first = service.enqueue(
        _upload(tmp_path, first_content),
        tenant_id=TENANT,
        filename="first.txt",
        source_uri=None,
    )
    assert service.process_next()
    assert service.get(TENANT, first.job.id).status == IngestionJobStatus.DEAD_LETTER

    second = tmp_path / "second.txt"
    second.write_bytes(second_content)
    with pytest.raises(JobQueueFullError, match="quota exceeded"):
        service.enqueue(
            second,
            tenant_id=TENANT,
            filename="second.txt",
            source_uri=None,
        )

    assert not second.exists()
    retained_files = [
        item for item in (service.settings.object_dir / "jobs").rglob("*") if item.is_file()
    ]
    assert len(retained_files) == 1


def test_cancellation_race_does_not_delete_preexisting_deduplicated_document(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    ingestion.deduplicated = True
    ingestion.before_result = lambda: service.store.request_cancel(
        TENANT,
        queued.job.id,
        now=clock(),
    )

    assert service.process_next()

    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.CANCELLED
    assert ingestion.deleted == []


def test_cancellation_race_deletes_newly_published_document(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    ingestion.before_result = lambda: service.store.request_cancel(
        TENANT,
        queued.job.id,
        now=clock(),
    )

    assert service.process_next()

    assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.CANCELLED
    assert ingestion.deleted == [(TENANT, "11111111-1111-4111-8111-111111111111")]


def test_worker_handles_pre_ingest_cancellation_and_heartbeat_lease_loss(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, _clock = job_service
    cancelled = service.enqueue(
        _upload(tmp_path, b"cancel before ingest"),
        tenant_id=TENANT,
        filename="cancelled.txt",
        source_uri=None,
    )
    with monkeypatch.context() as patch:
        patch.setattr(service.store, "cancellation_requested", lambda *_args: True)
        assert service.process_next()
    assert ingestion.calls == 0
    assert service.get(TENANT, cancelled.job.id).status == IngestionJobStatus.DEAD_LETTER

    lost_path = tmp_path / "lost.txt"
    lost_path.write_bytes(b"heartbeat lease loss")
    lost = service.enqueue(
        lost_path,
        tenant_id=TENANT,
        filename="lost.txt",
        source_uri=None,
    )
    with monkeypatch.context() as patch:
        patch.setattr(service.store, "heartbeat", lambda *_args, **_kwargs: False)
        assert service.process_next()
    assert ingestion.calls == 1
    assert service.get(TENANT, lost.job.id).status == IngestionJobStatus.DEAD_LETTER


def test_worker_handles_lost_final_lease_and_cancelled_generic_failure(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, ingestion, _clock = job_service
    lost = service.enqueue(
        _upload(tmp_path, b"lost final lease"),
        tenant_id=TENANT,
        filename="lost.txt",
        source_uri=None,
    )
    with monkeypatch.context() as patch:
        patch.setattr(service.store, "succeed", lambda *_args, **_kwargs: False)
        patch.setattr(service.store, "get", lambda *_args, **_kwargs: None)
        assert service.process_next()
    assert lost.job.id

    failed_path = tmp_path / "failed.txt"
    failed_path.write_bytes(b"cancelled generic failure")
    failed = service.enqueue(
        failed_path,
        tenant_id=TENANT,
        filename="failed.txt",
        source_uri=None,
    )
    failed_record = service.store.get(TENANT, failed.job.id)
    assert failed_record is not None
    ingestion.failures = [RuntimeError("provider unavailable")]
    cancelled_record = failed_record.model_copy(
        update={
            "status": IngestionJobStatus.CANCELLED,
            "stage": "cancelled",
            "input_cleanup_pending": True,
        }
    )
    with monkeypatch.context() as patch:
        patch.setattr(service.store, "fail", lambda *_args, **_kwargs: cancelled_record)
        assert service.process_next()
    assert not Path(failed_record.input_object_ref).exists()


def test_expired_lease_is_resumed_or_dead_lettered(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    claimed = service.store.claim("crashed-worker", now=clock(), lease_seconds=1)
    assert claimed is not None
    clock.advance(2)
    assert service.store.recover_expired(now=clock()) == 1
    recovered = service.get(TENANT, queued.job.id)
    assert recovered.status == IngestionJobStatus.RETRY_WAIT
    assert recovered.error_code == "WORKER_LEASE_EXPIRED"


def test_claimers_do_not_lease_two_same_tenant_jobs_concurrently(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    settings: Settings,
    tmp_path: Path,
) -> None:
    service, _ingestion, clock = job_service
    first_job = service.enqueue(
        _upload(tmp_path, b"tenant job one"),
        tenant_id=TENANT,
        filename="one.txt",
        source_uri=None,
    )
    clock.advance(1)
    second_path = tmp_path / "two.txt"
    second_path.write_bytes(b"tenant job two")
    second_job = service.enqueue(
        second_path,
        tenant_id=TENANT,
        filename="two.txt",
        source_uri=None,
    )
    clock.advance(1)
    other_path = tmp_path / "other.txt"
    other_path.write_bytes(b"other tenant job")
    other_job = service.enqueue(
        other_path,
        tenant_id=OTHER_TENANT,
        filename="other.txt",
        source_uri=None,
    )

    replica = SQLiteIngestionJobStore(settings.data_dir / "jobs.sqlite3")
    try:
        first_claim = service.store.claim("worker-one", now=clock(), lease_seconds=30)
        second_claim = replica.claim("worker-two", now=clock(), lease_seconds=30)

        assert first_claim is not None
        assert first_claim.id == first_job.job.id
        assert second_claim is not None
        assert second_claim.id == other_job.job.id
        assert replica.claim("worker-three", now=clock(), lease_seconds=30) is None

        assert service.store.succeed(
            first_claim.id,
            "worker-one",
            "11111111-1111-4111-8111-111111111111",
            now=clock(),
        )
        next_same_tenant = replica.claim("worker-three", now=clock(), lease_seconds=30)
        assert next_same_tenant is not None
        assert next_same_tenant.id == second_job.job.id
    finally:
        replica.close()


def test_reset_and_enqueue_are_linearized_by_one_tenant_operation_guard(
    settings: Settings, tmp_path: Path
) -> None:
    configured = settings.model_copy(update={"ingestion_worker_enabled": False})
    clock = Clock()
    ingestion = ResetBarrierFakeIngestion()
    object_store = LocalObjectStore(configured.object_dir, configured.artifact_dir)
    service = IngestionJobService(  # type: ignore[arg-type]
        configured,
        ingestion,
        store=SQLiteIngestionJobStore(configured.data_dir / "linearizable-reset.sqlite3"),
        object_store=object_store,
        clock=clock,
    )
    reset_result: list[int] = []
    enqueue_result: list[str] = []
    failures: list[BaseException] = []
    try:
        preceding = service.enqueue(
            _upload(tmp_path, b"evidence before reset"),
            tenant_id=TENANT,
            filename="before.txt",
            source_uri=None,
        )

        def run_reset() -> None:
            try:
                reset_result.append(service.reset(TENANT, timeout_seconds=2))
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        reset_thread = threading.Thread(target=run_reset, daemon=True)
        reset_thread.start()
        assert ingestion.delete_started.wait(timeout=1)

        incoming = tmp_path / "after.txt"
        incoming.write_bytes(b"evidence after reset")

        def run_enqueue() -> None:
            try:
                queued = service.enqueue(
                    incoming,
                    tenant_id=TENANT,
                    filename="after.txt",
                    source_uri=None,
                )
                enqueue_result.append(queued.job.id)
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        enqueue_thread = threading.Thread(target=run_enqueue, daemon=True)
        enqueue_thread.start()
        deadline = time.monotonic() + 1
        while not list((configured.object_dir / "jobs" / TENANT).rglob("*.txt")):
            assert time.monotonic() < deadline
            time.sleep(0.005)
        assert enqueue_result == []  # object persisted, quota+insert still waits on reset

        ingestion.allow_delete.set()
        reset_thread.join(timeout=1)
        enqueue_thread.join(timeout=1)

        assert not reset_thread.is_alive()
        assert not enqueue_thread.is_alive()
        assert failures == []
        assert reset_result == [0]
        assert len(enqueue_result) == 1
        assert service.get(TENANT, preceding.job.id).status == IngestionJobStatus.CANCELLED
        assert service.get(TENANT, enqueue_result[0]).status == IngestionJobStatus.QUEUED
        assert service.store.active_count(TENANT) == 1
    finally:
        ingestion.allow_delete.set()
        service.close()
        object_store.close()


def test_reset_drains_queued_and_running_jobs_before_deleting_evidence(
    settings: Settings, tmp_path: Path
) -> None:
    configured = settings.model_copy(update={"ingestion_worker_enabled": False})
    clock = Clock()
    ingestion = BlockingFakeIngestion()
    object_store = LocalObjectStore(configured.object_dir, configured.artifact_dir)
    service = IngestionJobService(  # type: ignore[arg-type]
        configured,
        ingestion,
        store=SQLiteIngestionJobStore(configured.data_dir / "reset-jobs.sqlite3"),
        object_store=object_store,
        clock=clock,
    )
    try:
        running = service.enqueue(
            _upload(tmp_path, b"running evidence"),
            tenant_id=TENANT,
            filename="running.txt",
            source_uri=None,
        )
        queued_path = tmp_path / "queued.txt"
        queued_path.write_bytes(b"queued evidence")
        queued = service.enqueue(
            queued_path,
            tenant_id=TENANT,
            filename="queued.txt",
            source_uri=None,
        )

        worker = threading.Thread(target=service.process_next, daemon=True)
        worker.start()
        assert ingestion.started.wait(timeout=1)

        assert service.reset(TENANT, timeout_seconds=2) == 0
        assert service.store.active_count(TENANT) == 0
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert service.get(TENANT, running.job.id).status == IngestionJobStatus.CANCELLED
        assert service.get(TENANT, queued.job.id).status == IngestionJobStatus.CANCELLED
        assert ingestion.reset_tenants == [TENANT]
        assert len(service.list(TENANT, limit=10)) == 2  # terminal audit history is retained
    finally:
        service.close()
        object_store.close()


def test_sqlite_job_store_rejects_stale_transitions_and_deletes_terminal(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock], tmp_path: Path
) -> None:
    service, _ingestion, clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    assert (
        service.store.fail(
            queued.job.id,
            "not-the-lease-owner",
            "STALE",
            retryable=True,
            retry_delay_seconds=1,
            now=clock(),
        )
        is None
    )
    assert service.store.mark_cancelled(queued.job.id, None, now=clock())
    terminal = service.store.request_cancel(TENANT, queued.job.id, now=clock())
    assert terminal is not None
    assert terminal.status == IngestionJobStatus.CANCELLED
    assert service.store.retry(TENANT, queued.job.id, now=clock()) is None
    requested = service.store.request_delete(TENANT, queued.job.id, now=clock())
    assert requested is not None
    assert requested.input_cleanup_pending
    assert service.store.delete_terminal(TENANT, queued.job.id) is None
    cleaned = service.store.complete_input_cleanup(
        queued.job.id,
        requested.input_object_ref,
        now=clock(),
    )
    assert cleaned is not None
    deleted = service.store.delete_terminal(TENANT, queued.job.id)
    assert deleted is not None
    assert service.store.get(TENANT, queued.job.id) is None

    assert (
        SQLiteIngestionJobStore._text(datetime(2026, 8, 3))
        == datetime(2026, 8, 3, tzinfo=UTC).isoformat()
    )
    with pytest.raises(ValueError, match="timestamp is missing"):
        SQLiteIngestionJobStore._required_time(None)  # type: ignore[arg-type]

    fresh = new_job_record(
        job_id="22222222-2222-4222-8222-222222222222",
        tenant_id=TENANT,
        filename="fresh.txt",
        source_uri=None,
        input_object_ref="local-object",
        sha256="2" * 64,
        size_bytes=1,
        max_attempts=1,
    )
    assert fresh.created_at.tzinfo is not None
    assert jobs_module.utc_now().tzinfo is not None


def test_delete_reports_terminal_transition_race(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _ingestion, _clock = job_service
    queued = service.enqueue(
        _upload(tmp_path),
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
    )
    assert service.store.delete_terminal(TENANT, queued.job.id) is None
    service.cancel(TENANT, queued.job.id)
    monkeypatch.setattr(service.store, "delete_terminal", lambda *_args: None)
    with pytest.raises(JobStateConflictError, match="state changed"):
        service.delete(TENANT, queued.job.id)


@pytest.mark.asyncio
async def test_worker_run_releases_capacity_when_stop_is_requested(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ingestion, _clock = job_service
    stop = asyncio.Event()
    capacity = asyncio.Semaphore(1)
    calls = 0

    def process_once() -> bool:
        nonlocal calls
        calls += 1
        stop.set()
        return True

    monkeypatch.setattr(service, "process_next", process_once)
    await service.run(stop, capacity)
    assert calls == 1
    await asyncio.wait_for(capacity.acquire(), timeout=0.1)
    capacity.release()


@pytest.mark.asyncio
async def test_worker_run_polls_again_after_idle_timeout(
    job_service: tuple[IngestionJobService, FakeIngestion, Clock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ingestion, _clock = job_service
    stop = asyncio.Event()
    calls = 0

    def idle_then_stop() -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            stop.set()
        return False

    monkeypatch.setattr(service, "process_next", idle_then_stop)
    monkeypatch.setattr(jobs_module, "WORKER_POLL_SECONDS", 0.001)
    await service.run(stop)
    assert calls == 2


def test_owned_job_service_close_is_idempotent(settings: Settings) -> None:
    configured = settings.model_copy(
        update={
            "ingestion_worker_enabled": False,
            "ingestion_lifecycle_retention_days": 30,
        }
    )
    configured.data_dir.mkdir(parents=True, exist_ok=True)
    service = create_job_service(configured, FakeIngestion())  # type: ignore[arg-type]
    service.close()
    service.close()
    assert service._closed  # noqa: SLF001 - verifies the idempotent ownership boundary
    assert service._lifecycle_retention_days == 30  # noqa: SLF001


def test_production_job_store_factory_refuses_local_sqlite(settings: Settings) -> None:
    configured = settings.model_copy(update={"app_env": "production", "database_backend": "duckdb"})
    with pytest.raises(RuntimeError, match="require PostgreSQL"):
        build_ingestion_job_store(configured)


def test_job_store_factory_requires_postgres_dsn_and_builds_local_store(
    settings: Settings,
) -> None:
    missing_dsn = settings.model_copy(update={"database_backend": "postgresql"})
    with pytest.raises(RuntimeError, match="require a DSN"):
        build_ingestion_job_store(missing_dsn)

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    local = build_ingestion_job_store(settings)
    assert isinstance(local, SQLiteIngestionJobStore)
    local.close()


def test_postgres_job_store_uses_shared_schema_and_migration_lock(monkeypatch: Any) -> None:
    class Result:
        rowcount = 0

        @staticmethod
        def fetchone() -> None:
            return None

        @staticmethod
        def fetchall() -> list[dict[str, object]]:
            return []

    class Connection:
        def __init__(self) -> None:
            self.statements: list[str] = []

        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def transaction(self) -> Connection:
            return self

        def execute(self, statement: str, _parameters: object = None) -> Result:
            self.statements.append(" ".join(statement.split()))
            return Result()

    class Pool:
        def __init__(self) -> None:
            self.connection_value = Connection()

        def connection(self) -> Connection:
            return self.connection_value

        @staticmethod
        def close() -> None:
            return None

    pool = Pool()
    psycopg_module = types.ModuleType("psycopg")
    rows_module = types.ModuleType("psycopg.rows")
    rows_module.dict_row = object()  # type: ignore[attr-defined]
    psycopg_module.rows = rows_module  # type: ignore[attr-defined]
    pool_module = types.ModuleType("psycopg_pool")
    pool_module.ConnectionPool = lambda **_kwargs: pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", psycopg_module)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows_module)
    monkeypatch.setitem(sys.modules, "psycopg_pool", pool_module)

    store = PostgresIngestionJobStore(
        "postgresql://example.invalid/crisisweave",
        min_size=1,
        max_size=1,
        timeout_seconds=1,
    )
    store.close()

    migration_sql = "\n".join(pool.connection_value.statements)
    assert "pg_advisory_xact_lock" in migration_sql
    assert "CREATE SCHEMA IF NOT EXISTS crisisweave" in migration_sql
    assert "ALTER TABLE public.ingestion_jobs SET SCHEMA crisisweave" in migration_sql
    assert "CREATE TABLE IF NOT EXISTS crisisweave.ingestion_jobs" in migration_sql
    assert migration_sql.count("ON crisisweave.ingestion_jobs") == 4
    assert "WHERE status IN ('running', 'cancelling')" in migration_sql

    source = inspect.getsource(PostgresIngestionJobStore)
    for operation in ("FROM", "INTO", "UPDATE", "TABLE", "ON"):
        assert re.search(rf"\b{operation}\s+ingestion_jobs\b", source, re.IGNORECASE) is None
    claim_source = inspect.getsource(PostgresIngestionJobStore.claim)
    assert "NOT EXISTS" in claim_source
    assert "active.status IN ('running', 'cancelling')" in claim_source
    assert "FOR UPDATE OF candidate SKIP LOCKED" in claim_source
    assert "pg_try_advisory_xact_lock" in claim_source
