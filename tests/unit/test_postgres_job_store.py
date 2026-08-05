from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from crisisweave.job_store import (
    IngestionJobStatus,
    JobQueueFullError,
    JobRecord,
    PostgresIngestionJobStore,
    new_job_record,
)

TENANT = "a" * 32
JOB_ID = "11111111-1111-4111-8111-111111111111"
NOW = datetime(2026, 8, 3, tzinfo=UTC)


class Result:
    def __init__(
        self,
        *,
        row: dict[str, object] | None = None,
        rows: list[dict[str, object]] | None = None,
        rowcount: int = 0,
    ) -> None:
        self._row = row
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self) -> dict[str, object] | None:
        return self._row

    def fetchall(self) -> list[dict[str, object]]:
        return self._rows


class Connection:
    def __init__(self, responses: list[Result]) -> None:
        self.responses = responses
        self.statements: list[tuple[str, object]] = []

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> Connection:
        return self

    def execute(self, statement: str, parameters: object = None) -> Result:
        self.statements.append((" ".join(statement.split()), parameters))
        if not self.responses:
            raise AssertionError(f"unexpected SQL statement: {statement}")
        return self.responses.pop(0)


class Pool:
    def __init__(self, responses: list[Result]) -> None:
        self.connection_value = Connection(responses)
        self.closed = False

    def connection(self) -> Connection:
        return self.connection_value

    def close(self) -> None:
        self.closed = True


def _record(**updates: object) -> JobRecord:
    record = new_job_record(
        job_id=JOB_ID,
        tenant_id=TENANT,
        filename="incident.txt",
        source_uri=None,
        input_object_ref="s3://evidence/input?versionId=1",
        sha256="1" * 64,
        size_bytes=12,
        max_attempts=3,
        now=NOW,
    )
    return record.model_copy(update=updates)


def _row(**updates: object) -> dict[str, object]:
    return _record(**updates).model_dump(mode="python")


def _store(*responses: Result) -> tuple[PostgresIngestionJobStore, Pool]:
    store = object.__new__(PostgresIngestionJobStore)
    pool = Pool(list(responses))
    store._pool = pool
    return store, pool


def _assert_consumed(pool: Pool) -> None:
    assert pool.connection_value.responses == []


def test_postgres_enqueue_handles_duplicate_quota_insert_and_missing_return() -> None:
    record = _record()

    duplicate_store, duplicate_pool = _store(Result(), Result(row=_row()))
    duplicate, deduplicated = duplicate_store.enqueue(
        record,
        max_retained_jobs=10,
        max_retained_bytes=100,
    )
    assert deduplicated
    assert duplicate.id == JOB_ID
    _assert_consumed(duplicate_pool)

    quota_store, quota_pool = _store(
        Result(),
        Result(),
        Result(row={"job_count": 1, "job_bytes": 12}),
    )
    with pytest.raises(JobQueueFullError, match="quota exceeded"):
        quota_store.enqueue(record, max_retained_jobs=1, max_retained_bytes=100)
    quota_parameters = quota_pool.connection_value.statements[-1][1]
    assert isinstance(quota_parameters, list)
    assert IngestionJobStatus.DEAD_LETTER.value in quota_parameters[1]
    _assert_consumed(quota_pool)

    inserted_store, inserted_pool = _store(
        Result(),
        Result(),
        Result(row={"job_count": 0, "job_bytes": 0}),
        Result(row=_row()),
    )
    inserted, deduplicated = inserted_store.enqueue(
        record,
        max_retained_jobs=10,
        max_retained_bytes=100,
    )
    assert not deduplicated
    assert inserted.id == JOB_ID
    _assert_consumed(inserted_pool)

    missing_store, missing_pool = _store(Result(), Result(), Result(), Result())
    with pytest.raises(RuntimeError, match="did not return"):
        missing_store.enqueue(record, max_retained_jobs=10, max_retained_bytes=100)
    _assert_consumed(missing_pool)


def test_postgres_claim_respects_empty_queue_tenant_lock_and_lease_update() -> None:
    empty_store, empty_pool = _store(Result())
    assert empty_store.claim("worker", now=NOW, lease_seconds=30) is None
    _assert_consumed(empty_pool)

    selected = {"id": JOB_ID, "tenant_id": TENANT}
    denied_store, denied_pool = _store(
        Result(row=selected),
        Result(row={"acquired": False}),
    )
    assert denied_store.claim("worker", now=NOW, lease_seconds=30) is None
    _assert_consumed(denied_pool)

    running = _row(
        status=IngestionJobStatus.RUNNING,
        stage="claimed",
        progress=5,
        attempt_count=1,
        lease_owner="worker",
        lease_expires_at=NOW + timedelta(seconds=30),
    )
    claimed_store, claimed_pool = _store(
        Result(row=selected),
        Result(row={"acquired": True}),
        Result(row=running),
    )
    claimed = claimed_store.claim("worker", now=NOW, lease_seconds=30)
    assert claimed is not None
    assert claimed.status == IngestionJobStatus.RUNNING
    assert claimed.lease_owner == "worker"
    assert "SKIP LOCKED" in claimed_pool.connection_value.statements[0][0]
    _assert_consumed(claimed_pool)


def test_postgres_heartbeat_cancellation_success_and_mark_cancelled_contracts() -> None:
    heartbeat_store, heartbeat_pool = _store(Result(rowcount=1))
    assert heartbeat_store.heartbeat(
        JOB_ID,
        "worker",
        progress=140,
        stage="x" * 100,
        now=NOW,
        lease_seconds=30,
    )
    heartbeat_parameters = heartbeat_pool.connection_value.statements[0][1]
    assert isinstance(heartbeat_parameters, list)
    assert heartbeat_parameters[0] == 99
    assert heartbeat_parameters[1] == "x" * 80

    missing_cancel_store, _ = _store(Result())
    assert missing_cancel_store.cancellation_requested(JOB_ID, "worker")
    requested_store, _ = _store(Result(row={"cancel_requested": True}))
    assert requested_store.cancellation_requested(JOB_ID, "worker")
    active_store, _ = _store(Result(row={"cancel_requested": False}))
    assert not active_store.cancellation_requested(JOB_ID, "worker")

    succeeded = _row(status=IngestionJobStatus.SUCCEEDED, stage="completed")
    succeed_store, _ = _store(Result(row=succeeded), Result())
    assert succeed_store.succeed(JOB_ID, "worker", "document-id", now=NOW)
    stale_store, _ = _store(Result())
    assert not stale_store.succeed(JOB_ID, "worker", "document-id", now=NOW)

    cancelled = _row(status=IngestionJobStatus.CANCELLED, stage="cancelled")
    owned_store, owned_pool = _store(Result(row=cancelled), Result())
    assert owned_store.mark_cancelled(JOB_ID, "worker", now=NOW)
    assert "lease_owner = %s" in owned_pool.connection_value.statements[0][0]
    ownerless_store, ownerless_pool = _store(Result())
    assert not ownerless_store.mark_cancelled(JOB_ID, None, now=NOW)
    assert "lease_owner IS NULL" in ownerless_pool.connection_value.statements[0][0]


@pytest.mark.parametrize(
    ("current", "retryable", "expected_status", "expected_stage"),
    [
        (
            _row(
                status=IngestionJobStatus.RUNNING,
                lease_owner="worker",
                attempt_count=1,
            ),
            True,
            IngestionJobStatus.RETRY_WAIT,
            "retry_wait",
        ),
        (
            _row(
                status=IngestionJobStatus.RUNNING,
                lease_owner="worker",
                attempt_count=3,
            ),
            True,
            IngestionJobStatus.DEAD_LETTER,
            "dead_letter",
        ),
        (
            _row(
                status=IngestionJobStatus.CANCELLING,
                lease_owner="worker",
                cancel_requested=True,
            ),
            False,
            IngestionJobStatus.CANCELLED,
            "cancelled",
        ),
    ],
)
def test_postgres_fail_applies_retry_dead_letter_and_cancel_transitions(
    current: dict[str, object],
    retryable: bool,
    expected_status: IngestionJobStatus,
    expected_stage: str,
) -> None:
    updated = dict(current)
    updated.update(
        status=expected_status,
        stage=expected_stage,
        lease_owner=None,
        lease_expires_at=None,
    )
    responses = [Result(row=current), Result(row=updated)]
    if expected_status in {
        IngestionJobStatus.DEAD_LETTER,
        IngestionJobStatus.CANCELLED,
    }:
        responses.append(Result())
    store, pool = _store(*responses)
    failed = store.fail(
        JOB_ID,
        "worker",
        "E" * 100,
        retryable=retryable,
        retry_delay_seconds=4,
        now=NOW,
    )
    assert failed is not None
    assert failed.status == expected_status
    parameters = next(
        parameters
        for statement, parameters in pool.connection_value.statements
        if statement.startswith("UPDATE crisisweave.ingestion_jobs SET status")
    )
    assert isinstance(parameters, list)
    assert parameters[3] == "E" * 80
    _assert_consumed(pool)


def test_postgres_fail_ignores_missing_or_stale_lease() -> None:
    missing_store, missing_pool = _store(Result())
    assert (
        missing_store.fail(
            JOB_ID,
            "worker",
            "ERROR",
            retryable=True,
            retry_delay_seconds=1,
            now=NOW,
        )
        is None
    )
    _assert_consumed(missing_pool)

    stale_store, stale_pool = _store(
        Result(row=_row(status=IngestionJobStatus.RUNNING, lease_owner="another-worker"))
    )
    assert (
        stale_store.fail(
            JOB_ID,
            "worker",
            "ERROR",
            retryable=True,
            retry_delay_seconds=1,
            now=NOW,
        )
        is None
    )
    _assert_consumed(stale_pool)


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (_row(status=IngestionJobStatus.QUEUED), IngestionJobStatus.CANCELLED),
        (
            _row(status=IngestionJobStatus.RUNNING, lease_owner="worker"),
            IngestionJobStatus.CANCELLING,
        ),
    ],
)
def test_postgres_request_cancel_distinguishes_queued_and_running(
    current: dict[str, object], expected: IngestionJobStatus
) -> None:
    updated = dict(current)
    updated.update(status=expected, stage=expected.value, cancel_requested=True)
    responses = [Result(row=current), Result(row=updated)]
    if expected == IngestionJobStatus.CANCELLED:
        responses.append(Result())
    store, pool = _store(*responses)
    result = store.request_cancel(TENANT, JOB_ID, now=NOW)
    assert result is not None
    assert result.status == expected
    parameters = next(
        parameters
        for statement, parameters in pool.connection_value.statements
        if statement.startswith("UPDATE crisisweave.ingestion_jobs SET status")
    )
    assert isinstance(parameters, list)
    is_queued = expected == IngestionJobStatus.CANCELLED
    assert parameters[2:4] == [is_queued, is_queued]
    _assert_consumed(pool)


def test_postgres_request_cancel_handles_missing_and_terminal_without_update() -> None:
    missing_store, missing_pool = _store(Result())
    assert missing_store.request_cancel(TENANT, JOB_ID, now=NOW) is None
    _assert_consumed(missing_pool)

    terminal = _row(status=IngestionJobStatus.DEAD_LETTER, stage="dead_letter")
    terminal_store, terminal_pool = _store(Result(row=terminal))
    result = terminal_store.request_cancel(TENANT, JOB_ID, now=NOW)
    assert result is not None
    assert result.status == IngestionJobStatus.DEAD_LETTER
    _assert_consumed(terminal_pool)


def test_postgres_bulk_queries_crud_recovery_and_close() -> None:
    cancelled = _row(
        status=IngestionJobStatus.CANCELLED,
        stage="cancelled",
        cancel_requested=True,
    )
    cancel_all_store, _ = _store(Result(rows=[cancelled]), Result())
    cancelled_rows = cancel_all_store.request_cancel_all(TENANT, now=NOW)
    assert [item.status for item in cancelled_rows] == [IngestionJobStatus.CANCELLED]

    count_store, _ = _store(Result(row={"job_count": 2}))
    assert count_store.active_count(TENANT) == 2
    missing_count_store, _ = _store(Result())
    assert missing_count_store.active_count(TENANT) == 0

    queued = _row(status=IngestionJobStatus.QUEUED)
    dead_letter = _row(status=IngestionJobStatus.DEAD_LETTER, stage="dead_letter")
    retry_store, _ = _store(Result(row=dead_letter), Result(row=queued))
    assert retry_store.retry(TENANT, JOB_ID, now=NOW) is not None
    missing_retry_store, _ = _store(Result())
    assert missing_retry_store.retry(TENANT, JOB_ID, now=NOW) is None

    get_store, _ = _store(Result(row=queued))
    assert get_store.get(TENANT, JOB_ID) is not None
    missing_get_store, _ = _store(Result())
    assert missing_get_store.get(TENANT, JOB_ID) is None

    list_store, list_pool = _store(Result(rows=[queued, cancelled]))
    assert len(list_store.list(TENANT, limit=9_999)) == 2
    list_parameters = list_pool.connection_value.statements[0][1]
    assert list_parameters == [TENANT, 500]

    delete_store, _ = _store(Result(row=cancelled))
    assert delete_store.delete_terminal(TENANT, JOB_ID) is not None
    missing_delete_store, _ = _store(Result())
    assert missing_delete_store.delete_terminal(TENANT, JOB_ID) is None

    expired = _row(
        status=IngestionJobStatus.RUNNING,
        lease_owner="worker",
        lease_expires_at=NOW,
        current_attempt_started_at=NOW - timedelta(seconds=5),
        attempt_count=3,
    )
    recovered_dead = dict(
        expired,
        status=IngestionJobStatus.DEAD_LETTER,
        stage="dead_letter",
        lease_owner=None,
        lease_expires_at=None,
        current_attempt_started_at=None,
        processing_seconds=5.0,
        usage_estimated=True,
    )
    recover_store, recover_pool = _store(
        Result(rows=[expired]),
        Result(row=recovered_dead),
        Result(),
    )
    assert recover_store.recover_expired(now=NOW) == 1
    recovery_statement = recover_pool.connection_value.statements[1][0]
    assert "usage_estimated = TRUE" in recovery_statement
    lifecycle_parameters = recover_pool.connection_value.statements[2][1]
    assert isinstance(lifecycle_parameters, list)
    assert lifecycle_parameters[-1] is True
    _assert_consumed(recover_pool)

    close_store, close_pool = _store()
    close_store.close()
    assert close_pool.closed


def test_postgres_record_normalizes_database_uuid_values() -> None:
    import uuid

    row: dict[str, Any] = _row(document_id="22222222-2222-4222-8222-222222222222")
    row["id"] = uuid.UUID(JOB_ID)
    row["document_id"] = uuid.UUID("22222222-2222-4222-8222-222222222222")
    record = PostgresIngestionJobStore._record(row)
    assert record.id == JOB_ID
    assert record.document_id == "22222222-2222-4222-8222-222222222222"


def test_postgres_cleanup_state_outbox_and_safe_delete_contracts() -> None:
    deleting = _row(
        status=IngestionJobStatus.CANCELLED,
        cancel_requested=True,
        input_cleanup_pending=True,
        delete_requested=True,
    )
    requested_store, requested_pool = _store(Result(row=deleting))
    requested = requested_store.request_delete(TENANT, JOB_ID, now=NOW)
    assert requested is not None and requested.input_cleanup_pending
    assert "input_cleanup_pending = TRUE" in requested_pool.connection_value.statements[0][0]

    candidates_store, candidates_pool = _store(Result(rows=[deleting]))
    candidates = candidates_store.cleanup_candidates(limit=9_999)
    assert [item.id for item in candidates] == [JOB_ID]
    assert candidates_pool.connection_value.statements[0][1] == [500]

    cleaned_row = dict(deleting, input_cleanup_pending=False)
    cleaned_store, cleaned_pool = _store(Result(row=cleaned_row))
    cleaned = cleaned_store.complete_input_cleanup(
        JOB_ID,
        str(deleting["input_object_ref"]),
        now=NOW,
    )
    assert cleaned is not None and not cleaned.input_cleanup_pending
    cleanup_sql = cleaned_pool.connection_value.statements[0][0]
    assert "input_object_ref = %s" in cleanup_sql
    assert "input_cleanup_pending = TRUE" in cleanup_sql

    delete_store, delete_pool = _store(Result(row=cleaned_row))
    assert delete_store.delete_terminal(TENANT, JOB_ID) is not None
    delete_sql = delete_pool.connection_value.statements[0][0]
    assert "delete_requested = TRUE" in delete_sql
    assert "input_cleanup_pending = FALSE" in delete_sql

    schedule_store, schedule_pool = _store(Result())
    reference = "s3://evidence/orphan?versionId=exact"
    schedule_store.schedule_orphan_cleanup(reference, now=NOW)
    assert schedule_pool.connection_value.statements[0][1] == [reference, NOW, NOW]

    orphan_store, orphan_pool = _store(Result(rows=[{"input_object_ref": reference}]))
    assert orphan_store.orphan_cleanup_candidates(limit=0) == [reference]
    assert orphan_pool.connection_value.statements[0][1] == [1]

    failure_store, failure_pool = _store(Result())
    failure_store.record_orphan_cleanup_failure(reference, "E" * 100, now=NOW)
    failure_parameters = failure_pool.connection_value.statements[0][1]
    assert isinstance(failure_parameters, list)
    assert failure_parameters[0] == "E" * 80

    complete_store, _ = _store(Result(rowcount=1))
    assert complete_store.complete_orphan_cleanup(reference)
    raced_store, _ = _store(Result(rowcount=0))
    assert not raced_store.complete_orphan_cleanup(reference)


def test_postgres_lifecycle_outbox_claim_ack_and_generation_contracts() -> None:
    event_id = "66666666-6666-4666-8666-666666666666"
    event_row: dict[str, object] = {
        "event_id": event_id,
        "lifecycle_generation": 2,
        "status": IngestionJobStatus.SUCCEEDED.value,
        "lifecycle_started_at": NOW - timedelta(seconds=20),
        "terminal_at": NOW,
        "processing_seconds": 7.5,
        "compute_cost_usd": 0.25,
        "usage_estimated": True,
        "delivery_attempts": 1,
    }
    claim_store, claim_pool = _store(Result(rows=[event_row]))
    events = claim_store.claim_lifecycle_events(
        "telemetry-worker",
        now=NOW,
        lease_seconds=30,
        limit=9_999,
    )
    assert len(events) == 1
    assert events[0].event_id == event_id
    assert events[0].duration_seconds == 20
    assert events[0].processing_seconds == 7.5
    assert events[0].usage_estimated
    claim_parameters = claim_pool.connection_value.statements[0][1]
    assert isinstance(claim_parameters, list)
    assert claim_parameters[1] == 500
    assert "SKIP LOCKED" in claim_pool.connection_value.statements[0][0]

    ack_store, _ = _store(Result(rowcount=1))
    assert ack_store.complete_lifecycle_event(event_id, "telemetry-worker", now=NOW)
    stale_ack_store, _ = _store(Result(rowcount=0))
    assert not stale_ack_store.complete_lifecycle_event(event_id, "wrong-owner", now=NOW)

    stats_store, stats_pool = _store(
        Result(
            row={
                "pending_count": 4,
                "oldest_terminal_at": NOW - timedelta(seconds=90),
            }
        )
    )
    assert stats_store.lifecycle_outbox_stats(now=NOW) == (4, 90.0)
    assert "delivered_at IS NULL" in stats_pool.connection_value.statements[0][0]

    empty_stats_store, _ = _store(Result(row={"pending_count": 0, "oldest_terminal_at": None}))
    assert empty_stats_store.lifecycle_outbox_stats(now=NOW) == (0, 0.0)

    prune_store, prune_pool = _store(Result(rowcount=3))
    assert (
        prune_store.prune_delivered_lifecycle_events(
            before=NOW - timedelta(days=14),
            limit=9_999,
        )
        == 3
    )
    prune_statement, prune_parameters = prune_pool.connection_value.statements[0]
    assert "delivered_at IS NOT NULL" in prune_statement
    assert isinstance(prune_parameters, list)
    assert prune_parameters[1] == 500

    dead = _row(
        status=IngestionJobStatus.DEAD_LETTER,
        stage="dead_letter",
        lifecycle_generation=1,
        processing_seconds=3.0,
        compute_cost_usd=0.1,
    )
    requeued = _row(
        status=IngestionJobStatus.QUEUED,
        stage="queued",
        lifecycle_generation=2,
        lifecycle_started_at=NOW,
        processing_seconds=0.0,
        compute_cost_usd=0.0,
        compute_cost_per_hour_usd=12.0,
    )
    retry_store, retry_pool = _store(Result(row=dead), Result(row=requeued))
    retried = retry_store.retry(
        TENANT,
        JOB_ID,
        now=NOW,
        compute_cost_per_hour_usd=12.0,
    )
    assert retried is not None
    assert retried.lifecycle_generation == 2
    update_parameters = retry_pool.connection_value.statements[1][1]
    assert isinstance(update_parameters, list)
    assert update_parameters[4] == 12.0
    assert "usage_estimated = FALSE" in retry_pool.connection_value.statements[1][0]
