"""Durable single-node ingestion queue with transactional worker leases."""

from __future__ import annotations

import builtins
import hashlib
import math
import re
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from crisisweave.config import Settings
from crisisweave.postgres_migrations import (
    MIGRATION_LOCK,
    apply_job_migrations,
    apply_metadata_migrations,
    verify_postgres_schema,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IngestionJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    CANCELLING = "cancelling"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"


ACTIVE_JOB_STATUSES = (
    IngestionJobStatus.QUEUED,
    IngestionJobStatus.RUNNING,
    IngestionJobStatus.RETRY_WAIT,
    IngestionJobStatus.CANCELLING,
)
RETAINED_INPUT_STATUSES = (*ACTIVE_JOB_STATUSES, IngestionJobStatus.DEAD_LETTER)
TERMINAL_JOB_STATUSES = (
    IngestionJobStatus.SUCCEEDED,
    IngestionJobStatus.CANCELLED,
    IngestionJobStatus.DEAD_LETTER,
)


class IngestionJob(BaseModel):
    """Public, tenant-scoped projection of an ingestion job."""

    model_config = ConfigDict(extra="forbid")

    id: str
    filename: str
    source_uri: str | None = None
    size_bytes: int = Field(ge=1)
    status: IngestionJobStatus
    progress: int = Field(ge=0, le=100)
    stage: str
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    cancel_requested: bool = False
    document_id: str | None = None
    error_code: str | None = None
    created_at: datetime
    updated_at: datetime
    available_at: datetime


class EnqueueJobResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job: IngestionJob
    deduplicated: bool = False


class JobRecord(IngestionJob):
    """Internal queue record; paths and tenant lineage never cross the API boundary."""

    tenant_id: str
    sha256: str
    input_object_ref: str
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    input_cleanup_pending: bool = False
    delete_requested: bool = False
    lifecycle_started_at: datetime
    lifecycle_generation: int = Field(default=1, ge=1)
    processing_seconds: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    compute_cost_usd: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    usage_estimated: bool = False
    current_attempt_started_at: datetime | None = None
    compute_cost_per_hour_usd: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)

    def public(self) -> IngestionJob:
        return IngestionJob.model_validate(
            self.model_dump(
                exclude={
                    "tenant_id",
                    "sha256",
                    "input_object_ref",
                    "lease_owner",
                    "lease_expires_at",
                    "input_cleanup_pending",
                    "delete_requested",
                    "lifecycle_started_at",
                    "lifecycle_generation",
                    "processing_seconds",
                    "compute_cost_usd",
                    "usage_estimated",
                    "current_attempt_started_at",
                    "compute_cost_per_hour_usd",
                }
            )
        )


class IngestionLifecycleEvent(BaseModel):
    """Content-free terminal lifecycle event delivered with at-least-once semantics."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    lifecycle_generation: int = Field(ge=1)
    status: IngestionJobStatus
    lifecycle_started_at: datetime
    terminal_at: datetime
    processing_seconds: float = Field(ge=0.0, allow_inf_nan=False)
    compute_cost_usd: float = Field(ge=0.0, allow_inf_nan=False)
    usage_estimated: bool = False
    delivery_attempts: int = Field(ge=1)

    @property
    def duration_seconds(self) -> float:
        return (self.terminal_at - self.lifecycle_started_at).total_seconds()


class JobQueueFullError(ValueError):
    """Raised when a tenant's durable pending-work quota is exhausted."""


class IngestionJobStore(Protocol):
    def enqueue(
        self,
        record: JobRecord,
        *,
        max_retained_jobs: int,
        max_retained_bytes: int,
    ) -> tuple[JobRecord, bool]: ...

    def claim(self, owner: str, *, now: datetime, lease_seconds: float) -> JobRecord | None: ...

    def heartbeat(
        self,
        job_id: str,
        owner: str,
        *,
        progress: int,
        stage: str,
        now: datetime,
        lease_seconds: float,
    ) -> bool: ...

    def cancellation_requested(self, job_id: str, owner: str) -> bool: ...

    def succeed(
        self,
        job_id: str,
        owner: str,
        document_id: str,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool: ...

    def fail(
        self,
        job_id: str,
        owner: str,
        error_code: str,
        *,
        retryable: bool,
        retry_delay_seconds: float,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> JobRecord | None: ...

    def mark_cancelled(
        self,
        job_id: str,
        owner: str | None,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool: ...

    def request_cancel(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None: ...

    def request_cancel_all(self, tenant_id: str, *, now: datetime) -> list[JobRecord]: ...

    def active_count(self, tenant_id: str) -> int: ...

    def retry(
        self,
        tenant_id: str,
        job_id: str,
        *,
        now: datetime,
        compute_cost_per_hour_usd: float | None = None,
    ) -> JobRecord | None: ...

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None: ...

    def list(self, tenant_id: str, *, limit: int) -> list[JobRecord]: ...

    def status_counts(self) -> dict[str, int]: ...

    def request_delete(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None: ...

    def cleanup_candidates(self, *, limit: int) -> builtins.list[JobRecord]: ...

    def complete_input_cleanup(
        self, job_id: str, input_object_ref: str, *, now: datetime
    ) -> JobRecord | None: ...

    def delete_terminal(self, tenant_id: str, job_id: str) -> JobRecord | None: ...

    def schedule_orphan_cleanup(self, input_object_ref: str, *, now: datetime) -> None: ...

    def orphan_cleanup_candidates(self, *, limit: int) -> builtins.list[str]: ...

    def record_orphan_cleanup_failure(
        self, input_object_ref: str, error_code: str, *, now: datetime
    ) -> None: ...

    def complete_orphan_cleanup(self, input_object_ref: str) -> bool: ...

    def recover_expired(self, *, now: datetime) -> int: ...

    def claim_lifecycle_events(
        self,
        owner: str,
        *,
        now: datetime,
        lease_seconds: float,
        limit: int,
    ) -> builtins.list[IngestionLifecycleEvent]: ...

    def complete_lifecycle_event(self, event_id: str, owner: str, *, now: datetime) -> bool: ...

    def lifecycle_outbox_stats(self, *, now: datetime) -> tuple[int, float]: ...

    def prune_delivered_lifecycle_events(self, *, before: datetime, limit: int) -> int: ...

    def close(self) -> None: ...


_SELECT_COLUMNS = """
    id, tenant_id, filename, source_uri, input_object_ref, sha256, size_bytes,
    status, progress, stage, attempt_count, max_attempts, available_at,
    lease_owner, lease_expires_at, cancel_requested, document_id, error_code,
    input_cleanup_pending, delete_requested, lifecycle_started_at,
    lifecycle_generation, processing_seconds, compute_cost_usd,
    usage_estimated, current_attempt_started_at, compute_cost_per_hour_usd,
    created_at, updated_at
"""

_OUTBOX_SELECT_COLUMNS = """
    event_id, lifecycle_generation, status, lifecycle_started_at, terminal_at,
    processing_seconds, compute_cost_usd, delivery_attempts, usage_estimated
"""

_LIFECYCLE_EVENT_DOMAIN = b"crisisweave:ingestion-lifecycle-event:v1\x00"


def _lifecycle_event_id(job_id: str, generation: int) -> str:
    """Derive a stable opaque event UUID from a random job UUID and generation."""

    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError as exc:
        raise ValueError("Ingestion job identifier must be a UUID") from exc
    digest = hashlib.sha256(
        _LIFECYCLE_EVENT_DOMAIN + job_uuid.bytes + generation.to_bytes(8, "big")
    ).digest()
    return str(uuid.UUID(bytes=digest[:16], version=5))


def _validated_usage(processing_seconds: float, compute_cost_usd: float) -> tuple[float, float]:
    if (
        not math.isfinite(processing_seconds)
        or processing_seconds < 0
        or not math.isfinite(compute_cost_usd)
        or compute_cost_usd < 0
    ):
        raise ValueError("Ingestion lifecycle usage must be finite and non-negative")
    return processing_seconds, compute_cost_usd


def _expired_attempt_usage(record: JobRecord, now: datetime) -> tuple[float, float]:
    if record.current_attempt_started_at is None:
        return (0.0, 0.0)
    terminal = min(now, record.lease_expires_at or now)
    seconds = max(0.0, (terminal - record.current_attempt_started_at).total_seconds())
    return seconds, seconds * record.compute_cost_per_hour_usd / 3600


class SQLiteIngestionJobStore:
    """SQLite WAL queue for the repository's single-node deployment profile.

    Every state transition is guarded by the current lease owner. ``BEGIN IMMEDIATE``
    serializes selection and claim across processes without relying on an in-memory lock.
    """

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(path),
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=30000")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ingestion_jobs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    source_uri TEXT,
                    input_object_ref TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL CHECK(progress BETWEEN 0 AND 100),
                    stage TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
                    max_attempts INTEGER NOT NULL CHECK(max_attempts >= 1),
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    document_id TEXT,
                    error_code TEXT,
                    input_cleanup_pending INTEGER NOT NULL DEFAULT 0,
                    delete_requested INTEGER NOT NULL DEFAULT 0,
                    lifecycle_started_at TEXT NOT NULL,
                    lifecycle_generation INTEGER NOT NULL DEFAULT 1
                        CHECK(lifecycle_generation >= 1),
                    processing_seconds REAL NOT NULL DEFAULT 0
                        CHECK(processing_seconds >= 0),
                    compute_cost_usd REAL NOT NULL DEFAULT 0
                        CHECK(compute_cost_usd >= 0),
                    usage_estimated INTEGER NOT NULL DEFAULT 0
                        CHECK(usage_estimated IN (0, 1)),
                    current_attempt_started_at TEXT,
                    compute_cost_per_hour_usd REAL NOT NULL DEFAULT 0
                        CHECK(compute_cost_per_hour_usd >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ingestion_lifecycle_outbox (
                    event_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    lifecycle_generation INTEGER NOT NULL CHECK(lifecycle_generation >= 1),
                    status TEXT NOT NULL CHECK(status IN ('succeeded', 'cancelled', 'dead_letter')),
                    lifecycle_started_at TEXT NOT NULL,
                    terminal_at TEXT NOT NULL,
                    processing_seconds REAL NOT NULL CHECK(processing_seconds >= 0),
                    compute_cost_usd REAL NOT NULL CHECK(compute_cost_usd >= 0),
                    usage_estimated INTEGER NOT NULL DEFAULT 0
                        CHECK(usage_estimated IN (0, 1)),
                    delivery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(delivery_attempts >= 0),
                    delivery_owner TEXT,
                    delivery_lease_expires_at TEXT,
                    delivered_at TEXT,
                    UNIQUE(job_id, lifecycle_generation)
                );
                CREATE TABLE IF NOT EXISTS ingestion_orphan_cleanup (
                    input_object_ref TEXT PRIMARY KEY,
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ingestion_jobs_tenant_created
                    ON ingestion_jobs(tenant_id, created_at DESC, id DESC);
                CREATE INDEX IF NOT EXISTS ingestion_jobs_claim
                    ON ingestion_jobs(status, available_at, created_at, id);
                CREATE INDEX IF NOT EXISTS ingestion_jobs_active_sha
                    ON ingestion_jobs(tenant_id, sha256, status);
                CREATE INDEX IF NOT EXISTS ingestion_jobs_active_tenant
                    ON ingestion_jobs(tenant_id)
                    WHERE status IN ('running', 'cancelling');
                """
            )
            columns = {
                str(row[1]) for row in self._connection.execute("PRAGMA table_info(ingestion_jobs)")
            }
            if "input_cleanup_pending" not in columns:
                self._connection.execute(
                    "ALTER TABLE ingestion_jobs ADD COLUMN "
                    "input_cleanup_pending INTEGER NOT NULL DEFAULT 0"
                )
            if "delete_requested" not in columns:
                self._connection.execute(
                    "ALTER TABLE ingestion_jobs ADD COLUMN "
                    "delete_requested INTEGER NOT NULL DEFAULT 0"
                )
            additions = {
                "lifecycle_started_at": "TEXT",
                "lifecycle_generation": "INTEGER NOT NULL DEFAULT 1",
                "processing_seconds": "REAL NOT NULL DEFAULT 0",
                "compute_cost_usd": "REAL NOT NULL DEFAULT 0",
                "usage_estimated": "INTEGER NOT NULL DEFAULT 0",
                "current_attempt_started_at": "TEXT",
                "compute_cost_per_hour_usd": "REAL NOT NULL DEFAULT 0",
            }
            for column, definition in additions.items():
                if column not in columns:
                    self._connection.execute(
                        f"ALTER TABLE ingestion_jobs ADD COLUMN {column} {definition}"  # noqa: S608
                    )
            self._connection.execute(
                """UPDATE ingestion_jobs SET lifecycle_started_at = created_at
                   WHERE lifecycle_started_at IS NULL"""
            )
            outbox_columns = {
                str(row[1])
                for row in self._connection.execute("PRAGMA table_info(ingestion_lifecycle_outbox)")
            }
            if "usage_estimated" not in outbox_columns:
                # Pre-v5 events have no trustworthy measurement provenance.
                self._connection.execute(
                    "ALTER TABLE ingestion_lifecycle_outbox ADD COLUMN "
                    "usage_estimated INTEGER NOT NULL DEFAULT 1"
                )
            self._connection.execute(
                """CREATE INDEX IF NOT EXISTS ingestion_jobs_cleanup
                   ON ingestion_jobs(input_cleanup_pending, delete_requested, updated_at)"""
            )
            self._connection.execute(
                """CREATE INDEX IF NOT EXISTS ingestion_lifecycle_outbox_pending
                   ON ingestion_lifecycle_outbox(
                       delivered_at, delivery_lease_expires_at, terminal_at, event_id
                   )"""
            )
            # Upgrades must not silently omit terminal lifecycles that predate the outbox.
            terminal_rows = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs
                    WHERE status IN (?, ?, ?)""",  # noqa: S608  # nosec B608
                [item.value for item in TERMINAL_JOB_STATUSES],
            ).fetchall()
            for row in terminal_rows:
                self._insert_lifecycle_event(
                    self._record(row),
                    self._required_time(row["updated_at"]),
                    force_estimated=True,
                )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _text(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _time(value: str | None) -> datetime | None:
        return datetime.fromisoformat(value) if value is not None else None

    @classmethod
    def _required_time(cls, value: str) -> datetime:
        parsed = cls._time(value)
        if parsed is None:
            raise ValueError("Durable ingestion job timestamp is missing")
        return parsed

    @classmethod
    def _record(cls, row: sqlite3.Row) -> JobRecord:
        return JobRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            filename=row["filename"],
            source_uri=row["source_uri"],
            input_object_ref=row["input_object_ref"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            status=IngestionJobStatus(row["status"]),
            progress=row["progress"],
            stage=row["stage"],
            attempt_count=row["attempt_count"],
            max_attempts=row["max_attempts"],
            available_at=cls._required_time(row["available_at"]),
            lease_owner=row["lease_owner"],
            lease_expires_at=cls._time(row["lease_expires_at"]),
            cancel_requested=bool(row["cancel_requested"]),
            document_id=row["document_id"],
            error_code=row["error_code"],
            input_cleanup_pending=bool(row["input_cleanup_pending"]),
            delete_requested=bool(row["delete_requested"]),
            lifecycle_started_at=cls._required_time(row["lifecycle_started_at"]),
            lifecycle_generation=row["lifecycle_generation"],
            processing_seconds=row["processing_seconds"],
            compute_cost_usd=row["compute_cost_usd"],
            usage_estimated=bool(row["usage_estimated"]),
            current_attempt_started_at=cls._time(row["current_attempt_started_at"]),
            compute_cost_per_hour_usd=row["compute_cost_per_hour_usd"],
            created_at=cls._required_time(row["created_at"]),
            updated_at=cls._required_time(row["updated_at"]),
        )

    @classmethod
    def _lifecycle_event(cls, row: sqlite3.Row) -> IngestionLifecycleEvent:
        return IngestionLifecycleEvent(
            event_id=row["event_id"],
            lifecycle_generation=row["lifecycle_generation"],
            status=IngestionJobStatus(row["status"]),
            lifecycle_started_at=cls._required_time(row["lifecycle_started_at"]),
            terminal_at=cls._required_time(row["terminal_at"]),
            processing_seconds=row["processing_seconds"],
            compute_cost_usd=row["compute_cost_usd"],
            delivery_attempts=row["delivery_attempts"],
            usage_estimated=bool(row["usage_estimated"]),
        )

    def _insert_lifecycle_event(
        self,
        record: JobRecord,
        terminal_at: datetime,
        *,
        force_estimated: bool = False,
    ) -> None:
        if record.status not in TERMINAL_JOB_STATUSES:
            return
        self._connection.execute(
            """INSERT OR IGNORE INTO ingestion_lifecycle_outbox (
                   event_id, job_id, lifecycle_generation, status,
                   lifecycle_started_at, terminal_at, processing_seconds,
                   compute_cost_usd, usage_estimated, delivery_attempts
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            [
                _lifecycle_event_id(record.id, record.lifecycle_generation),
                record.id,
                record.lifecycle_generation,
                record.status.value,
                self._text(record.lifecycle_started_at),
                self._text(terminal_at),
                record.processing_seconds,
                record.compute_cost_usd,
                int(record.usage_estimated or force_estimated),
            ],
        )

    def _get_by_id(self, job_id: str) -> JobRecord | None:
        row = self._connection.execute(
            f"SELECT {_SELECT_COLUMNS} FROM ingestion_jobs WHERE id = ?",  # noqa: S608  # nosec B608
            [job_id],
        ).fetchone()
        return self._record(row) if row else None

    def enqueue(
        self,
        record: JobRecord,
        *,
        max_retained_jobs: int,
        max_retained_bytes: int,
    ) -> tuple[JobRecord, bool]:
        active_values = tuple(item.value for item in ACTIVE_JOB_STATUSES)
        placeholders = ",".join("?" for _ in active_values)
        retained_values = tuple(item.value for item in RETAINED_INPUT_STATUSES)
        retained_placeholders = ",".join("?" for _ in retained_values)
        with self._lock, self._transaction():
            duplicate = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs
                    WHERE tenant_id = ? AND sha256 = ? AND status IN ({placeholders})
                    ORDER BY created_at DESC LIMIT 1""",  # noqa: S608  # nosec B608
                [record.tenant_id, record.sha256, *active_values],
            ).fetchone()
            if duplicate:
                return self._record(duplicate), True
            usage = self._connection.execute(
                f"""SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM ingestion_jobs
                    WHERE tenant_id = ? AND (
                        status IN ({retained_placeholders}) OR input_cleanup_pending = 1
                    )""",  # noqa: S608  # nosec B608
                [record.tenant_id, *retained_values],
            ).fetchone()
            if usage and (
                int(usage[0]) + 1 > max_retained_jobs
                or int(usage[1]) + record.size_bytes > max_retained_bytes
            ):
                raise JobQueueFullError("Tenant ingestion queue quota exceeded")
            self._connection.execute(
                """INSERT INTO ingestion_jobs (
                       id, tenant_id, filename, source_uri, input_object_ref, sha256, size_bytes,
                       status, progress, stage, attempt_count, max_attempts, available_at,
                       lease_owner, lease_expires_at, cancel_requested, document_id, error_code,
                       input_cleanup_pending, delete_requested, lifecycle_started_at,
                       lifecycle_generation, processing_seconds, compute_cost_usd,
                       usage_estimated, current_attempt_started_at,
                       compute_cost_per_hour_usd, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                             ?, ?, ?, ?, ?, ?, ?)""",
                [
                    record.id,
                    record.tenant_id,
                    record.filename,
                    record.source_uri,
                    record.input_object_ref,
                    record.sha256,
                    record.size_bytes,
                    record.status.value,
                    record.progress,
                    record.stage,
                    record.attempt_count,
                    record.max_attempts,
                    self._text(record.available_at),
                    record.lease_owner,
                    self._text(record.lease_expires_at) if record.lease_expires_at else None,
                    int(record.cancel_requested),
                    record.document_id,
                    record.error_code,
                    int(record.input_cleanup_pending),
                    int(record.delete_requested),
                    self._text(record.lifecycle_started_at),
                    record.lifecycle_generation,
                    record.processing_seconds,
                    record.compute_cost_usd,
                    int(record.usage_estimated),
                    (
                        self._text(record.current_attempt_started_at)
                        if record.current_attempt_started_at
                        else None
                    ),
                    record.compute_cost_per_hour_usd,
                    self._text(record.created_at),
                    self._text(record.updated_at),
                ],
            )
        return record, False

    def claim(self, owner: str, *, now: datetime, lease_seconds: float) -> JobRecord | None:
        now_text = self._text(now)
        lease_until = self._text(datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC))
        with self._lock, self._transaction():
            row = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs AS candidate
                    WHERE candidate.status IN (?, ?) AND candidate.cancel_requested = 0
                      AND candidate.available_at <= ?
                      AND NOT EXISTS (
                          SELECT 1 FROM ingestion_jobs AS active
                          WHERE active.tenant_id = candidate.tenant_id
                            AND active.status IN (?, ?)
                      )
                    ORDER BY available_at, created_at, id LIMIT 1""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    now_text,
                    IngestionJobStatus.RUNNING.value,
                    IngestionJobStatus.CANCELLING.value,
                ],
            ).fetchone()
            if row is None:
                return None
            job_id = str(row["id"])
            changed = self._connection.execute(
                """UPDATE ingestion_jobs
                   SET status = ?, progress = MAX(progress, 5), stage = ?,
                       attempt_count = attempt_count + 1, lease_owner = ?,
                       lease_expires_at = ?, current_attempt_started_at = ?, updated_at = ?
                   WHERE id = ? AND status IN (?, ?) AND cancel_requested = 0""",
                [
                    IngestionJobStatus.RUNNING.value,
                    "claimed",
                    owner,
                    lease_until,
                    now_text,
                    now_text,
                    job_id,
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                ],
            ).rowcount
            if changed != 1:
                return None
            return self._get_by_id(job_id)

    def heartbeat(
        self,
        job_id: str,
        owner: str,
        *,
        progress: int,
        stage: str,
        now: datetime,
        lease_seconds: float,
    ) -> bool:
        lease_until = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC)
        with self._lock:
            changed = self._connection.execute(
                """UPDATE ingestion_jobs
                   SET progress = MAX(progress, ?), stage = ?, lease_expires_at = ?, updated_at = ?
                   WHERE id = ? AND lease_owner = ? AND status IN (?, ?)""",
                [
                    max(0, min(progress, 99)),
                    stage[:80],
                    self._text(lease_until),
                    self._text(now),
                    job_id,
                    owner,
                    IngestionJobStatus.RUNNING.value,
                    IngestionJobStatus.CANCELLING.value,
                ],
            ).rowcount
        return int(changed) == 1

    def cancellation_requested(self, job_id: str, owner: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                """SELECT cancel_requested FROM ingestion_jobs
                   WHERE id = ? AND lease_owner = ? AND status IN (?, ?)""",
                [
                    job_id,
                    owner,
                    IngestionJobStatus.RUNNING.value,
                    IngestionJobStatus.CANCELLING.value,
                ],
            ).fetchone()
        return row is None or bool(row[0])

    def succeed(
        self,
        job_id: str,
        owner: str,
        document_id: str,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        with self._lock, self._transaction():
            changed = self._connection.execute(
                """UPDATE ingestion_jobs SET status = ?, progress = 100, stage = ?,
                       document_id = ?, error_code = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + ?,
                       compute_cost_usd = compute_cost_usd + ?,
                       input_cleanup_pending = 1, updated_at = ?
                   WHERE id = ? AND lease_owner = ? AND status = ? AND cancel_requested = 0""",
                [
                    IngestionJobStatus.SUCCEEDED.value,
                    "completed",
                    document_id,
                    processing_seconds,
                    compute_cost_usd,
                    self._text(now),
                    job_id,
                    owner,
                    IngestionJobStatus.RUNNING.value,
                ],
            ).rowcount
            if int(changed) == 1:
                completed = self._get_by_id(job_id)
                if completed is None:
                    raise RuntimeError("Completed ingestion job disappeared")
                self._insert_lifecycle_event(completed, now)
        return int(changed) == 1

    def fail(
        self,
        job_id: str,
        owner: str,
        error_code: str,
        *,
        retryable: bool,
        retry_delay_seconds: float,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> JobRecord | None:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        with self._lock, self._transaction():
            current = self._get_by_id(job_id)
            if (
                current is None
                or current.lease_owner != owner
                or current.status
                not in {
                    IngestionJobStatus.RUNNING,
                    IngestionJobStatus.CANCELLING,
                }
            ):
                return None
            cancelled = current.cancel_requested
            retry = retryable and not cancelled and current.attempt_count < current.max_attempts
            if cancelled:
                status = IngestionJobStatus.CANCELLED
                stage = "cancelled"
                available_at = now
            elif retry:
                status = IngestionJobStatus.RETRY_WAIT
                stage = "retry_wait"
                available_at = datetime.fromtimestamp(
                    now.timestamp() + max(0.0, retry_delay_seconds), UTC
                )
            else:
                status = IngestionJobStatus.DEAD_LETTER
                stage = "dead_letter"
                available_at = now
            self._connection.execute(
                """UPDATE ingestion_jobs SET status = ?, stage = ?, available_at = ?,
                       error_code = ?, lease_owner = NULL, lease_expires_at = NULL,
                       current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + ?,
                       compute_cost_usd = compute_cost_usd + ?,
                       input_cleanup_pending = ?, updated_at = ?
                   WHERE id = ? AND lease_owner = ?""",
                [
                    status.value,
                    stage,
                    self._text(available_at),
                    error_code[:80],
                    processing_seconds,
                    compute_cost_usd,
                    int(cancelled),
                    self._text(now),
                    job_id,
                    owner,
                ],
            )
            updated = self._get_by_id(job_id)
            if updated is not None:
                self._insert_lifecycle_event(updated, now)
            return updated

    def mark_cancelled(
        self,
        job_id: str,
        owner: str | None,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        owner_clause = "AND lease_owner = ?" if owner else "AND lease_owner IS NULL"
        parameters: list[object] = [
            IngestionJobStatus.CANCELLED.value,
            "cancelled",
            processing_seconds,
            compute_cost_usd,
            self._text(now),
            job_id,
        ]
        if owner:
            parameters.append(owner)
        with self._lock, self._transaction():
            changed = self._connection.execute(
                f"""UPDATE ingestion_jobs SET status = ?, stage = ?, cancel_requested = 1,
                       lease_owner = NULL, lease_expires_at = NULL,
                       current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + ?,
                       compute_cost_usd = compute_cost_usd + ?,
                       input_cleanup_pending = 1, updated_at = ?
                   WHERE id = ? {owner_clause} AND status IN (?, ?, ?)""",  # noqa: S608  # nosec B608
                [
                    *parameters,
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RUNNING.value,
                    IngestionJobStatus.CANCELLING.value,
                ],
            ).rowcount
            if int(changed) == 1:
                cancelled = self._get_by_id(job_id)
                if cancelled is None:
                    raise RuntimeError("Cancelled ingestion job disappeared")
                self._insert_lifecycle_event(cancelled, now)
        return int(changed) == 1

    def request_cancel(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None:
        with self._lock, self._transaction():
            current = self._get_by_id(job_id)
            if current is None or current.tenant_id != tenant_id:
                return None
            if current.status in TERMINAL_JOB_STATUSES:
                return current
            if current.status in {IngestionJobStatus.QUEUED, IngestionJobStatus.RETRY_WAIT}:
                status = IngestionJobStatus.CANCELLED
                stage = "cancelled"
                lease_owner = None
                lease_expires_at = None
            else:
                status = IngestionJobStatus.CANCELLING
                stage = "cancelling"
                lease_owner = current.lease_owner
                lease_expires_at = current.lease_expires_at
            self._connection.execute(
                """UPDATE ingestion_jobs SET status = ?, stage = ?, cancel_requested = 1,
                       lease_owner = ?, lease_expires_at = ?,
                       input_cleanup_pending = ?, updated_at = ? WHERE id = ?""",
                [
                    status.value,
                    stage,
                    lease_owner,
                    self._text(lease_expires_at) if lease_expires_at else None,
                    int(status == IngestionJobStatus.CANCELLED),
                    self._text(now),
                    job_id,
                ],
            )
            updated = self._get_by_id(job_id)
            if updated is not None and updated.status == IngestionJobStatus.CANCELLED:
                self._insert_lifecycle_event(updated, now)
            return updated

    def request_cancel_all(self, tenant_id: str, *, now: datetime) -> list[JobRecord]:
        active_values = tuple(item.value for item in ACTIVE_JOB_STATUSES)
        placeholders = ",".join("?" for _ in active_values)
        now_text = self._text(now)
        with self._lock, self._transaction():
            rows = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs
                    WHERE tenant_id = ? AND status IN ({placeholders})""",  # noqa: S608  # nosec B608
                [tenant_id, *active_values],
            ).fetchall()
            current = [self._record(row) for row in rows]
            self._connection.execute(
                f"""UPDATE ingestion_jobs SET
                       status = CASE WHEN status IN (?, ?) THEN ? ELSE ? END,
                       stage = CASE WHEN status IN (?, ?) THEN ? ELSE ? END,
                       cancel_requested = 1,
                       lease_owner = CASE WHEN status IN (?, ?) THEN NULL ELSE lease_owner END,
                       lease_expires_at = CASE
                           WHEN status IN (?, ?) THEN NULL ELSE lease_expires_at END,
                       input_cleanup_pending = CASE
                           WHEN status IN (?, ?) THEN 1 ELSE input_cleanup_pending END,
                       updated_at = ?
                   WHERE tenant_id = ? AND status IN ({placeholders})""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    IngestionJobStatus.CANCELLED.value,
                    IngestionJobStatus.CANCELLING.value,
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    "cancelled",
                    "cancelling",
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    IngestionJobStatus.QUEUED.value,
                    IngestionJobStatus.RETRY_WAIT.value,
                    now_text,
                    tenant_id,
                    *active_values,
                ],
            )
            updated_records = [
                updated for record in current if (updated := self._get_by_id(record.id)) is not None
            ]
            for updated in updated_records:
                if updated.status == IngestionJobStatus.CANCELLED:
                    self._insert_lifecycle_event(updated, now)
            return updated_records

    def active_count(self, tenant_id: str) -> int:
        active_values = tuple(item.value for item in ACTIVE_JOB_STATUSES)
        placeholders = ",".join("?" for _ in active_values)
        with self._lock:
            row = self._connection.execute(
                f"""SELECT COUNT(*) FROM ingestion_jobs
                    WHERE tenant_id = ? AND status IN ({placeholders})""",  # noqa: S608  # nosec B608
                [tenant_id, *active_values],
            ).fetchone()
        return int(row[0]) if row else 0

    def retry(
        self,
        tenant_id: str,
        job_id: str,
        *,
        now: datetime,
        compute_cost_per_hour_usd: float | None = None,
    ) -> JobRecord | None:
        with self._lock, self._transaction():
            current = self._get_by_id(job_id)
            if (
                current is None
                or current.tenant_id != tenant_id
                or current.status != IngestionJobStatus.DEAD_LETTER
                or current.delete_requested
            ):
                return None
            rate = (
                current.compute_cost_per_hour_usd
                if compute_cost_per_hour_usd is None
                else compute_cost_per_hour_usd
            )
            _validated_usage(0.0, rate)
            self._connection.execute(
                """UPDATE ingestion_jobs SET status = ?, progress = 0, stage = ?,
                       attempt_count = 0, available_at = ?, lease_owner = NULL,
                       lease_expires_at = NULL, cancel_requested = 0, document_id = NULL,
                       error_code = NULL, input_cleanup_pending = 0,
                       delete_requested = 0, lifecycle_started_at = ?,
                       lifecycle_generation = lifecycle_generation + 1,
                       processing_seconds = 0, compute_cost_usd = 0, usage_estimated = 0,
                       current_attempt_started_at = NULL,
                       compute_cost_per_hour_usd = ?, updated_at = ? WHERE id = ?""",
                [
                    IngestionJobStatus.QUEUED.value,
                    "queued",
                    self._text(now),
                    self._text(now),
                    rate,
                    self._text(now),
                    job_id,
                ],
            )
            return self._get_by_id(job_id)

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None:
        with self._lock:
            record = self._get_by_id(job_id)
        return record if record and record.tenant_id == tenant_id else None

    def list(self, tenant_id: str, *, limit: int) -> list[JobRecord]:
        with self._lock:
            rows = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs WHERE tenant_id = ?
                    ORDER BY created_at DESC, id DESC LIMIT ?""",  # noqa: S608  # nosec B608
                [tenant_id, max(1, min(limit, 500))],
            ).fetchall()
        return [self._record(row) for row in rows]

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT status, COUNT(*) AS job_count FROM ingestion_jobs GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["job_count"]) for row in rows}

    def request_delete(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None:
        terminal_values = tuple(item.value for item in TERMINAL_JOB_STATUSES)
        placeholders = ",".join("?" for _ in terminal_values)
        with self._lock, self._transaction():
            changed = self._connection.execute(
                f"""UPDATE ingestion_jobs
                    SET delete_requested = 1, input_cleanup_pending = 1, updated_at = ?
                    WHERE tenant_id = ? AND id = ?
                      AND status IN ({placeholders})""",  # noqa: S608  # nosec B608
                [self._text(now), tenant_id, job_id, *terminal_values],
            ).rowcount
            return self._get_by_id(job_id) if int(changed) == 1 else None

    def cleanup_candidates(self, *, limit: int) -> builtins.list[JobRecord]:
        with self._lock:
            rows = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs
                    WHERE input_cleanup_pending = 1 OR delete_requested = 1
                    ORDER BY updated_at, id LIMIT ?""",  # noqa: S608  # nosec B608
                [max(1, min(limit, 500))],
            ).fetchall()
        return [self._record(row) for row in rows]

    def complete_input_cleanup(
        self, job_id: str, input_object_ref: str, *, now: datetime
    ) -> JobRecord | None:
        with self._lock, self._transaction():
            changed = self._connection.execute(
                """UPDATE ingestion_jobs SET input_cleanup_pending = 0, updated_at = ?
                   WHERE id = ? AND input_object_ref = ? AND input_cleanup_pending = 1""",
                [self._text(now), job_id, input_object_ref],
            ).rowcount
            return self._get_by_id(job_id) if int(changed) == 1 else None

    def delete_terminal(self, tenant_id: str, job_id: str) -> JobRecord | None:
        terminal_values = tuple(item.value for item in TERMINAL_JOB_STATUSES)
        placeholders = ",".join("?" for _ in terminal_values)
        with self._lock, self._transaction():
            current = self._get_by_id(job_id)
            if (
                current is None
                or current.tenant_id != tenant_id
                or current.status not in TERMINAL_JOB_STATUSES
                or not current.delete_requested
                or current.input_cleanup_pending
            ):
                return None
            self._connection.execute(
                f"""DELETE FROM ingestion_jobs WHERE id = ?
                    AND status IN ({placeholders}) AND delete_requested = 1
                    AND input_cleanup_pending = 0""",  # noqa: S608  # nosec B608
                [job_id, *terminal_values],
            )
            return current

    def schedule_orphan_cleanup(self, input_object_ref: str, *, now: datetime) -> None:
        now_text = self._text(now)
        with self._lock:
            self._connection.execute(
                """INSERT INTO ingestion_orphan_cleanup (
                       input_object_ref, attempt_count, last_error, created_at, updated_at
                   ) VALUES (?, 0, NULL, ?, ?)
                   ON CONFLICT(input_object_ref) DO UPDATE SET updated_at = excluded.updated_at""",
                [input_object_ref, now_text, now_text],
            )

    def orphan_cleanup_candidates(self, *, limit: int) -> builtins.list[str]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT input_object_ref FROM ingestion_orphan_cleanup
                   ORDER BY updated_at, input_object_ref LIMIT ?""",
                [max(1, min(limit, 500))],
            ).fetchall()
        return [str(row[0]) for row in rows]

    def record_orphan_cleanup_failure(
        self, input_object_ref: str, error_code: str, *, now: datetime
    ) -> None:
        with self._lock:
            self._connection.execute(
                """UPDATE ingestion_orphan_cleanup
                   SET attempt_count = attempt_count + 1, last_error = ?, updated_at = ?
                   WHERE input_object_ref = ?""",
                [error_code[:80], self._text(now), input_object_ref],
            )

    def complete_orphan_cleanup(self, input_object_ref: str) -> bool:
        with self._lock:
            changed = self._connection.execute(
                "DELETE FROM ingestion_orphan_cleanup WHERE input_object_ref = ?",
                [input_object_ref],
            ).rowcount
        return int(changed) == 1

    def recover_expired(self, *, now: datetime) -> int:
        now_text = self._text(now)
        with self._lock, self._transaction():
            rows = self._connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM ingestion_jobs
                    WHERE status IN (?, ?)
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.RUNNING.value,
                    IngestionJobStatus.CANCELLING.value,
                    now_text,
                ],
            ).fetchall()
            recovered = 0
            for row in rows:
                current = self._record(row)
                processing_seconds, compute_cost_usd = _expired_attempt_usage(current, now)
                if current.cancel_requested:
                    status = IngestionJobStatus.CANCELLED
                    error_code = "WORKER_LEASE_EXPIRED_AFTER_CANCEL"
                elif current.attempt_count < current.max_attempts:
                    status = IngestionJobStatus.RETRY_WAIT
                    error_code = "WORKER_LEASE_EXPIRED"
                else:
                    status = IngestionJobStatus.DEAD_LETTER
                    error_code = "WORKER_LEASE_EXPIRED"
                changed = self._connection.execute(
                    """UPDATE ingestion_jobs SET status = ?, stage = ?, available_at = ?,
                           lease_owner = NULL, lease_expires_at = NULL,
                           current_attempt_started_at = NULL, error_code = ?,
                           processing_seconds = processing_seconds + ?,
                           compute_cost_usd = compute_cost_usd + ?,
                           usage_estimated = 1,
                           input_cleanup_pending = CASE
                             WHEN ? THEN 1 ELSE input_cleanup_pending END,
                           updated_at = ? WHERE id = ? AND status IN (?, ?)""",
                    [
                        status.value,
                        status.value,
                        now_text,
                        error_code,
                        processing_seconds,
                        compute_cost_usd,
                        int(status == IngestionJobStatus.CANCELLED),
                        now_text,
                        current.id,
                        IngestionJobStatus.RUNNING.value,
                        IngestionJobStatus.CANCELLING.value,
                    ],
                ).rowcount
                if int(changed) != 1:
                    continue
                recovered += 1
                updated = self._get_by_id(current.id)
                if updated is not None:
                    self._insert_lifecycle_event(updated, now)
        return recovered

    def claim_lifecycle_events(
        self,
        owner: str,
        *,
        now: datetime,
        lease_seconds: float,
        limit: int,
    ) -> builtins.list[IngestionLifecycleEvent]:
        if lease_seconds <= 0 or not math.isfinite(lease_seconds):
            raise ValueError("Lifecycle delivery lease must be finite and positive")
        bounded_limit = max(1, min(limit, 500))
        now_text = self._text(now)
        lease_until = self._text(datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC))
        with self._lock, self._transaction():
            rows = self._connection.execute(
                """SELECT event_id FROM ingestion_lifecycle_outbox
                   WHERE delivered_at IS NULL
                     AND (delivery_lease_expires_at IS NULL OR delivery_lease_expires_at <= ?)
                   ORDER BY terminal_at, event_id LIMIT ?""",
                [now_text, bounded_limit],
            ).fetchall()
            events: builtins.list[IngestionLifecycleEvent] = []
            for row in rows:
                event_id = str(row["event_id"])
                changed = self._connection.execute(
                    """UPDATE ingestion_lifecycle_outbox
                       SET delivery_owner = ?, delivery_lease_expires_at = ?,
                           delivery_attempts = delivery_attempts + 1
                       WHERE event_id = ? AND delivered_at IS NULL
                         AND (delivery_lease_expires_at IS NULL
                              OR delivery_lease_expires_at <= ?)""",
                    [owner, lease_until, event_id, now_text],
                ).rowcount
                if int(changed) != 1:
                    continue
                claimed = self._connection.execute(
                    f"""SELECT {_OUTBOX_SELECT_COLUMNS} FROM ingestion_lifecycle_outbox
                        WHERE event_id = ? AND delivery_owner = ?""",  # noqa: S608  # nosec B608
                    [event_id, owner],
                ).fetchone()
                if claimed is not None:
                    events.append(self._lifecycle_event(claimed))
        return events

    def complete_lifecycle_event(self, event_id: str, owner: str, *, now: datetime) -> bool:
        with self._lock:
            changed = self._connection.execute(
                """UPDATE ingestion_lifecycle_outbox
                   SET delivered_at = ?, delivery_owner = NULL,
                       delivery_lease_expires_at = NULL
                   WHERE event_id = ? AND delivery_owner = ? AND delivered_at IS NULL""",
                [self._text(now), event_id, owner],
            ).rowcount
        return int(changed) == 1

    def lifecycle_outbox_stats(self, *, now: datetime) -> tuple[int, float]:
        """Return global pending count and oldest age for a worker-owned gauge."""

        with self._lock:
            row = self._connection.execute(
                """SELECT COUNT(*), MIN(terminal_at)
                   FROM ingestion_lifecycle_outbox WHERE delivered_at IS NULL"""
            ).fetchone()
        count = int(row[0]) if row else 0
        if count == 0:
            return (0, 0.0)
        oldest = self._required_time(row[1]) if row and row[1] is not None else None
        if oldest is None:
            raise RuntimeError("Pending lifecycle outbox timestamp is unavailable")
        return (count, max(0.0, (now - oldest).total_seconds()))

    def prune_delivered_lifecycle_events(self, *, before: datetime, limit: int) -> int:
        """Delete only old acknowledged events with a bounded batch size."""

        bounded_limit = max(1, min(limit, 500))
        with self._lock, self._transaction():
            changed = self._connection.execute(
                """DELETE FROM ingestion_lifecycle_outbox WHERE event_id IN (
                       SELECT event_id FROM ingestion_lifecycle_outbox
                       WHERE delivered_at IS NOT NULL AND delivered_at < ?
                       ORDER BY delivered_at, event_id LIMIT ?
                   )""",
                [self._text(before), bounded_limit],
            ).rowcount
        return int(changed)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class PostgresIngestionJobStore:
    """Shared production queue using row locks with ``SKIP LOCKED`` claims."""

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int,
        max_size: int,
        timeout_seconds: float,
        rls_enabled: bool = False,
        migrate_on_startup: bool = True,
    ) -> None:
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            timeout=timeout_seconds,
            kwargs={"row_factory": dict_row},
            open=True,
        )
        self._rls_enabled = rls_enabled
        if migrate_on_startup:
            with self._pool.connection() as connection, connection.transaction():
                connection.execute("SELECT pg_advisory_xact_lock(%s)", [MIGRATION_LOCK])
                # Keep direct construction useful in local/test profiles while production
                # runtimes always take the validate-only path through the factory.
                apply_metadata_migrations(connection)
                apply_job_migrations(connection)
        else:
            with self._pool.connection() as connection:
                verify_postgres_schema(connection)

    @contextmanager
    def _tenant_connection(self, tenant_id: str) -> Iterator[Any]:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise ValueError("Tenant identifier is invalid")
        with self._pool.connection() as connection, connection.transaction():
            if getattr(self, "_rls_enabled", False):
                connection.execute(
                    "SELECT set_config('crisisweave.tenant_id', %s, true)", [tenant_id]
                )
            yield connection

    @staticmethod
    def _record(row: dict[str, object]) -> JobRecord:
        values = dict(row)
        values["id"] = str(values["id"])
        if values.get("document_id") is not None:
            values["document_id"] = str(values["document_id"])
        return JobRecord.model_validate(values)

    @staticmethod
    def _lifecycle_event(row: dict[str, object]) -> IngestionLifecycleEvent:
        values = dict(row)
        values["event_id"] = str(values["event_id"])
        return IngestionLifecycleEvent.model_validate(values)

    @staticmethod
    def _insert_lifecycle_event(
        connection: Any,
        record: JobRecord,
        terminal_at: datetime,
        *,
        force_estimated: bool = False,
    ) -> None:
        if record.status not in TERMINAL_JOB_STATUSES:
            return
        connection.execute(
            """INSERT INTO crisisweave.ingestion_lifecycle_outbox (
                   event_id, job_id, lifecycle_generation, status,
                   lifecycle_started_at, terminal_at, processing_seconds, compute_cost_usd,
                   usage_estimated
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (job_id, lifecycle_generation) DO NOTHING""",
            [
                _lifecycle_event_id(record.id, record.lifecycle_generation),
                record.id,
                record.lifecycle_generation,
                record.status.value,
                record.lifecycle_started_at,
                terminal_at,
                record.processing_seconds,
                record.compute_cost_usd,
                record.usage_estimated or force_estimated,
            ],
        )

    def enqueue(
        self,
        record: JobRecord,
        *,
        max_retained_jobs: int,
        max_retained_bytes: int,
    ) -> tuple[JobRecord, bool]:
        active = [item.value for item in ACTIVE_JOB_STATUSES]
        retained = [item.value for item in RETAINED_INPUT_STATUSES]
        with self._tenant_connection(record.tenant_id) as connection:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                [record.tenant_id],
            )
            duplicate = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                    WHERE tenant_id = %s AND sha256 = %s AND status = ANY(%s)
                    ORDER BY created_at DESC LIMIT 1 FOR UPDATE""",  # noqa: S608  # nosec B608
                [record.tenant_id, record.sha256, active],
            ).fetchone()
            if duplicate:
                return self._record(duplicate), True
            usage = connection.execute(
                """SELECT COUNT(*) AS job_count, COALESCE(SUM(size_bytes), 0) AS job_bytes
                   FROM crisisweave.ingestion_jobs
                   WHERE tenant_id = %s
                     AND (status = ANY(%s) OR input_cleanup_pending = TRUE)""",
                [record.tenant_id, retained],
            ).fetchone()
            if usage and (
                int(usage["job_count"]) + 1 > max_retained_jobs
                or int(usage["job_bytes"]) + record.size_bytes > max_retained_bytes
            ):
                raise JobQueueFullError("Tenant ingestion queue quota exceeded")
            row = connection.execute(
                f"""INSERT INTO crisisweave.ingestion_jobs ({_SELECT_COLUMNS})
                   VALUES (
                       %(id)s, %(tenant_id)s, %(filename)s, %(source_uri)s,
                       %(input_object_ref)s, %(sha256)s, %(size_bytes)s, %(status)s,
                       %(progress)s, %(stage)s, %(attempt_count)s, %(max_attempts)s,
                       %(available_at)s, %(lease_owner)s, %(lease_expires_at)s,
                       %(cancel_requested)s, %(document_id)s, %(error_code)s,
                       %(input_cleanup_pending)s, %(delete_requested)s,
                       %(lifecycle_started_at)s, %(lifecycle_generation)s,
                       %(processing_seconds)s, %(compute_cost_usd)s,
                       %(usage_estimated)s, %(current_attempt_started_at)s,
                       %(compute_cost_per_hour_usd)s,
                       %(created_at)s, %(updated_at)s
                   ) RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                record.model_dump(mode="python"),
            ).fetchone()
            if row is None:
                raise RuntimeError("PostgreSQL did not return the enqueued job")
            return self._record(row), False

    def claim(self, owner: str, *, now: datetime, lease_seconds: float) -> JobRecord | None:
        lease_until = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC)
        with self._pool.connection() as connection, connection.transaction():
            selected_raw = connection.execute(
                """SELECT candidate.id, candidate.tenant_id
                   FROM crisisweave.ingestion_jobs AS candidate
                   WHERE candidate.status = ANY(%s)
                     AND candidate.cancel_requested = FALSE
                     AND candidate.available_at <= %s
                     AND NOT EXISTS (
                         SELECT 1 FROM crisisweave.ingestion_jobs AS active
                         WHERE active.tenant_id = candidate.tenant_id
                           AND active.status IN ('running', 'cancelling')
                     )
                   ORDER BY candidate.available_at, candidate.created_at, candidate.id
                   LIMIT 1 FOR UPDATE OF candidate SKIP LOCKED""",
                [
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    now,
                ],
            ).fetchone()
            if selected_raw is None:
                return None
            selected = cast(dict[str, object], selected_raw)
            tenant_lock_raw = connection.execute(
                """SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))
                          AS acquired""",
                [selected["tenant_id"]],
            ).fetchone()
            tenant_lock = cast(dict[str, object] | None, tenant_lock_raw)
            if tenant_lock is None or not bool(tenant_lock["acquired"]):
                return None
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs SET status = %s,
                       progress = GREATEST(progress, 5), stage = %s,
                       attempt_count = attempt_count + 1, lease_owner = %s,
                       lease_expires_at = %s, current_attempt_started_at = %s,
                       updated_at = %s
                   WHERE id = %s AND status = ANY(%s) AND cancel_requested = FALSE
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.RUNNING.value,
                    "claimed",
                    owner,
                    lease_until,
                    now,
                    now,
                    selected["id"],
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                ],
            ).fetchone()
            return self._record(cast(dict[str, object], row)) if row else None

    def heartbeat(
        self,
        job_id: str,
        owner: str,
        *,
        progress: int,
        stage: str,
        now: datetime,
        lease_seconds: float,
    ) -> bool:
        lease_until = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC)
        with self._pool.connection() as connection:
            changed = connection.execute(
                """UPDATE crisisweave.ingestion_jobs
                   SET progress = GREATEST(progress, %s), stage = %s,
                       lease_expires_at = %s, updated_at = %s
                   WHERE id = %s AND lease_owner = %s AND status = ANY(%s)""",
                [
                    max(0, min(progress, 99)),
                    stage[:80],
                    lease_until,
                    now,
                    job_id,
                    owner,
                    [IngestionJobStatus.RUNNING.value, IngestionJobStatus.CANCELLING.value],
                ],
            ).rowcount
        return int(changed) == 1

    def cancellation_requested(self, job_id: str, owner: str) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """SELECT cancel_requested FROM crisisweave.ingestion_jobs
                   WHERE id = %s AND lease_owner = %s AND status = ANY(%s)""",
                [
                    job_id,
                    owner,
                    [IngestionJobStatus.RUNNING.value, IngestionJobStatus.CANCELLING.value],
                ],
            ).fetchone()
        typed_row = cast(dict[str, object] | None, row)
        return typed_row is None or bool(typed_row["cancel_requested"])

    def succeed(
        self,
        job_id: str,
        owner: str,
        document_id: str,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs
                   SET status = %s, progress = 100, stage = %s,
                       document_id = %s, error_code = NULL, lease_owner = NULL,
                       lease_expires_at = NULL, current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + %s,
                       compute_cost_usd = compute_cost_usd + %s,
                       input_cleanup_pending = TRUE,
                       updated_at = %s
                   WHERE id = %s AND lease_owner = %s AND status = %s
                     AND cancel_requested = FALSE
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.SUCCEEDED.value,
                    "completed",
                    document_id,
                    processing_seconds,
                    compute_cost_usd,
                    now,
                    job_id,
                    owner,
                    IngestionJobStatus.RUNNING.value,
                ],
            ).fetchone()
            if row is None:
                return False
            completed = self._record(cast(dict[str, object], row))
            self._insert_lifecycle_event(connection, completed, now)
            return True

    def fail(
        self,
        job_id: str,
        owner: str,
        error_code: str,
        *,
        retryable: bool,
        retry_delay_seconds: float,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> JobRecord | None:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        with self._pool.connection() as connection, connection.transaction():
            current_row = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE id = %s FOR UPDATE""",  # noqa: S608  # nosec B608
                [job_id],
            ).fetchone()
            if current_row is None:
                return None
            current = self._record(cast(dict[str, object], current_row))
            if current.lease_owner != owner or current.status not in {
                IngestionJobStatus.RUNNING,
                IngestionJobStatus.CANCELLING,
            }:
                return None
            retry = (
                retryable
                and not current.cancel_requested
                and current.attempt_count < current.max_attempts
            )
            if current.cancel_requested:
                status = IngestionJobStatus.CANCELLED
                stage = "cancelled"
                available_at = now
            elif retry:
                status = IngestionJobStatus.RETRY_WAIT
                stage = "retry_wait"
                available_at = datetime.fromtimestamp(
                    now.timestamp() + max(0.0, retry_delay_seconds), UTC
                )
            else:
                status = IngestionJobStatus.DEAD_LETTER
                stage = "dead_letter"
                available_at = now
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs
                   SET status = %s, stage = %s, available_at = %s,
                       error_code = %s, lease_owner = NULL, lease_expires_at = NULL,
                       current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + %s,
                       compute_cost_usd = compute_cost_usd + %s,
                       input_cleanup_pending = %s,
                       updated_at = %s WHERE id = %s AND lease_owner = %s
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [
                    status.value,
                    stage,
                    available_at,
                    error_code[:80],
                    processing_seconds,
                    compute_cost_usd,
                    current.cancel_requested,
                    now,
                    job_id,
                    owner,
                ],
            ).fetchone()
            updated = self._record(cast(dict[str, object], row)) if row else None
            if updated is not None:
                self._insert_lifecycle_event(connection, updated, now)
            return updated

    def mark_cancelled(
        self,
        job_id: str,
        owner: str | None,
        *,
        now: datetime,
        processing_seconds: float = 0.0,
        compute_cost_usd: float = 0.0,
    ) -> bool:
        processing_seconds, compute_cost_usd = _validated_usage(
            processing_seconds, compute_cost_usd
        )
        owner_sql = "lease_owner = %s" if owner else "lease_owner IS NULL"
        parameters: list[object] = [
            IngestionJobStatus.CANCELLED.value,
            "cancelled",
            processing_seconds,
            compute_cost_usd,
            now,
            job_id,
        ]
        if owner:
            parameters.append(owner)
        parameters.append(
            [
                IngestionJobStatus.QUEUED.value,
                IngestionJobStatus.RUNNING.value,
                IngestionJobStatus.CANCELLING.value,
            ]
        )
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs SET status = %s, stage = %s,
                       cancel_requested = TRUE, lease_owner = NULL,
                       lease_expires_at = NULL, current_attempt_started_at = NULL,
                       processing_seconds = processing_seconds + %s,
                       compute_cost_usd = compute_cost_usd + %s,
                       input_cleanup_pending = TRUE,
                       updated_at = %s
                   WHERE id = %s AND {owner_sql} AND status = ANY(%s)
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                parameters,
            ).fetchone()
            if row is None:
                return False
            cancelled = self._record(cast(dict[str, object], row))
            self._insert_lifecycle_event(connection, cancelled, now)
            return True

    def request_cancel(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE id = %s AND tenant_id = %s FOR UPDATE""",  # noqa: S608  # nosec B608
                [job_id, tenant_id],
            ).fetchone()
            if row is None:
                return None
            current = self._record(row)
            if current.status in TERMINAL_JOB_STATUSES:
                return current
            queued = current.status in {
                IngestionJobStatus.QUEUED,
                IngestionJobStatus.RETRY_WAIT,
            }
            status = IngestionJobStatus.CANCELLED if queued else IngestionJobStatus.CANCELLING
            stage = "cancelled" if queued else "cancelling"
            updated = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs SET status = %s, stage = %s,
                       cancel_requested = TRUE,
                       lease_owner = CASE WHEN %s THEN NULL ELSE lease_owner END,
                       lease_expires_at = CASE WHEN %s THEN NULL ELSE lease_expires_at END,
                       input_cleanup_pending = CASE
                           WHEN %s THEN TRUE ELSE input_cleanup_pending END,
                       updated_at = %s WHERE id = %s
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [status.value, stage, queued, queued, queued, now, job_id],
            ).fetchone()
            record = self._record(updated) if updated else None
            if record is not None:
                self._insert_lifecycle_event(connection, record, now)
            return record

    def request_cancel_all(self, tenant_id: str, *, now: datetime) -> list[JobRecord]:
        active = [item.value for item in ACTIVE_JOB_STATUSES]
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs SET
                       status = CASE WHEN status = ANY(%s) THEN %s ELSE %s END,
                       stage = CASE WHEN status = ANY(%s) THEN %s ELSE %s END,
                       cancel_requested = TRUE,
                       lease_owner = CASE WHEN status = ANY(%s) THEN NULL ELSE lease_owner END,
                       lease_expires_at = CASE
                           WHEN status = ANY(%s) THEN NULL ELSE lease_expires_at END,
                       input_cleanup_pending = CASE WHEN status = ANY(%s)
                           THEN TRUE ELSE input_cleanup_pending END,
                       updated_at = %s
                   WHERE tenant_id = %s AND status = ANY(%s)
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    IngestionJobStatus.CANCELLED.value,
                    IngestionJobStatus.CANCELLING.value,
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    "cancelled",
                    "cancelling",
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    [IngestionJobStatus.QUEUED.value, IngestionJobStatus.RETRY_WAIT.value],
                    now,
                    tenant_id,
                    active,
                ],
            ).fetchall()
            records = [self._record(cast(dict[str, object], row)) for row in rows]
            for record in records:
                self._insert_lifecycle_event(connection, record, now)
        return records

    def active_count(self, tenant_id: str) -> int:
        active = [item.value for item in ACTIVE_JOB_STATUSES]
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                """SELECT COUNT(*) AS job_count FROM crisisweave.ingestion_jobs
                   WHERE tenant_id = %s AND status = ANY(%s)""",
                [tenant_id, active],
            ).fetchone()
        return int(row["job_count"]) if row else 0

    def retry(
        self,
        tenant_id: str,
        job_id: str,
        *,
        now: datetime,
        compute_cost_per_hour_usd: float | None = None,
    ) -> JobRecord | None:
        with self._tenant_connection(tenant_id) as connection:
            current_row = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE id = %s AND tenant_id = %s AND status = %s
                     AND delete_requested = FALSE FOR UPDATE""",  # noqa: S608  # nosec B608
                [job_id, tenant_id, IngestionJobStatus.DEAD_LETTER.value],
            ).fetchone()
            if current_row is None:
                return None
            current = self._record(cast(dict[str, object], current_row))
            rate = (
                current.compute_cost_per_hour_usd
                if compute_cost_per_hour_usd is None
                else compute_cost_per_hour_usd
            )
            _validated_usage(0.0, rate)
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs
                   SET status = %s, progress = 0, stage = %s,
                       attempt_count = 0, available_at = %s, lease_owner = NULL,
                       lease_expires_at = NULL, cancel_requested = FALSE, document_id = NULL,
                       error_code = NULL, input_cleanup_pending = FALSE,
                       delete_requested = FALSE, lifecycle_started_at = %s,
                       lifecycle_generation = lifecycle_generation + 1,
                       processing_seconds = 0, compute_cost_usd = 0,
                       usage_estimated = FALSE,
                       current_attempt_started_at = NULL,
                       compute_cost_per_hour_usd = %s, updated_at = %s
                   WHERE id = %s AND tenant_id = %s AND status = %s
                     AND delete_requested = FALSE
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [
                    IngestionJobStatus.QUEUED.value,
                    "queued",
                    now,
                    now,
                    rate,
                    now,
                    job_id,
                    tenant_id,
                    IngestionJobStatus.DEAD_LETTER.value,
                ],
            ).fetchone()
        return self._record(cast(dict[str, object], row)) if row else None

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE tenant_id = %s AND id = %s""",  # noqa: S608  # nosec B608
                [tenant_id, job_id],
            ).fetchone()
        return self._record(cast(dict[str, object], row)) if row else None

    def list(self, tenant_id: str, *, limit: int) -> list[JobRecord]:
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE tenant_id = %s
                   ORDER BY created_at DESC, id DESC LIMIT %s""",  # noqa: S608  # nosec B608
                [tenant_id, max(1, min(limit, 500))],
            ).fetchall()
        return [self._record(cast(dict[str, object], row)) for row in rows]

    def status_counts(self) -> dict[str, int]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """SELECT status, COUNT(*) AS job_count
                   FROM crisisweave.ingestion_jobs GROUP BY status"""
            ).fetchall()
        return {
            str(row["status"]): cast(int, row["job_count"])
            for row in cast(list[dict[str, object]], rows)
        }

    def request_delete(self, tenant_id: str, job_id: str, *, now: datetime) -> JobRecord | None:
        terminal = [item.value for item in TERMINAL_JOB_STATUSES]
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs
                   SET delete_requested = TRUE, input_cleanup_pending = TRUE, updated_at = %s
                   WHERE tenant_id = %s AND id = %s AND status = ANY(%s)
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [now, tenant_id, job_id, terminal],
            ).fetchone()
        return self._record(cast(dict[str, object], row)) if row else None

    def cleanup_candidates(self, *, limit: int) -> builtins.list[JobRecord]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE input_cleanup_pending = TRUE OR delete_requested = TRUE
                   ORDER BY updated_at, id LIMIT %s""",  # noqa: S608  # nosec B608
                [max(1, min(limit, 500))],
            ).fetchall()
        return [self._record(cast(dict[str, object], row)) for row in rows]

    def complete_input_cleanup(
        self, job_id: str, input_object_ref: str, *, now: datetime
    ) -> JobRecord | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"""UPDATE crisisweave.ingestion_jobs
                   SET input_cleanup_pending = FALSE, updated_at = %s
                   WHERE id = %s AND input_object_ref = %s
                     AND input_cleanup_pending = TRUE
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [now, job_id, input_object_ref],
            ).fetchone()
        return self._record(cast(dict[str, object], row)) if row else None

    def delete_terminal(self, tenant_id: str, job_id: str) -> JobRecord | None:
        terminal = [item.value for item in TERMINAL_JOB_STATUSES]
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""DELETE FROM crisisweave.ingestion_jobs
                   WHERE tenant_id = %s AND id = %s
                   AND status = ANY(%s) AND delete_requested = TRUE
                   AND input_cleanup_pending = FALSE
                   RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [tenant_id, job_id, terminal],
            ).fetchone()
        return self._record(row) if row else None

    def schedule_orphan_cleanup(self, input_object_ref: str, *, now: datetime) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """INSERT INTO crisisweave.ingestion_orphan_cleanup (
                       input_object_ref, attempt_count, last_error, created_at, updated_at
                   ) VALUES (%s, 0, NULL, %s, %s)
                   ON CONFLICT (input_object_ref) DO UPDATE
                   SET updated_at = EXCLUDED.updated_at""",
                [input_object_ref, now, now],
            )

    def orphan_cleanup_candidates(self, *, limit: int) -> builtins.list[str]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """SELECT input_object_ref
                   FROM crisisweave.ingestion_orphan_cleanup
                   ORDER BY updated_at, input_object_ref LIMIT %s""",
                [max(1, min(limit, 500))],
            ).fetchall()
        return [str(cast(dict[str, object], row)["input_object_ref"]) for row in rows]

    def record_orphan_cleanup_failure(
        self, input_object_ref: str, error_code: str, *, now: datetime
    ) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                """UPDATE crisisweave.ingestion_orphan_cleanup
                   SET attempt_count = attempt_count + 1,
                       last_error = %s, updated_at = %s
                   WHERE input_object_ref = %s""",
                [error_code[:80], now, input_object_ref],
            )

    def complete_orphan_cleanup(self, input_object_ref: str) -> bool:
        with self._pool.connection() as connection:
            changed = connection.execute(
                """DELETE FROM crisisweave.ingestion_orphan_cleanup
                   WHERE input_object_ref = %s""",
                [input_object_ref],
            ).rowcount
        return int(changed) == 1

    def recover_expired(self, *, now: datetime) -> int:
        with self._pool.connection() as connection, connection.transaction():
            rows = connection.execute(
                f"""SELECT {_SELECT_COLUMNS} FROM crisisweave.ingestion_jobs
                   WHERE status = ANY(%s)
                     AND (lease_expires_at IS NULL OR lease_expires_at <= %s)
                   FOR UPDATE SKIP LOCKED""",  # noqa: S608  # nosec B608
                [
                    [IngestionJobStatus.RUNNING.value, IngestionJobStatus.CANCELLING.value],
                    now,
                ],
            ).fetchall()
            recovered = 0
            for raw in rows:
                current = self._record(cast(dict[str, object], raw))
                processing_seconds, compute_cost_usd = _expired_attempt_usage(current, now)
                if current.cancel_requested:
                    status = IngestionJobStatus.CANCELLED
                    error_code = "WORKER_LEASE_EXPIRED_AFTER_CANCEL"
                elif current.attempt_count < current.max_attempts:
                    status = IngestionJobStatus.RETRY_WAIT
                    error_code = "WORKER_LEASE_EXPIRED"
                else:
                    status = IngestionJobStatus.DEAD_LETTER
                    error_code = "WORKER_LEASE_EXPIRED"
                updated_row = connection.execute(
                    f"""UPDATE crisisweave.ingestion_jobs
                       SET status = %s, stage = %s, available_at = %s,
                           lease_owner = NULL, lease_expires_at = NULL,
                           current_attempt_started_at = NULL, error_code = %s,
                           processing_seconds = processing_seconds + %s,
                           compute_cost_usd = compute_cost_usd + %s,
                           usage_estimated = TRUE,
                           input_cleanup_pending = CASE
                             WHEN %s THEN TRUE ELSE input_cleanup_pending END,
                           updated_at = %s
                       WHERE id = %s AND status = ANY(%s)
                       RETURNING {_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                    [
                        status.value,
                        status.value,
                        now,
                        error_code,
                        processing_seconds,
                        compute_cost_usd,
                        status == IngestionJobStatus.CANCELLED,
                        now,
                        current.id,
                        [IngestionJobStatus.RUNNING.value, IngestionJobStatus.CANCELLING.value],
                    ],
                ).fetchone()
                if updated_row is None:
                    continue
                recovered += 1
                updated = self._record(cast(dict[str, object], updated_row))
                self._insert_lifecycle_event(connection, updated, now)
        return recovered

    def claim_lifecycle_events(
        self,
        owner: str,
        *,
        now: datetime,
        lease_seconds: float,
        limit: int,
    ) -> builtins.list[IngestionLifecycleEvent]:
        if lease_seconds <= 0 or not math.isfinite(lease_seconds):
            raise ValueError("Lifecycle delivery lease must be finite and positive")
        lease_until = datetime.fromtimestamp(now.timestamp() + lease_seconds, UTC)
        with self._pool.connection() as connection, connection.transaction():
            rows = connection.execute(
                f"""WITH candidates AS (
                       SELECT event_id FROM crisisweave.ingestion_lifecycle_outbox
                       WHERE delivered_at IS NULL AND (
                           delivery_lease_expires_at IS NULL OR delivery_lease_expires_at <= %s
                       ) ORDER BY terminal_at, event_id
                       LIMIT %s FOR UPDATE SKIP LOCKED
                   ) UPDATE crisisweave.ingestion_lifecycle_outbox AS lifecycle
                     SET delivery_owner = %s, delivery_lease_expires_at = %s,
                         delivery_attempts = lifecycle.delivery_attempts + 1
                   FROM candidates WHERE lifecycle.event_id = candidates.event_id
                   RETURNING {_OUTBOX_SELECT_COLUMNS}""",  # noqa: S608  # nosec B608
                [now, max(1, min(limit, 500)), owner, lease_until],
            ).fetchall()
        return [self._lifecycle_event(cast(dict[str, object], row)) for row in rows]

    def complete_lifecycle_event(self, event_id: str, owner: str, *, now: datetime) -> bool:
        with self._pool.connection() as connection:
            changed = connection.execute(
                """UPDATE crisisweave.ingestion_lifecycle_outbox
                   SET delivered_at = %s, delivery_owner = NULL,
                       delivery_lease_expires_at = NULL
                   WHERE event_id = %s AND delivery_owner = %s AND delivered_at IS NULL""",
                [now, event_id, owner],
            ).rowcount
        return int(changed) == 1

    def lifecycle_outbox_stats(self, *, now: datetime) -> tuple[int, float]:
        """Return global pending count and oldest age for a worker-owned gauge."""

        with self._pool.connection() as connection:
            raw = connection.execute(
                """SELECT COUNT(*) AS pending_count, MIN(terminal_at) AS oldest_terminal_at
                   FROM crisisweave.ingestion_lifecycle_outbox
                   WHERE delivered_at IS NULL"""
            ).fetchone()
        row = cast(dict[str, object] | None, raw)
        count_value = row.get("pending_count") if row else 0
        if isinstance(count_value, bool) or not isinstance(count_value, int) or count_value < 0:
            raise RuntimeError("Pending lifecycle outbox count is unavailable")
        count = count_value
        if count == 0:
            return (0, 0.0)
        oldest = row.get("oldest_terminal_at") if row else None
        if not isinstance(oldest, datetime):
            raise RuntimeError("Pending lifecycle outbox timestamp is unavailable")
        return (count, max(0.0, (now - oldest).total_seconds()))

    def prune_delivered_lifecycle_events(self, *, before: datetime, limit: int) -> int:
        """Delete only old acknowledged events with a bounded locking batch."""

        with self._pool.connection() as connection:
            changed = connection.execute(
                """WITH expired AS (
                       SELECT event_id FROM crisisweave.ingestion_lifecycle_outbox
                       WHERE delivered_at IS NOT NULL AND delivered_at < %s
                       ORDER BY delivered_at, event_id
                       LIMIT %s FOR UPDATE SKIP LOCKED
                   ) DELETE FROM crisisweave.ingestion_lifecycle_outbox AS lifecycle
                     USING expired WHERE lifecycle.event_id = expired.event_id""",
                [before, max(1, min(limit, 500))],
            ).rowcount
        return int(changed)

    def close(self) -> None:
        self._pool.close()


def build_ingestion_job_store(settings: Settings) -> IngestionJobStore:
    """Select shared production leasing and fail closed on local queue persistence."""
    if settings.database_backend == "postgresql":
        if settings.postgres_dsn is None:
            raise RuntimeError("PostgreSQL ingestion jobs require a DSN")
        return PostgresIngestionJobStore(
            settings.postgres_dsn.get_secret_value(),
            min_size=settings.postgres_pool_min_size,
            max_size=settings.postgres_pool_max_size,
            timeout_seconds=settings.postgres_pool_timeout_seconds,
            rls_enabled=settings.postgres_rls_enabled,
            migrate_on_startup=settings.app_env != "production",
        )
    if settings.app_env == "production":
        raise RuntimeError("Production ingestion jobs require PostgreSQL leasing")
    return SQLiteIngestionJobStore(settings.data_dir / "ingestion_jobs.sqlite3")


def new_job_record(
    *,
    job_id: str,
    tenant_id: str,
    filename: str,
    source_uri: str | None,
    input_object_ref: str,
    sha256: str,
    size_bytes: int,
    max_attempts: int,
    compute_cost_per_hour_usd: float = 0.0,
    now: datetime | None = None,
) -> JobRecord:
    created = now or _utc_now()
    _validated_usage(0.0, compute_cost_per_hour_usd)
    return JobRecord(
        id=job_id,
        tenant_id=tenant_id,
        filename=filename,
        source_uri=source_uri,
        input_object_ref=input_object_ref,
        sha256=sha256,
        size_bytes=size_bytes,
        status=IngestionJobStatus.QUEUED,
        progress=0,
        stage="queued",
        attempt_count=0,
        max_attempts=max_attempts,
        available_at=created,
        lifecycle_started_at=created,
        compute_cost_per_hour_usd=compute_cost_per_hour_usd,
        created_at=created,
        updated_at=created,
    )
