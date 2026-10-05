"""Tamper-evident identity audit and mandatory human-review workflow."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from crisisweave.auth import Principal
from crisisweave.config import Settings
from crisisweave.models import (
    ConflictSignal,
    ConflictStatus,
    IdentityAuditEvent,
    QueryResponse,
    ReviewDecision,
    ReviewRecord,
    ReviewStatus,
    RiskLevel,
    SourceFreshness,
    SourceFreshnessStatus,
)
from crisisweave.storage import MetadataStoreProtocol

_TENANT_ID = re.compile(r"[a-f0-9]{32}")
_HASH = re.compile(r"[a-f0-9]{64}")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class OversightAssessment:
    requires_review: bool
    risk_level: RiskLevel
    reasons: tuple[str, ...]
    confidence: float
    oldest_source_age_days: float | None
    contradiction_score: float | None
    source_freshness: SourceFreshness = field(default_factory=SourceFreshness)
    claim_evidence_conflict: ConflictSignal = field(default_factory=ConflictSignal)
    cross_source_conflict: ConflictSignal = field(default_factory=ConflictSignal)


class GovernanceRepository(Protocol):
    def record_identity_event(
        self,
        *,
        tenant_id: str | None,
        subject_id: str,
        identity_type: str,
        auth_method: str,
        event_type: str,
        outcome: str,
        request_id: str | None,
        details: Mapping[str, str] | None = None,
    ) -> IdentityAuditEvent: ...

    def list_identity_events(self, tenant_id: str, *, limit: int) -> list[IdentityAuditEvent]: ...

    def create_review(
        self,
        *,
        tenant_id: str,
        query: str,
        requester: Principal,
        response: QueryResponse,
        assessment: OversightAssessment,
    ) -> ReviewRecord: ...

    def get_review(self, tenant_id: str, review_id: str) -> ReviewRecord | None: ...

    def list_reviews(
        self, tenant_id: str, *, status: ReviewStatus | None, limit: int
    ) -> list[ReviewRecord]: ...

    def decide_review(
        self,
        tenant_id: str,
        review_id: str,
        *,
        reviewer: Principal,
        decision: ReviewDecision,
        reason: str,
    ) -> ReviewRecord | None: ...

    def close(self) -> None: ...


def _event_payload(
    *,
    event_id: str,
    tenant_id: str | None,
    subject_id: str,
    identity_type: str,
    auth_method: str,
    event_type: str,
    outcome: str,
    request_id: str | None,
    details: Mapping[str, str],
    previous_hash: str | None,
    created_at: datetime,
) -> dict[str, object]:
    return {
        "id": event_id,
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "identity_type": identity_type,
        "auth_method": auth_method,
        "event_type": event_type,
        "outcome": outcome,
        "request_id": request_id,
        "details": dict(details),
        "previous_hash": previous_hash,
        "created_at": created_at.isoformat(),
    }


def _validate_event_inputs(
    tenant_id: str | None,
    subject_id: str,
    event_type: str,
    outcome: str,
    details: Mapping[str, str],
) -> None:
    if tenant_id is not None and not _TENANT_ID.fullmatch(tenant_id):
        raise ValueError("identity audit tenant is invalid")
    if not 1 <= len(subject_id) <= 255 or not 1 <= len(event_type) <= 80:
        raise ValueError("identity audit subject or event type is invalid")
    if outcome not in {"success", "denied", "failed"}:
        raise ValueError("identity audit outcome is invalid")
    if len(details) > 20 or any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or not 1 <= len(key) <= 80
        or len(value) > 500
        for key, value in details.items()
    ):
        raise ValueError("identity audit details exceed their bounded schema")


def _event_model(row: Mapping[str, Any]) -> IdentityAuditEvent:
    details = row["details_json"]
    if isinstance(details, str):
        details = json.loads(details)
    return IdentityAuditEvent(
        id=str(row["id"]),
        tenant_id=row["tenant_id"],
        subject_id=str(row["subject_id"]),
        identity_type=str(row["identity_type"]),
        auth_method=str(row["auth_method"]),
        event_type=str(row["event_type"]),
        outcome=str(row["outcome"]),
        request_id=row["request_id"],
        details=details,
        previous_hash=row["previous_hash"],
        event_hash=str(row["event_hash"]),
        created_at=row["created_at"],
    )


def _review_model(row: Mapping[str, Any]) -> ReviewRecord:
    reasons = row["reasons_json"]
    response = row["response_json"]
    if isinstance(reasons, str):
        reasons = json.loads(reasons)
    if isinstance(response, str):
        response = json.loads(response)
    parsed_response = QueryResponse.model_validate(response)
    return ReviewRecord(
        id=str(row["id"]),
        query=str(row["query_text"]),
        status=ReviewStatus(str(row["status"])),
        risk_level=RiskLevel(str(row["risk_level"])),
        reasons=reasons,
        confidence=float(row["confidence"]),
        oldest_source_age_days=(
            float(row["oldest_source_age_days"])
            if row["oldest_source_age_days"] is not None
            else None
        ),
        contradiction_score=max(
            (
                score
                for score in (
                    parsed_response.claim_evidence_conflict.score,
                    parsed_response.cross_source_conflict.score,
                )
                if score is not None
            ),
            default=None,
        ),
        source_freshness=parsed_response.source_freshness,
        claim_evidence_conflict=parsed_response.claim_evidence_conflict,
        cross_source_conflict=parsed_response.cross_source_conflict,
        requester_subject=str(row["requester_subject"]),
        requester_identity_type=str(row["requester_identity_type"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        reviewed_by=row["reviewed_by"],
        decision_reason=row["decision_reason"],
        candidate_response=parsed_response,
    )


class SQLiteGovernanceRepository:
    def __init__(self, settings: Settings) -> None:
        path = settings.data_dir / "governance.sqlite3"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, timeout=30.0, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._identity_retention_days = settings.identity_audit_retention_days
        self._max_identity_rows = settings.max_identity_audit_rows
        self._review_retention_days = settings.review_retention_days
        self._last_prune = 0.0
        with self._lock:
            self._connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS identity_events (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    subject_id TEXT NOT NULL,
                    identity_type TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    request_id TEXT,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS identity_events_tenant_created
                    ON identity_events(tenant_id, created_at DESC, id DESC);
                CREATE TABLE IF NOT EXISTS audit_retention_guard (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1))
                );
                INSERT OR IGNORE INTO audit_retention_guard(singleton, enabled) VALUES (1, 0);
                CREATE TRIGGER IF NOT EXISTS identity_events_no_update
                BEFORE UPDATE ON identity_events BEGIN
                    SELECT RAISE(ABORT, 'identity audit events are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS identity_events_guarded_delete
                BEFORE DELETE ON identity_events
                WHEN (SELECT enabled FROM audit_retention_guard WHERE singleton = 1) != 1
                BEGIN
                    SELECT RAISE(ABORT, 'identity audit events are immutable');
                END;
                CREATE TABLE IF NOT EXISTS review_records (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    query_sha256 TEXT NOT NULL,
                    requester_subject TEXT NOT NULL,
                    requester_identity_type TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    oldest_source_age_days REAL,
                    contradiction_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    reviewed_by TEXT,
                    decision_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reviews_tenant_status_created
                    ON review_records(tenant_id, status, created_at DESC, id DESC);
                """
            )

    def _prune(self, now: datetime) -> None:
        if time.monotonic() - self._last_prune < 3600:
            return
        identity_cutoff = now.timestamp() - self._identity_retention_days * 86400
        review_cutoff = now.timestamp() - self._review_retention_days * 86400
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "UPDATE audit_retention_guard SET enabled = 1 WHERE singleton = 1"
            )
            self._connection.execute(
                "DELETE FROM identity_events WHERE created_at < ?",
                [datetime.fromtimestamp(identity_cutoff, UTC).isoformat()],
            )
            self._connection.execute(
                """DELETE FROM identity_events WHERE id IN (
                       SELECT id FROM identity_events ORDER BY created_at DESC, id DESC
                       LIMIT -1 OFFSET ?
                   )""",
                [self._max_identity_rows],
            )
            self._connection.execute(
                "UPDATE audit_retention_guard SET enabled = 0 WHERE singleton = 1"
            )
            self._connection.execute(
                "DELETE FROM review_records WHERE status != ? AND updated_at < ?",
                [
                    ReviewStatus.PENDING.value,
                    datetime.fromtimestamp(review_cutoff, UTC).isoformat(),
                ],
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        self._last_prune = time.monotonic()

    def record_identity_event(
        self,
        *,
        tenant_id: str | None,
        subject_id: str,
        identity_type: str,
        auth_method: str,
        event_type: str,
        outcome: str,
        request_id: str | None,
        details: Mapping[str, str] | None = None,
    ) -> IdentityAuditEvent:
        bounded_details = dict(details or {})
        _validate_event_inputs(tenant_id, subject_id, event_type, outcome, bounded_details)
        created_at = _utc_now()
        event_id = str(uuid.uuid4())
        scope = tenant_id or "__global__"
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """SELECT event_hash FROM identity_events
                       WHERE COALESCE(tenant_id, '__global__') = ?
                       ORDER BY created_at DESC, id DESC LIMIT 1""",
                    [scope],
                ).fetchone()
                previous_hash = str(row[0]) if row else None
                payload = _event_payload(
                    event_id=event_id,
                    tenant_id=tenant_id,
                    subject_id=subject_id,
                    identity_type=identity_type,
                    auth_method=auth_method,
                    event_type=event_type,
                    outcome=outcome,
                    request_id=request_id,
                    details=bounded_details,
                    previous_hash=previous_hash,
                    created_at=created_at,
                )
                event_hash = hashlib.sha256(_canonical_json(payload).encode()).hexdigest()
                self._connection.execute(
                    """INSERT INTO identity_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        event_id,
                        tenant_id,
                        subject_id,
                        identity_type,
                        auth_method,
                        event_type,
                        outcome,
                        request_id,
                        _canonical_json(bounded_details),
                        previous_hash,
                        event_hash,
                        created_at.isoformat(),
                    ],
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            self._prune(created_at)
        return IdentityAuditEvent.model_validate({**payload, "event_hash": event_hash})

    def list_identity_events(self, tenant_id: str, *, limit: int) -> list[IdentityAuditEvent]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM identity_events WHERE tenant_id = ?
                   ORDER BY created_at DESC, id DESC LIMIT ?""",
                [tenant_id, max(1, min(limit, 500))],
            ).fetchall()
        return [_event_model(row) for row in rows]

    def create_review(
        self,
        *,
        tenant_id: str,
        query: str,
        requester: Principal,
        response: QueryResponse,
        assessment: OversightAssessment,
    ) -> ReviewRecord:
        now = _utc_now()
        review_id = str(uuid.uuid4())
        values = [
            review_id,
            tenant_id,
            query,
            hashlib.sha256(query.encode()).hexdigest(),
            requester.subject_id,
            requester.identity_type.value,
            response.model_dump_json(),
            assessment.risk_level.value,
            _canonical_json(list(assessment.reasons)),
            assessment.confidence,
            assessment.oldest_source_age_days,
            assessment.contradiction_score or 0.0,
            ReviewStatus.PENDING.value,
            None,
            None,
            now.isoformat(),
            now.isoformat(),
        ]
        with self._lock:
            self._connection.execute(
                """INSERT INTO review_records
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
            row = self._connection.execute(
                "SELECT * FROM review_records WHERE id = ?", [review_id]
            ).fetchone()
        if row is None:
            raise RuntimeError("Review record was not persisted")
        return _review_model(row)

    def get_review(self, tenant_id: str, review_id: str) -> ReviewRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM review_records WHERE tenant_id = ? AND id = ?",
                [tenant_id, review_id],
            ).fetchone()
        return _review_model(row) if row else None

    def list_reviews(
        self, tenant_id: str, *, status: ReviewStatus | None, limit: int
    ) -> list[ReviewRecord]:
        parameters: list[object] = [tenant_id]
        status_sql = ""
        if status is not None:
            status_sql = " AND status = ?"
            parameters.append(status.value)
        parameters.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._connection.execute(
                f"""SELECT * FROM review_records WHERE tenant_id = ?{status_sql}
                      ORDER BY created_at DESC, id DESC LIMIT ?""",  # nosec B608  # noqa: S608
                parameters,
            ).fetchall()
        return [_review_model(row) for row in rows]

    def decide_review(
        self,
        tenant_id: str,
        review_id: str,
        *,
        reviewer: Principal,
        decision: ReviewDecision,
        reason: str,
    ) -> ReviewRecord | None:
        status_value = (
            ReviewStatus.APPROVED.value
            if decision == ReviewDecision.APPROVE
            else ReviewStatus.REJECTED.value
        )
        now = _utc_now().isoformat()
        with self._lock:
            changed = self._connection.execute(
                """UPDATE review_records SET status = ?, reviewed_by = ?, decision_reason = ?,
                       updated_at = ? WHERE tenant_id = ? AND id = ? AND status = ?
                       AND requester_subject != ?""",
                [
                    status_value,
                    reviewer.subject_id,
                    reason,
                    now,
                    tenant_id,
                    review_id,
                    ReviewStatus.PENDING.value,
                    reviewer.subject_id,
                ],
            ).rowcount
            if changed != 1:
                return None
            row = self._connection.execute(
                "SELECT * FROM review_records WHERE tenant_id = ? AND id = ?",
                [tenant_id, review_id],
            ).fetchone()
        return _review_model(row) if row else None

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class PostgresGovernanceRepository:
    def __init__(self, settings: Settings) -> None:
        if settings.postgres_dsn is None:
            raise RuntimeError("PostgreSQL governance requires a DSN")
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            conninfo=settings.postgres_dsn.get_secret_value(),
            min_size=settings.postgres_pool_min_size,
            max_size=settings.postgres_pool_max_size,
            timeout=settings.postgres_pool_timeout_seconds,
            kwargs={"row_factory": dict_row},
            open=True,
        )
        self._pool.wait(timeout=settings.postgres_pool_timeout_seconds)
        self._identity_retention_days = settings.identity_audit_retention_days
        self._max_identity_rows = settings.max_identity_audit_rows
        self._review_retention_days = settings.review_retention_days
        self._last_prune = 0.0

    @staticmethod
    def _bind(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('crisisweave.tenant_id', %s, true)", [tenant_id])

    def _prune(self, tenant_id: str | None) -> None:
        if time.monotonic() - self._last_prune < 3600:
            return
        with self._pool.connection() as connection, connection.transaction():
            connection.execute(
                "SELECT crisisweave.prune_identity_events(%s, %s)",
                [self._identity_retention_days, self._max_identity_rows],
            )
            if tenant_id is not None:
                self._bind(connection, tenant_id)
                connection.execute(
                    """DELETE FROM crisisweave.review_records
                       WHERE tenant_id = %s AND status != %s
                         AND updated_at < current_timestamp - (%s * INTERVAL '1 day')""",
                    [tenant_id, ReviewStatus.PENDING.value, self._review_retention_days],
                )
        self._last_prune = time.monotonic()

    def record_identity_event(
        self,
        *,
        tenant_id: str | None,
        subject_id: str,
        identity_type: str,
        auth_method: str,
        event_type: str,
        outcome: str,
        request_id: str | None,
        details: Mapping[str, str] | None = None,
    ) -> IdentityAuditEvent:
        bounded_details = dict(details or {})
        _validate_event_inputs(tenant_id, subject_id, event_type, outcome, bounded_details)
        created_at = _utc_now()
        event_id = str(uuid.uuid4())
        scope = tenant_id or "__global__"
        with self._pool.connection() as connection, connection.transaction():
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                [f"identity-audit:{scope}"],
            )
            if tenant_id:
                self._bind(connection, tenant_id)
            row = connection.execute(
                """SELECT event_hash FROM crisisweave.identity_events
                   WHERE COALESCE(tenant_id, '__global__') = %s
                   ORDER BY created_at DESC, id DESC LIMIT 1""",
                [scope],
            ).fetchone()
            typed_row = cast(Mapping[str, Any] | None, row)
            previous_hash = str(typed_row["event_hash"]) if typed_row else None
            payload = _event_payload(
                event_id=event_id,
                tenant_id=tenant_id,
                subject_id=subject_id,
                identity_type=identity_type,
                auth_method=auth_method,
                event_type=event_type,
                outcome=outcome,
                request_id=request_id,
                details=bounded_details,
                previous_hash=previous_hash,
                created_at=created_at,
            )
            event_hash = hashlib.sha256(_canonical_json(payload).encode()).hexdigest()
            connection.execute(
                """INSERT INTO crisisweave.identity_events
                   (id, tenant_id, subject_id, identity_type, auth_method, event_type, outcome,
                    request_id, details_json, previous_hash, event_hash, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)""",
                [
                    event_id,
                    tenant_id,
                    subject_id,
                    identity_type,
                    auth_method,
                    event_type,
                    outcome,
                    request_id,
                    _canonical_json(bounded_details),
                    previous_hash,
                    event_hash,
                    created_at,
                ],
            )
        self._prune(tenant_id)
        return IdentityAuditEvent.model_validate({**payload, "event_hash": event_hash})

    def list_identity_events(self, tenant_id: str, *, limit: int) -> list[IdentityAuditEvent]:
        with self._pool.connection() as connection, connection.transaction():
            self._bind(connection, tenant_id)
            rows = connection.execute(
                """SELECT * FROM crisisweave.identity_events WHERE tenant_id = %s
                   ORDER BY created_at DESC, id DESC LIMIT %s""",
                [tenant_id, max(1, min(limit, 500))],
            ).fetchall()
        return [_event_model(cast(Mapping[str, Any], row)) for row in rows]

    def create_review(
        self,
        *,
        tenant_id: str,
        query: str,
        requester: Principal,
        response: QueryResponse,
        assessment: OversightAssessment,
    ) -> ReviewRecord:
        now = _utc_now()
        review_id = str(uuid.uuid4())
        with self._pool.connection() as connection, connection.transaction():
            self._bind(connection, tenant_id)
            row = connection.execute(
                """INSERT INTO crisisweave.review_records
                   (id, tenant_id, query_text, query_sha256, requester_subject,
                    requester_identity_type, response_json, risk_level, reasons_json, confidence,
                    oldest_source_age_days, contradiction_score, status, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s::jsonb, %s, %s, %s, %s,
                           %s, %s) RETURNING *""",
                [
                    review_id,
                    tenant_id,
                    query,
                    hashlib.sha256(query.encode()).hexdigest(),
                    requester.subject_id,
                    requester.identity_type.value,
                    response.model_dump_json(),
                    assessment.risk_level.value,
                    _canonical_json(list(assessment.reasons)),
                    assessment.confidence,
                    assessment.oldest_source_age_days,
                    assessment.contradiction_score or 0.0,
                    ReviewStatus.PENDING.value,
                    now,
                    now,
                ],
            ).fetchone()
        if row is None:
            raise RuntimeError("Review record was not persisted")
        return _review_model(cast(Mapping[str, Any], row))

    def get_review(self, tenant_id: str, review_id: str) -> ReviewRecord | None:
        with self._pool.connection() as connection, connection.transaction():
            self._bind(connection, tenant_id)
            row = connection.execute(
                "SELECT * FROM crisisweave.review_records WHERE tenant_id = %s AND id = %s",
                [tenant_id, review_id],
            ).fetchone()
        return _review_model(cast(Mapping[str, Any], row)) if row else None

    def list_reviews(
        self, tenant_id: str, *, status: ReviewStatus | None, limit: int
    ) -> list[ReviewRecord]:
        where = "tenant_id = %s"
        parameters: list[object] = [tenant_id]
        if status is not None:
            where += " AND status = %s"
            parameters.append(status.value)
        parameters.append(max(1, min(limit, 500)))
        with self._pool.connection() as connection, connection.transaction():
            self._bind(connection, tenant_id)
            rows = connection.execute(
                f"""SELECT * FROM crisisweave.review_records WHERE {where}
                    ORDER BY created_at DESC, id DESC LIMIT %s""",  # nosec B608  # noqa: S608
                parameters,
            ).fetchall()
        return [_review_model(cast(Mapping[str, Any], row)) for row in rows]

    def decide_review(
        self,
        tenant_id: str,
        review_id: str,
        *,
        reviewer: Principal,
        decision: ReviewDecision,
        reason: str,
    ) -> ReviewRecord | None:
        status_value = (
            ReviewStatus.APPROVED.value
            if decision == ReviewDecision.APPROVE
            else ReviewStatus.REJECTED.value
        )
        with self._pool.connection() as connection, connection.transaction():
            self._bind(connection, tenant_id)
            row = connection.execute(
                """UPDATE crisisweave.review_records SET status = %s, reviewed_by = %s,
                       decision_reason = %s, updated_at = current_timestamp
                   WHERE tenant_id = %s AND id = %s AND status = %s
                     AND requester_subject != %s RETURNING *""",
                [
                    status_value,
                    reviewer.subject_id,
                    reason,
                    tenant_id,
                    review_id,
                    ReviewStatus.PENDING.value,
                    reviewer.subject_id,
                ],
            ).fetchone()
        return _review_model(cast(Mapping[str, Any], row)) if row else None

    def close(self) -> None:
        self._pool.close()


def build_governance_repository(settings: Settings) -> GovernanceRepository:
    if settings.database_backend == "postgresql":
        return PostgresGovernanceRepository(settings)
    return SQLiteGovernanceRepository(settings)


class OversightService:
    def __init__(
        self,
        settings: Settings,
        metadata: MetadataStoreProtocol,
        repository: GovernanceRepository,
    ) -> None:
        self.settings = settings
        self.metadata = metadata
        self.repository = repository
        self._risk_terms = tuple(
            item.casefold().strip() for item in settings.high_risk_terms.split(",") if item.strip()
        )

    def assess(self, tenant_id: str, query: str, response: QueryResponse) -> OversightAssessment:
        reasons: list[str] = []
        query_folded = " ".join(query.casefold().split())
        high_risk = any(term in query_folded for term in self._risk_terms)
        if high_risk:
            reasons.append("high_risk_subject")
        confidence = response.concordance.score
        if confidence < self.settings.minimum_answer_confidence:
            reasons.append("confidence_below_threshold")
        claim_conflict = response.claim_evidence_conflict
        source_conflict = response.cross_source_conflict
        conflict_scores = [
            score for score in (claim_conflict.score, source_conflict.score) if score is not None
        ]
        contradiction_score = max(conflict_scores, default=None)
        if (
            claim_conflict.status == ConflictStatus.DETECTED
            and claim_conflict.score is not None
            and claim_conflict.score >= self.settings.contradiction_escalation_threshold
        ):
            reasons.append("claim_evidence_conflict")
        if (
            source_conflict.status == ConflictStatus.DETECTED
            and source_conflict.score is not None
            and source_conflict.score >= self.settings.contradiction_escalation_threshold
        ):
            reasons.append("contradictory_evidence")

        freshness = response.source_freshness
        oldest_age = freshness.oldest_source_age_days
        if freshness.status in {SourceFreshnessStatus.UNKNOWN, SourceFreshnessStatus.PARTIAL} and (
            high_risk or self.settings.unknown_source_freshness_requires_review
        ):
            reasons.append("source_freshness_unknown")
        if freshness.status == SourceFreshnessStatus.STALE:
            reasons.append("source_freshness_exceeded")

        risk_level = (
            RiskLevel.HIGH if high_risk else RiskLevel.ELEVATED if reasons else RiskLevel.LOW
        )
        return OversightAssessment(
            requires_review=bool(reasons),
            risk_level=risk_level,
            reasons=tuple(dict.fromkeys(reasons)),
            confidence=confidence,
            oldest_source_age_days=oldest_age,
            contradiction_score=contradiction_score,
            source_freshness=freshness,
            claim_evidence_conflict=claim_conflict,
            cross_source_conflict=source_conflict,
        )

    def submit(
        self,
        *,
        tenant_id: str,
        query: str,
        requester: Principal,
        response: QueryResponse,
        assessment: OversightAssessment,
    ) -> ReviewRecord:
        return self.repository.create_review(
            tenant_id=tenant_id,
            query=query,
            requester=requester,
            response=response,
            assessment=assessment,
        )
