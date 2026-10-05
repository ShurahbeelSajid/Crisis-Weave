"""DuckDB metadata and constrained analytics persistence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, NamedTuple, Protocol, cast

import duckdb
import sqlglot
from sqlglot import exp

from crisisweave.models import (
    Chunk,
    Document,
    DocumentStatus,
    chunk_metadata_for_storage,
    split_chunk_storage_metadata,
)
from crisisweave.security import SecurityError

ANALYTICS_COLUMNS = {
    "document_id",
    "row_index",
    "event_id",
    "begin_year",
    "state",
    "event_type",
    "cz_name",
    "injuries_direct",
    "deaths_direct",
    "damage_property",
    "damage_crops",
    "magnitude",
}
ALLOWED_SQL_FUNCTIONS = {
    "AVG",
    "COALESCE",
    "COUNT",
    "LOWER",
    "MAX",
    "MIN",
    "ROUND",
    "SUM",
    "UPPER",
}


class AnalyticsResult(NamedTuple):
    sql: str
    rows: list[dict[str, Any]]
    sources: list[Document]
    source_rows: dict[str, list[dict[str, Any]]]
    source_count: int
    source_count_exact: bool


class _SQLNamed(Protocol):
    def sql_name(self) -> str: ...


class MetadataStoreProtocol(Protocol):
    """Backend-neutral persistence contract used by agents and ingestion workers."""

    def create_document(self, document: Document) -> None: ...
    def find_document_by_sha(self, tenant_id: str, sha256: str) -> Document | None: ...
    def get_document(self, tenant_id: str, document_id: str) -> Document | None: ...
    def list_documents(self, tenant_id: str, limit: int = 100) -> list[Document]: ...
    def list_documents_by_status(
        self,
        statuses: tuple[DocumentStatus, ...],
        limit: int = 500,
    ) -> list[Document]: ...
    def ready_document_ids(self, tenant_id: str, document_ids: set[str]) -> set[str]: ...
    def non_ready_document_ids(self, tenant_id: str) -> set[str]: ...
    def tenant_usage(self, tenant_id: str) -> tuple[int, int]: ...
    def reset_document_for_retry(self, tenant_id: str, document_id: str) -> None: ...
    def mark_document(
        self,
        tenant_id: str,
        document_id: str,
        status: DocumentStatus,
        *,
        chunk_count: int = 0,
        derived_size_bytes: int | None = None,
        warnings: Iterable[str] = (),
        error: str | None = None,
    ) -> None: ...
    def set_document_object_ref(
        self, tenant_id: str, document_id: str, object_ref: str
    ) -> None: ...
    def storm_event_count(self, tenant_id: str) -> int: ...
    def analytics_sources(self, tenant_id: str, limit: int = 10) -> tuple[list[Document], int]: ...
    def purge_failed_documents(self, tenant_id: str, keep: int) -> None: ...
    def replace_chunks(self, tenant_id: str, document_id: str, chunks: list[Chunk]) -> None: ...
    def replace_storm_events(
        self, tenant_id: str, document_id: str, records: list[dict[str, Any]]
    ) -> None: ...
    def get_chunks(self, tenant_id: str, chunk_ids: list[str]) -> list[Chunk]: ...
    def artifact_references(self, tenant_id: str, document_id: str) -> list[str]: ...
    def delete_document(self, tenant_id: str, document_id: str) -> bool: ...
    def object_reference_count(self, object_ref: str) -> int: ...
    def sha_reference_count(self, sha256: str) -> int: ...
    def execute_safe_analytics(
        self, tenant_id: str, proposed_sql: str, max_rows: int = 100
    ) -> tuple[str, list[dict[str, Any]]]: ...
    def execute_safe_analytics_with_sources(
        self,
        tenant_id: str,
        proposed_sql: str,
        max_rows: int = 100,
        source_limit: int = 10,
    ) -> AnalyticsResult: ...
    def healthcheck(self) -> bool: ...
    def record_query_audit(
        self,
        tenant_id: str,
        query: str,
        routes: list[str],
        citation_count: int,
        duration_ms: float,
        policy_flags: list[str],
    ) -> None: ...
    def tenant_lock(self, tenant_id: str) -> AbstractContextManager[None]: ...
    def try_tenant_lock(self, tenant_id: str) -> AbstractContextManager[bool]: ...
    def close(self) -> None: ...


class MetadataStore:
    """A lock-serialized DuckDB adapter suitable for one API process."""

    def __init__(
        self,
        database_path: Path | str,
        *,
        audit_retention_days: int = 30,
        max_audit_rows: int = 100_000,
        analytics_timeout_seconds: float = 10.0,
        max_analytics_result_bytes: int = 512 * 1024,
        max_analytics_cell_bytes: int = 32 * 1024,
    ) -> None:
        self._lock = threading.RLock()
        self._database_path = str(database_path)
        self._audit_retention_days = audit_retention_days
        self._max_audit_rows = max_audit_rows
        self._analytics_timeout_seconds = analytics_timeout_seconds
        self._max_analytics_result_bytes = max_analytics_result_bytes
        self._max_analytics_cell_bytes = max_analytics_cell_bytes
        self._last_audit_prune = 0.0
        self._connection = duckdb.connect(str(database_path))
        self._initialize()

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS documents (
            id VARCHAR PRIMARY KEY,
            tenant_id VARCHAR NOT NULL,
            filename VARCHAR NOT NULL,
            media_type VARCHAR NOT NULL,
            sha256 VARCHAR NOT NULL,
            size_bytes UBIGINT NOT NULL,
            status VARCHAR NOT NULL,
            source_uri VARCHAR,
            created_at TIMESTAMPTZ NOT NULL,
            error VARCHAR,
            chunk_count INTEGER NOT NULL DEFAULT 0,
            warnings_json VARCHAR NOT NULL DEFAULT '[]',
            derived_size_bytes UBIGINT NOT NULL DEFAULT 0,
            object_ref VARCHAR
        );
        CREATE UNIQUE INDEX IF NOT EXISTS documents_tenant_sha
            ON documents(tenant_id, sha256);
        CREATE TABLE IF NOT EXISTS chunks (
            id VARCHAR PRIMARY KEY,
            tenant_id VARCHAR NOT NULL,
            document_id VARCHAR NOT NULL,
            source_name VARCHAR NOT NULL,
            source_uri VARCHAR,
            modality VARCHAR NOT NULL,
            text VARCHAR NOT NULL,
            page INTEGER,
            timestamp_seconds DOUBLE,
            artifact_path VARCHAR,
            metadata_json VARCHAR NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS chunks_tenant_document
            ON chunks(tenant_id, document_id);
        CREATE TABLE IF NOT EXISTS storm_events (
            tenant_id VARCHAR NOT NULL,
            document_id VARCHAR NOT NULL,
            row_index INTEGER NOT NULL,
            event_id VARCHAR,
            begin_year INTEGER,
            state VARCHAR,
            event_type VARCHAR,
            cz_name VARCHAR,
            injuries_direct DOUBLE,
            deaths_direct DOUBLE,
            damage_property DOUBLE,
            damage_crops DOUBLE,
            magnitude DOUBLE,
            episode_narrative VARCHAR,
            raw_json VARCHAR NOT NULL,
            PRIMARY KEY (tenant_id, document_id, row_index)
        );
        CREATE TABLE IF NOT EXISTS query_audit (
            id VARCHAR PRIMARY KEY,
            tenant_id VARCHAR NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
            query_sha256 VARCHAR NOT NULL,
            routes_json VARCHAR NOT NULL,
            citation_count INTEGER NOT NULL,
            duration_ms DOUBLE NOT NULL,
            policy_flags_json VARCHAR NOT NULL
        );
        """
        with self._lock:
            self._connection.execute(schema)
            document_columns = {
                str(row[1])
                for row in self._connection.execute("PRAGMA table_info('documents')").fetchall()
            }
            if "derived_size_bytes" not in document_columns:
                self._connection.execute(
                    "ALTER TABLE documents ADD COLUMN derived_size_bytes UBIGINT DEFAULT 0"
                )
                self._connection.execute(
                    "UPDATE documents SET derived_size_bytes = 0 WHERE derived_size_bytes IS NULL"
                )
            if "object_ref" not in document_columns:
                self._connection.execute("ALTER TABLE documents ADD COLUMN object_ref VARCHAR")
            self._connection.execute("SET enable_external_access = false")
            for statement in (
                "SET autoload_known_extensions = false",
                "SET autoinstall_known_extensions = false",
                "SET allow_community_extensions = false",
                "SET threads = 2",
                "SET memory_limit = '512MB'",
            ):
                try:
                    self._connection.execute(statement)
                except duckdb.Error:
                    # Older supported DuckDB builds may not expose every hardening setting.
                    continue

    @staticmethod
    def _document_from_row(row: tuple[Any, ...]) -> Document:
        return Document(
            id=row[0],
            tenant_id=row[1],
            filename=row[2],
            media_type=row[3],
            sha256=row[4],
            size_bytes=row[5],
            status=DocumentStatus(row[6]),
            source_uri=row[7],
            created_at=row[8],
            error=row[9],
            chunk_count=row[10],
            warnings=json.loads(row[11]),
            derived_size_bytes=row[12],
            object_ref=row[13] if len(row) > 13 else None,
        )

    @staticmethod
    def _chunk_from_row(row: tuple[Any, ...]) -> Chunk:
        metadata, regions = split_chunk_storage_metadata(json.loads(row[10]))
        return Chunk(
            id=row[0],
            tenant_id=row[1],
            document_id=row[2],
            source_name=row[3],
            source_uri=row[4],
            modality=row[5],
            text=row[6],
            page=row[7],
            timestamp_seconds=row[8],
            artifact_path=row[9],
            metadata=metadata,
            regions=regions,
        )

    def create_document(self, document: Document) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    document.id,
                    document.tenant_id,
                    document.filename,
                    document.media_type,
                    document.sha256,
                    document.size_bytes,
                    document.status.value,
                    document.source_uri,
                    document.created_at,
                    document.error,
                    document.chunk_count,
                    json.dumps(document.warnings),
                    document.derived_size_bytes,
                    document.object_ref,
                ],
            )

    def find_document_by_sha(self, tenant_id: str, sha256: str) -> Document | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM documents WHERE tenant_id = ? AND sha256 = ?",
                [tenant_id, sha256],
            ).fetchone()
        return self._document_from_row(row) if row else None

    def get_document(self, tenant_id: str, document_id: str) -> Document | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM documents WHERE tenant_id = ? AND id = ?",
                [tenant_id, document_id],
            ).fetchone()
        return self._document_from_row(row) if row else None

    def list_documents(self, tenant_id: str, limit: int = 100) -> list[Document]:
        safe_limit = max(1, min(limit, 500))
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM documents WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                [tenant_id, safe_limit],
            ).fetchall()
        return [self._document_from_row(row) for row in rows]

    def list_documents_by_status(
        self,
        statuses: tuple[DocumentStatus, ...],
        limit: int = 500,
    ) -> list[Document]:
        if not statuses:
            return []
        safe_limit = max(1, min(limit, 5000))
        placeholders = ",".join("?" for _ in statuses)
        query = (
            "SELECT * FROM documents "  # noqa: S608  # nosec B608
            f"WHERE status IN ({placeholders}) ORDER BY created_at ASC LIMIT ?"
        )
        with self._lock:
            rows = self._connection.execute(
                query,
                [*[item.value for item in statuses], safe_limit],
            ).fetchall()
        return [self._document_from_row(row) for row in rows]

    def ready_document_ids(self, tenant_id: str, document_ids: set[str]) -> set[str]:
        if not document_ids:
            return set()
        placeholders = ",".join("?" for _ in document_ids)
        # Only the count of fixed parameter placeholders is interpolated; all values stay bound.
        query = (
            "SELECT id FROM documents WHERE tenant_id = ? AND status = ? "  # noqa: S608  # nosec B608
            f"AND id IN ({placeholders})"
        )
        with self._lock:
            rows = self._connection.execute(
                query,
                [tenant_id, DocumentStatus.READY.value, *sorted(document_ids)],
            ).fetchall()
        return {str(row[0]) for row in rows}

    def non_ready_document_ids(self, tenant_id: str) -> set[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id FROM documents WHERE tenant_id = ? AND status != ?",
                [tenant_id, DocumentStatus.READY.value],
            ).fetchall()
        return {str(row[0]) for row in rows}

    def tenant_usage(self, tenant_id: str) -> tuple[int, int]:
        with self._lock:
            row = self._connection.execute(
                """SELECT COUNT(*), COALESCE(SUM(size_bytes + derived_size_bytes), 0)
                   FROM documents
                   WHERE tenant_id = ? AND status != ?""",
                [tenant_id, DocumentStatus.FAILED.value],
            ).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def reset_document_for_retry(self, tenant_id: str, document_id: str) -> None:
        with self._lock:
            self._connection.execute("BEGIN TRANSACTION")
            try:
                self._connection.execute(
                    "DELETE FROM storm_events WHERE tenant_id = ? AND document_id = ?",
                    [tenant_id, document_id],
                )
                self._connection.execute(
                    "DELETE FROM chunks WHERE tenant_id = ? AND document_id = ?",
                    [tenant_id, document_id],
                )
                self._connection.execute(
                    """UPDATE documents SET status = ?, error = NULL, chunk_count = 0,
                       warnings_json = '[]', derived_size_bytes = 0
                       WHERE tenant_id = ? AND id = ?""",
                    [DocumentStatus.PROCESSING.value, tenant_id, document_id],
                )
                self._connection.execute("COMMIT")
            except duckdb.Error:
                self._connection.execute("ROLLBACK")
                raise

    def mark_document(
        self,
        tenant_id: str,
        document_id: str,
        status: DocumentStatus,
        *,
        chunk_count: int = 0,
        derived_size_bytes: int | None = None,
        warnings: Iterable[str] = (),
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._connection.execute(
                """
                UPDATE documents
                SET status = ?, chunk_count = ?, warnings_json = ?, error = ?,
                    derived_size_bytes = COALESCE(?, derived_size_bytes)
                WHERE tenant_id = ? AND id = ?
                """,
                [
                    status.value,
                    chunk_count,
                    json.dumps(list(warnings)),
                    error,
                    derived_size_bytes,
                    tenant_id,
                    document_id,
                ],
            )

    def set_document_object_ref(self, tenant_id: str, document_id: str, object_ref: str) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE documents SET object_ref = ? WHERE tenant_id = ? AND id = ?",
                [object_ref, tenant_id, document_id],
            )

    def storm_event_count(self, tenant_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                """SELECT COUNT(*) FROM storm_events AS event
                   WHERE event.tenant_id = ? AND event.document_id IN (
                       SELECT id FROM documents
                       WHERE tenant_id = ? AND status = ?
                   )""",
                [tenant_id, tenant_id, DocumentStatus.READY.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def analytics_sources(self, tenant_id: str, limit: int = 10) -> tuple[list[Document], int]:
        safe_limit = max(1, min(limit, 50))
        with self._lock:
            count_row = self._connection.execute(
                """SELECT COUNT(*) FROM documents AS document
                   WHERE document.tenant_id = ? AND document.status = ? AND EXISTS (
                       SELECT 1 FROM storm_events AS event
                       WHERE event.tenant_id = document.tenant_id
                         AND event.document_id = document.id
                   )""",
                [tenant_id, DocumentStatus.READY.value],
            ).fetchone()
            rows = self._connection.execute(
                """SELECT document.* FROM documents AS document
                   WHERE document.tenant_id = ? AND document.status = ? AND EXISTS (
                       SELECT 1 FROM storm_events AS event
                       WHERE event.tenant_id = document.tenant_id
                         AND event.document_id = document.id
                   ) ORDER BY document.created_at DESC LIMIT ?""",
                [tenant_id, DocumentStatus.READY.value, safe_limit],
            ).fetchall()
        total = int(count_row[0]) if count_row else 0
        return [self._document_from_row(row) for row in rows], total

    def purge_failed_documents(self, tenant_id: str, keep: int) -> None:
        safe_keep = max(0, keep)
        with self._lock:
            self._connection.execute(
                """DELETE FROM documents WHERE tenant_id = ? AND status = ? AND id IN (
                       SELECT id FROM documents
                       WHERE tenant_id = ? AND status = ?
                       ORDER BY created_at DESC, id DESC OFFSET ?
                   )""",
                [
                    tenant_id,
                    DocumentStatus.FAILED.value,
                    tenant_id,
                    DocumentStatus.FAILED.value,
                    safe_keep,
                ],
            )

    def replace_chunks(self, tenant_id: str, document_id: str, chunks: list[Chunk]) -> None:
        rows = [
            (
                chunk.id,
                tenant_id,
                document_id,
                chunk.source_name,
                chunk.source_uri,
                chunk.modality.value,
                chunk.text,
                chunk.page,
                chunk.timestamp_seconds,
                chunk.artifact_path,
                json.dumps(chunk_metadata_for_storage(chunk), ensure_ascii=False),
            )
            for chunk in chunks
        ]
        with self._lock:
            self._connection.execute(
                "DELETE FROM chunks WHERE tenant_id = ? AND document_id = ?",
                [tenant_id, document_id],
            )
            if rows:
                self._connection.executemany(
                    "INSERT INTO chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows
                )

    def replace_storm_events(
        self, tenant_id: str, document_id: str, records: list[dict[str, Any]]
    ) -> None:
        rows = [
            (
                tenant_id,
                document_id,
                index,
                record.get("event_id"),
                record.get("begin_year"),
                record.get("state"),
                record.get("event_type"),
                record.get("cz_name"),
                record.get("injuries_direct"),
                record.get("deaths_direct"),
                record.get("damage_property"),
                record.get("damage_crops"),
                record.get("magnitude"),
                record.get("episode_narrative"),
                json.dumps(record.get("raw", record), ensure_ascii=False),
            )
            for index, record in enumerate(records)
        ]
        with self._lock:
            self._connection.execute(
                "DELETE FROM storm_events WHERE tenant_id = ? AND document_id = ?",
                [tenant_id, document_id],
            )
            if rows:
                self._connection.executemany(
                    "INSERT INTO storm_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )

    def get_chunks(self, tenant_id: str, chunk_ids: list[str]) -> list[Chunk]:
        if not chunk_ids:
            return []
        placeholders = ",".join("?" for _ in chunk_ids)
        query = (
            "SELECT id, tenant_id, document_id, source_name, source_uri, modality, text, "  # noqa: S608
            "page, timestamp_seconds, artifact_path, metadata_json "
            "FROM chunks WHERE tenant_id = ? "
            f"AND id IN ({placeholders})"  # noqa: S608  # nosec B608
        )
        with self._lock:
            rows = self._connection.execute(
                query,
                [tenant_id, *chunk_ids],
            ).fetchall()
        by_id = {row[0]: self._chunk_from_row(row) for row in rows}
        return [by_id[item] for item in chunk_ids if item in by_id]

    def artifact_references(self, tenant_id: str, document_id: str) -> list[str]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT DISTINCT artifact_path FROM chunks
                   WHERE tenant_id = ? AND document_id = ? AND artifact_path IS NOT NULL""",
                [tenant_id, document_id],
            ).fetchall()
        return [str(row[0]) for row in rows]

    def delete_document(self, tenant_id: str, document_id: str) -> bool:
        with self._lock:
            exists = self._connection.execute(
                "SELECT 1 FROM documents WHERE tenant_id = ? AND id = ?",
                [tenant_id, document_id],
            ).fetchone()
            if not exists:
                return False
            self._connection.execute("BEGIN TRANSACTION")
            try:
                self._connection.execute(
                    "DELETE FROM storm_events WHERE tenant_id = ? AND document_id = ?",
                    [tenant_id, document_id],
                )
                self._connection.execute(
                    "DELETE FROM chunks WHERE tenant_id = ? AND document_id = ?",
                    [tenant_id, document_id],
                )
                self._connection.execute(
                    "DELETE FROM documents WHERE tenant_id = ? AND id = ?",
                    [tenant_id, document_id],
                )
                self._connection.execute("COMMIT")
            except duckdb.Error:
                self._connection.execute("ROLLBACK")
                raise
        return True

    def sha_reference_count(self, sha256: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM documents WHERE sha256 = ? AND status != ?",
                [sha256, DocumentStatus.FAILED.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def object_reference_count(self, object_ref: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM documents WHERE object_ref = ? AND status != ?",
                [object_ref, DocumentStatus.FAILED.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def execute_safe_analytics(
        self, tenant_id: str, proposed_sql: str, max_rows: int = 100
    ) -> tuple[str, list[dict[str, Any]]]:
        result = self._execute_safe_analytics(
            tenant_id,
            proposed_sql,
            max_rows=max_rows,
            source_limit=0,
        )
        return result.sql, result.rows

    def execute_safe_analytics_with_sources(
        self,
        tenant_id: str,
        proposed_sql: str,
        max_rows: int = 100,
        source_limit: int = 10,
    ) -> AnalyticsResult:
        """Execute analytics and return only documents that contributed to its rows."""
        return self._execute_safe_analytics(
            tenant_id,
            proposed_sql,
            max_rows=max_rows,
            source_limit=max(1, min(source_limit, 50)),
        )

    def _execute_safe_analytics(
        self,
        tenant_id: str,
        proposed_sql: str,
        *,
        max_rows: int,
        source_limit: int,
    ) -> AnalyticsResult:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        safe_sql = validate_analytics_sql(proposed_sql, max_rows=max_rows)
        execution_tree = sqlglot.parse_one(safe_sql, read="duckdb")
        for table in execution_tree.find_all(exp.Table):
            if not table.alias:
                table.set(
                    "alias",
                    exp.TableAlias(this=exp.to_identifier("authorized_storm_events")),
                )
            table.set("this", exp.to_identifier("storm_events"))
        tenant_predicate: exp.Condition = exp.column("tenant_id").eq(exp.Literal.string(tenant_id))
        existing_where = execution_tree.args.get("where")
        if existing_where:
            tenant_predicate = exp.and_(existing_where.this, tenant_predicate)
        ready_query = (
            exp.select("id")
            .from_("documents")
            .where(
                exp.and_(
                    exp.column("tenant_id").eq(exp.Literal.string(tenant_id)),
                    exp.column("status").eq(exp.Literal.string(DocumentStatus.READY.value)),
                )
            )
        )
        ready_predicate = exp.In(
            this=exp.column("document_id"),
            query=exp.Subquery(this=ready_query),
        )
        execution_tree.set("where", exp.Where(this=exp.and_(tenant_predicate, ready_predicate)))
        lineage_alias = "__crisisweave_source_ids"
        lineage_count_alias = "__crisisweave_source_count"
        aggregate_lineage = False
        if source_limit:
            has_aggregate = any(execution_tree.find_all(exp.AggFunc))
            if has_aggregate or execution_tree.args.get("group") is not None:
                aggregate_lineage = True
                lineage_selection = sqlglot.parse_one(
                    "SELECT "
                    "LIST_SLICE(LIST(DISTINCT document_id ORDER BY document_id), "
                    f"1, {source_limit}) AS {lineage_alias}, "
                    f"COUNT(DISTINCT document_id) AS {lineage_count_alias}",
                    read="duckdb",
                ).expressions
            else:
                lineage_selection = [
                    exp.alias_(exp.column("document_id"), lineage_alias, quoted=False)
                ]
            execution_tree.set("expressions", [*execution_tree.expressions, *lineage_selection])
        execution_sql = execution_tree.sql(dialect="duckdb")
        # Analytics runs on a dedicated connection so a costly aggregate cannot
        # monopolize the metadata writer. DuckDB's interrupt is invoked from a
        # watchdog thread and the validated SELECT is still tenant-scoped.
        connection = duckdb.connect(self._database_path)
        timed_out = threading.Event()

        def interrupt() -> None:
            timed_out.set()
            connection.interrupt()

        watchdog = threading.Timer(self._analytics_timeout_seconds, interrupt)
        watchdog.daemon = True
        try:
            connection.execute("SET enable_external_access = false")
            for statement in (
                "SET autoload_known_extensions = false",
                "SET autoinstall_known_extensions = false",
                "SET allow_community_extensions = false",
            ):
                unsupported = False
                try:
                    connection.execute(statement)
                except duckdb.Error:
                    unsupported = True
                if unsupported:
                    continue
            watchdog.start()
            cursor = connection.execute(execution_sql)
            columns = [item[0] for item in cursor.description]
            source_ids: set[str] = set()
            source_rows: dict[str, list[dict[str, Any]]] = {}
            source_count = 0
            source_count_exact = True
            hidden_indexes: set[int] = set()
            lineage_index: int | None = None
            count_index: int | None = None
            if source_limit:
                lineage_index = columns.index(lineage_alias)
                hidden_indexes.add(lineage_index)
                if aggregate_lineage:
                    count_index = columns.index(lineage_count_alias)
                    hidden_indexes.add(count_index)
            visible_columns = [
                column for index, column in enumerate(columns) if index not in hidden_indexes
            ]
            if len({column.casefold() for column in visible_columns}) != len(visible_columns):
                raise SecurityError("Analytics result columns must have unique names")
            visible_indexes = [
                index for index in range(len(columns)) if index not in hidden_indexes
            ]
            result_rows: list[tuple[Any, ...]] = []
            result_size = 2
            while result_row := cursor.fetchone():
                visible_values = [result_row[index] for index in visible_indexes]
                row_size = 2
                for column, value in zip(visible_columns, visible_values, strict=True):
                    cell = _analytics_json(value)
                    if len(cell) > self._max_analytics_cell_bytes:
                        raise SecurityError("Analytics result cell exceeded its byte budget")
                    row_size += len(column.encode("utf-8")) + len(cell) + 4
                result_size += row_size
                if result_size > self._max_analytics_result_bytes:
                    raise SecurityError("Analytics result exceeded its byte budget")
                result_rows.append(result_row)

            if source_limit:
                if lineage_index is None:
                    raise RuntimeError("Analytics lineage index was not created")
                rows = []
                group_counts: list[int] = []
                group_lineage_truncated = False
                for result_row in result_rows:
                    lineage = result_row[lineage_index]
                    row_source_ids: set[str] = set()
                    if isinstance(lineage, list):
                        row_source_ids = {str(value) for value in lineage}
                    elif lineage is not None:
                        row_source_ids = {str(lineage)}
                    source_ids.update(row_source_ids)
                    if count_index is not None:
                        group_count = int(result_row[count_index])
                        group_counts.append(group_count)
                        lineage_size = len(lineage) if isinstance(lineage, list) else 0
                        group_lineage_truncated |= group_count > lineage_size
                    visible_values = [result_row[index] for index in visible_indexes]
                    visible_row = dict(zip(visible_columns, visible_values, strict=True))
                    rows.append(visible_row)
                    for source_id in row_source_ids:
                        source_rows.setdefault(source_id, []).append(visible_row)
                if aggregate_lineage and group_counts:
                    source_count_exact = len(group_counts) == 1 or not group_lineage_truncated
                    source_count = (
                        group_counts[0]
                        if len(group_counts) == 1
                        else max(len(source_ids), max(group_counts))
                    )
                    if source_count_exact and len(group_counts) > 1:
                        source_count = len(source_ids)
                else:
                    source_count = len(source_ids)
            else:
                rows = [dict(zip(columns, result_row, strict=True)) for result_row in result_rows]

            selected_ids = sorted(source_ids)[:source_limit]
            documents: list[Document] = []
            if selected_ids:
                placeholders = ",".join("?" for _ in selected_ids)
                # Only the count of fixed parameter placeholders is interpolated.
                document_rows = connection.execute(
                    "SELECT * FROM documents WHERE tenant_id = ? AND status = ? "  # noqa: S608  # nosec B608
                    f"AND id IN ({placeholders})",
                    [tenant_id, DocumentStatus.READY.value, *selected_ids],
                ).fetchall()
                by_id = {row[0]: self._document_from_row(row) for row in document_rows}
                documents = [by_id[item] for item in selected_ids if item in by_id]
        except duckdb.Error as exc:
            if timed_out.is_set():
                raise SecurityError("Analytics query exceeded its execution budget") from exc
            raise SecurityError("Analytics query failed safely") from exc
        finally:
            watchdog.cancel()
            if watchdog.is_alive():
                watchdog.join(timeout=0.1)
            connection.close()
        selected_source_rows = {
            source_id: source_rows[source_id]
            for source_id in selected_ids
            if source_id in source_rows
        }
        return AnalyticsResult(
            sql=safe_sql,
            rows=rows,
            sources=documents,
            source_rows=selected_source_rows,
            source_count=source_count,
            source_count_exact=source_count_exact,
        )

    def healthcheck(self) -> bool:
        with self._lock:
            return self._connection.execute("SELECT 1").fetchone() == (1,)

    @contextmanager
    def tenant_lock(self, _tenant_id: str) -> Iterator[None]:
        """DuckDB is process-local; the ingestion service supplies its in-process lock."""
        yield

    @contextmanager
    def try_tenant_lock(self, _tenant_id: str) -> Iterator[bool]:
        yield True

    def record_query_audit(
        self,
        tenant_id: str,
        query: str,
        routes: list[str],
        citation_count: int,
        duration_ms: float,
        policy_flags: list[str],
    ) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO query_audit VALUES (?, ?, current_timestamp, ?, ?, ?, ?, ?)",
                [
                    str(uuid.uuid4()),
                    tenant_id,
                    query_hash(query),
                    json.dumps(routes),
                    citation_count,
                    duration_ms,
                    json.dumps(policy_flags),
                ],
            )
            now = time.monotonic()
            if now - self._last_audit_prune >= 3600:
                self._connection.execute(
                    "DELETE FROM query_audit WHERE created_at < "
                    "current_timestamp - (? * INTERVAL '1 day')",
                    [self._audit_retention_days],
                )
                self._connection.execute(
                    """DELETE FROM query_audit WHERE id IN (
                       SELECT id FROM query_audit ORDER BY created_at DESC
                       OFFSET ?
                    )""",
                    [self._max_audit_rows],
                )
                self._last_audit_prune = now

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _analytics_json(value: Any) -> bytes:
    if isinstance(value, float) and not math.isfinite(value):
        raise SecurityError("Analytics result contained a non-finite number")
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise SecurityError("Analytics result could not be serialized safely") from exc


def validate_analytics_sql(proposed_sql: str, max_rows: int = 100) -> str:
    if not proposed_sql or len(proposed_sql) > 4000 or "--" in proposed_sql or "/*" in proposed_sql:
        raise SecurityError("SQL is empty, oversized, or contains comments")
    try:
        statements = sqlglot.parse(proposed_sql, read="duckdb")
    except sqlglot.errors.ParseError as exc:
        raise SecurityError("SQL could not be parsed") from exc
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise SecurityError("Only one SELECT statement is allowed")
    tree = statements[0]
    if tree.find(exp.With) or tree.find(exp.Subquery) or tree.find(exp.Join):
        raise SecurityError("CTEs, subqueries, and joins are not allowed")
    if (
        tree.args.get("distinct")
        or tree.find(exp.Window)
        or tree.find(exp.Filter)
        or tree.find(exp.DPipe)
        or tree.find(exp.Placeholder)
        or tree.find(exp.Parameter)
    ):
        raise SecurityError(
            "DISTINCT, window, aggregate FILTER, concatenation, and parameters are not allowed"
        )
    group = tree.args.get("group")
    if (
        tree.find(exp.Cube)
        or tree.find(exp.Rollup)
        or tree.find(exp.GroupingSets)
        or tree.find(exp.TableSample)
        or tree.find(exp.Pivot)
        or tree.args.get("offset")
        or (group is not None and (group.args.get("all") or group.args.get("totals")))
    ):
        raise SecurityError("Advanced grouping, sampling, pivot, and OFFSET are not allowed")
    tables = {table.name.lower() for table in tree.find_all(exp.Table)}
    if tables != {"authorized_storm_events"}:
        raise SecurityError("SQL may query only authorized_storm_events")
    for selection in tree.expressions:
        if isinstance(selection, exp.Star) or (
            isinstance(selection, exp.Column) and selection.is_star
        ):
            raise SecurityError("SELECT * is not allowed")
    for alias in tree.find_all(exp.Alias):
        if alias.alias and (
            alias.alias.lower() in {"tenant_id", "raw_json"}
            or alias.alias.lower().startswith("__crisisweave_")
        ):
            raise SecurityError("SQL aliases may not shadow protected columns")
    for column in tree.find_all(exp.Column):
        if column.is_star:
            raise SecurityError("SELECT * is not allowed")
        if column.name.lower() not in ANALYTICS_COLUMNS:
            raise SecurityError(f"Column is not allowlisted: {column.name}")
    for function in tree.find_all(exp.Func):
        function_name = cast(_SQLNamed, function).sql_name()
        if function_name.upper() not in ALLOWED_SQL_FUNCTIONS:
            raise SecurityError(f"Function is not allowlisted: {function_name}")
    for aggregate in tree.find_all(exp.AggFunc):
        if (
            aggregate.find(exp.Predicate)
            or aggregate.find(exp.Connector)
            or aggregate.find(exp.Not)
            or aggregate.find(exp.Case)
            or aggregate.find(exp.If)
        ):
            raise SecurityError(
                "Conditional aggregates are not allowed; use a top-level WHERE clause"
            )
    bounded_limit = max(1, min(max_rows, 500))
    existing_limit = tree.args.get("limit")
    if existing_limit is not None:
        limit_expression = existing_limit.args.get("expression")
        if not isinstance(limit_expression, exp.Literal) or limit_expression.is_string:
            raise SecurityError("LIMIT must be a non-negative integer literal")
        try:
            requested_limit = int(limit_expression.this)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SecurityError("LIMIT must be a non-negative integer literal") from exc
        if requested_limit < 0:
            raise SecurityError("LIMIT must be a non-negative integer literal")
        bounded_limit = min(bounded_limit, requested_limit)
    bounded = tree.copy().limit(bounded_limit)
    return bounded.sql(dialect="duckdb")


def query_hash(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()
