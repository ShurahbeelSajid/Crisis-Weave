"""PostgreSQL metadata and tenant-scoped analytics persistence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any, cast

import sqlglot
from sqlglot import exp

from crisisweave.models import (
    Chunk,
    Document,
    DocumentStatus,
    Modality,
    chunk_metadata_for_storage,
    split_chunk_storage_metadata,
)
from crisisweave.postgres_migrations import (
    MIGRATION_LOCK,
    apply_metadata_migrations,
    verify_postgres_schema,
)
from crisisweave.security import SecurityError
from crisisweave.storage import AnalyticsResult, query_hash, validate_analytics_sql

_SCHEMA = "crisisweave"
_DOCUMENT_COLUMNS = (
    "id, tenant_id, filename, media_type, sha256, size_bytes, status, source_uri, "
    "created_at, error, chunk_count, warnings_json, derived_size_bytes, object_ref"
)


class PostgresMetadataStore:
    """Thread-safe pooled store supporting multiple API processes."""

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 8,
        pool_timeout_seconds: float = 10.0,
        audit_retention_days: int = 30,
        max_audit_rows: int = 100_000,
        analytics_timeout_seconds: float = 10.0,
        max_analytics_result_bytes: int = 512 * 1024,
        max_analytics_cell_bytes: int = 32 * 1024,
        rls_enabled: bool = False,
        migrate_on_startup: bool = True,
    ) -> None:
        import psycopg
        from psycopg_pool import ConnectionPool

        self._psycopg = psycopg
        self._audit_retention_days = audit_retention_days
        self._max_audit_rows = max_audit_rows
        self._analytics_timeout_seconds = analytics_timeout_seconds
        self._max_analytics_result_bytes = max_analytics_result_bytes
        self._max_analytics_cell_bytes = max_analytics_cell_bytes
        self._lock_timeout_seconds = pool_timeout_seconds
        self._rls_enabled = rls_enabled
        self._last_audit_prune = 0.0
        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=pool_min_size,
            max_size=pool_max_size,
            timeout=pool_timeout_seconds,
            kwargs={"autocommit": True},
            open=True,
        )
        self._pool.wait(timeout=pool_timeout_seconds)
        if migrate_on_startup:
            self._initialize()
        else:
            self._verify_schema()

    def _initialize(self) -> None:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(%s)", [MIGRATION_LOCK])
            apply_metadata_migrations(connection)

    def _verify_schema(self) -> None:
        with self._pool.connection() as connection:
            verify_postgres_schema(connection)

    @contextmanager
    def _tenant_connection(self, tenant_id: str) -> Iterator[Any]:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        with self._pool.connection() as connection, connection.transaction():
            if getattr(self, "_rls_enabled", False):
                connection.execute(
                    "SELECT set_config('crisisweave.tenant_id', %s, true)", [tenant_id]
                )
            yield connection

    @staticmethod
    def _json_value(value: Any, expected: type[list[Any]] | type[dict[str, Any]]) -> Any:
        decoded = json.loads(value) if isinstance(value, str) else value
        return decoded if isinstance(decoded, expected) else expected()

    @classmethod
    def _document_from_row(cls, row: tuple[Any, ...]) -> Document:
        return Document(
            id=str(row[0]),
            tenant_id=str(row[1]),
            filename=str(row[2]),
            media_type=str(row[3]),
            sha256=str(row[4]),
            size_bytes=int(row[5]),
            status=DocumentStatus(str(row[6])),
            source_uri=row[7],
            created_at=row[8],
            error=row[9],
            chunk_count=int(row[10]),
            warnings=cls._json_value(row[11], list),
            derived_size_bytes=int(row[12]),
            object_ref=row[13],
        )

    @classmethod
    def _chunk_from_row(cls, row: tuple[Any, ...]) -> Chunk:
        metadata, regions = split_chunk_storage_metadata(cls._json_value(row[10], dict))
        return Chunk(
            id=str(row[0]),
            tenant_id=str(row[1]),
            document_id=str(row[2]),
            source_name=str(row[3]),
            source_uri=row[4],
            modality=Modality(str(row[5])),
            text=str(row[6]),
            page=row[7],
            timestamp_seconds=row[8],
            artifact_path=row[9],
            metadata=metadata,
            regions=regions,
        )

    def create_document(self, document: Document) -> None:
        with self._tenant_connection(document.tenant_id) as connection:
            connection.execute(
                f"""INSERT INTO {_SCHEMA}.documents ({_DOCUMENT_COLUMNS})
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)""",  # noqa: S608  # nosec B608
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
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND sha256 = %s",
                [tenant_id, sha256],
            ).fetchone()
        return self._document_from_row(row) if row else None

    def get_document(self, tenant_id: str, document_id: str) -> Document | None:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND id = %s",
                [tenant_id, document_id],
            ).fetchone()
        return self._document_from_row(row) if row else None

    def list_documents(self, tenant_id: str, limit: int = 100) -> list[Document]:
        safe_limit = max(1, min(limit, 500))
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
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
        # Reconciliation is a trusted worker-wide operation. With RLS enabled the API role
        # sees no rows here because it deliberately has no tenant session binding.
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE status = ANY(%s) ORDER BY created_at ASC, tenant_id, id LIMIT %s",
                [[status.value for status in statuses], safe_limit],
            ).fetchall()
        return [self._document_from_row(row) for row in rows]

    def ready_document_ids(self, tenant_id: str, document_ids: set[str]) -> set[str]:
        if not document_ids:
            return set()
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"SELECT id FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND status = %s AND id = ANY(%s::uuid[])",
                [tenant_id, DocumentStatus.READY.value, sorted(document_ids)],
            ).fetchall()
        return {str(row[0]) for row in rows}

    def non_ready_document_ids(self, tenant_id: str) -> set[str]:
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"SELECT id FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND status != %s",
                [tenant_id, DocumentStatus.READY.value],
            ).fetchall()
        return {str(row[0]) for row in rows}

    def tenant_usage(self, tenant_id: str) -> tuple[int, int]:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""SELECT COUNT(*), COALESCE(SUM(size_bytes + derived_size_bytes), 0)
                    FROM {_SCHEMA}.documents WHERE tenant_id = %s AND status != %s""",  # noqa: S608  # nosec B608
                [tenant_id, DocumentStatus.FAILED.value],
            ).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def reset_document_for_retry(self, tenant_id: str, document_id: str) -> None:
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"DELETE FROM {_SCHEMA}.storm_events WHERE tenant_id = %s AND document_id = %s",  # noqa: S608  # nosec B608
                [tenant_id, document_id],
            )
            connection.execute(
                f"DELETE FROM {_SCHEMA}.chunks WHERE tenant_id = %s AND document_id = %s",  # noqa: S608  # nosec B608
                [tenant_id, document_id],
            )
            connection.execute(
                f"""UPDATE {_SCHEMA}.documents SET status = %s, error = NULL, chunk_count = 0,
                    warnings_json = '[]'::jsonb, derived_size_bytes = 0
                    WHERE tenant_id = %s AND id = %s""",  # noqa: S608  # nosec B608
                [DocumentStatus.PROCESSING.value, tenant_id, document_id],
            )

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
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"""UPDATE {_SCHEMA}.documents
                    SET status = %s, chunk_count = %s, warnings_json = %s::jsonb, error = %s,
                        derived_size_bytes = COALESCE(%s, derived_size_bytes)
                    WHERE tenant_id = %s AND id = %s""",  # noqa: S608  # nosec B608
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
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"UPDATE {_SCHEMA}.documents SET object_ref = %s "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND id = %s",
                [object_ref, tenant_id, document_id],
            )

    def storm_event_count(self, tenant_id: str) -> int:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"""SELECT COUNT(*) FROM {_SCHEMA}.storm_events AS event
                    WHERE event.tenant_id = %s AND EXISTS (
                        SELECT 1 FROM {_SCHEMA}.documents AS document
                        WHERE document.tenant_id = event.tenant_id
                          AND document.id = event.document_id AND document.status = %s)""",  # noqa: S608  # nosec B608
                [tenant_id, DocumentStatus.READY.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def analytics_sources(self, tenant_id: str, limit: int = 10) -> tuple[list[Document], int]:
        safe_limit = max(1, min(limit, 50))
        with self._tenant_connection(tenant_id) as connection:
            count = connection.execute(
                f"""SELECT COUNT(*) FROM {_SCHEMA}.documents AS document
                    WHERE document.tenant_id = %s AND document.status = %s AND EXISTS (
                        SELECT 1 FROM {_SCHEMA}.storm_events AS event
                        WHERE event.tenant_id = document.tenant_id
                          AND event.document_id = document.id)""",  # noqa: S608  # nosec B608
                [tenant_id, DocumentStatus.READY.value],
            ).fetchone()
            rows = connection.execute(
                f"""SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents AS document
                    WHERE document.tenant_id = %s AND document.status = %s AND EXISTS (
                        SELECT 1 FROM {_SCHEMA}.storm_events AS event
                        WHERE event.tenant_id = document.tenant_id
                          AND event.document_id = document.id)
                    ORDER BY document.created_at DESC LIMIT %s""",  # noqa: S608  # nosec B608
                [tenant_id, DocumentStatus.READY.value, safe_limit],
            ).fetchall()
        return [self._document_from_row(row) for row in rows], int(count[0]) if count else 0

    def purge_failed_documents(self, tenant_id: str, keep: int) -> None:
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"""DELETE FROM {_SCHEMA}.documents WHERE tenant_id = %s AND status = %s
                    AND id IN (SELECT id FROM {_SCHEMA}.documents
                    WHERE tenant_id = %s AND status = %s
                    ORDER BY created_at DESC, id DESC OFFSET %s)""",  # noqa: S608  # nosec B608
                [
                    tenant_id,
                    DocumentStatus.FAILED.value,
                    tenant_id,
                    DocumentStatus.FAILED.value,
                    max(0, keep),
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
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"DELETE FROM {_SCHEMA}.chunks WHERE tenant_id = %s AND document_id = %s",  # noqa: S608  # nosec B608
                [tenant_id, document_id],
            )
            if rows:
                connection.executemany(
                    f"""INSERT INTO {_SCHEMA}.chunks
                        (id, tenant_id, document_id, source_name, source_uri, modality, text, page,
                         timestamp_seconds, artifact_path, metadata_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)""",  # noqa: S608  # nosec B608
                    rows,
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
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"DELETE FROM {_SCHEMA}.storm_events "  # noqa: S608  # nosec B608
                "WHERE tenant_id = %s AND document_id = %s",
                [tenant_id, document_id],
            )
            if rows:
                connection.executemany(
                    f"""INSERT INTO {_SCHEMA}.storm_events
                        (tenant_id, document_id, row_index, event_id, begin_year, state, event_type,
                         cz_name, injuries_direct, deaths_direct, damage_property, damage_crops,
                         magnitude, episode_narrative, raw_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                %s::jsonb)""",  # noqa: S608  # nosec B608
                    rows,
                )

    def get_chunks(self, tenant_id: str, chunk_ids: list[str]) -> list[Chunk]:
        if not chunk_ids:
            return []
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"""SELECT id, tenant_id, document_id, source_name, source_uri, modality, text,
                    page, timestamp_seconds, artifact_path, metadata_json FROM {_SCHEMA}.chunks
                    WHERE tenant_id = %s AND id = ANY(%s::uuid[])""",  # noqa: S608  # nosec B608
                [tenant_id, chunk_ids],
            ).fetchall()
        by_id = {str(row[0]): self._chunk_from_row(row) for row in rows}
        return [by_id[item] for item in chunk_ids if item in by_id]

    def artifact_references(self, tenant_id: str, document_id: str) -> list[str]:
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"""SELECT DISTINCT artifact_path FROM {_SCHEMA}.chunks
                    WHERE tenant_id = %s AND document_id = %s AND artifact_path IS NOT NULL""",  # noqa: S608  # nosec B608
                [tenant_id, document_id],
            ).fetchall()
        return [str(row[0]) for row in rows]

    def delete_document(self, tenant_id: str, document_id: str) -> bool:
        with self._tenant_connection(tenant_id) as connection:
            result = connection.execute(
                f"DELETE FROM {_SCHEMA}.documents WHERE tenant_id = %s AND id = %s",  # noqa: S608  # nosec B608
                [tenant_id, document_id],
            )
            return cast(int, result.rowcount) == 1

    def sha_reference_count(self, sha256: str) -> int:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE sha256 = %s AND status != %s",
                [sha256, DocumentStatus.FAILED.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def object_reference_count(self, object_ref: str) -> int:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                "WHERE object_ref = %s AND status != %s",
                [object_ref, DocumentStatus.FAILED.value],
            ).fetchone()
        return int(row[0]) if row else 0

    def execute_safe_analytics(
        self, tenant_id: str, proposed_sql: str, max_rows: int = 100
    ) -> tuple[str, list[dict[str, Any]]]:
        result = self._execute_safe_analytics(
            tenant_id, proposed_sql, max_rows=max_rows, source_limit=0
        )
        return result.sql, result.rows

    def execute_safe_analytics_with_sources(
        self,
        tenant_id: str,
        proposed_sql: str,
        max_rows: int = 100,
        source_limit: int = 10,
    ) -> AnalyticsResult:
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
        tree = sqlglot.parse_one(safe_sql, read="duckdb")
        for table in tree.find_all(exp.Table):
            table.set("db", exp.to_identifier(_SCHEMA))
            table.set("this", exp.to_identifier("storm_events"))
        tenant_predicate: exp.Expression = exp.column("tenant_id").eq(exp.Placeholder())
        existing_where = tree.args.get("where")
        if existing_where:
            tenant_predicate = exp.and_(existing_where.this, tenant_predicate)
        ready_query = (
            exp.select("id")
            .from_(f"{_SCHEMA}.documents")
            .where(
                exp.and_(
                    exp.column("tenant_id").eq(exp.Placeholder()),
                    exp.column("status").eq(exp.Literal.string(DocumentStatus.READY.value)),
                )
            )
        )
        ready_predicate = exp.In(
            this=exp.column("document_id"), query=exp.Subquery(this=ready_query)
        )
        tree.set("where", exp.Where(this=exp.and_(tenant_predicate, ready_predicate)))
        for rounding in tree.find_all(exp.Round):
            if rounding.args.get("decimals") is not None:
                rounding.set(
                    "this",
                    exp.Cast(this=rounding.this.copy(), to=exp.DataType.build("NUMERIC")),
                )
        lineage_alias = "__crisisweave_source_ids"
        count_alias = "__crisisweave_source_count"
        aggregate_lineage = False
        if source_limit:
            aggregate_lineage = (
                any(tree.find_all(exp.AggFunc)) or tree.args.get("group") is not None
            )
            if aggregate_lineage:
                lineage = sqlglot.parse_one(
                    "SELECT (ARRAY_AGG(DISTINCT document_id ORDER BY document_id))"
                    f"[1:{source_limit}] AS {lineage_alias}, "
                    f"COUNT(DISTINCT document_id) AS {count_alias}",
                    read="postgres",
                ).expressions
            else:
                lineage = [exp.alias_(exp.column("document_id"), lineage_alias, quoted=False)]
            tree.set("expressions", [*tree.expressions, *lineage])
        execution_sql = tree.sql(dialect="postgres")
        try:
            with self._tenant_connection(tenant_id) as connection:
                connection.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    [str(max(1, int(self._analytics_timeout_seconds * 1000)))],
                )
                cursor = connection.execute(execution_sql, [tenant_id, tenant_id])
                columns = [item.name for item in cursor.description or ()]
                hidden = {index for index, name in enumerate(columns) if name == lineage_alias}
                lineage_index = columns.index(lineage_alias) if source_limit else None
                count_index = columns.index(count_alias) if aggregate_lineage else None
                if count_index is not None:
                    hidden.add(count_index)
                visible_columns = [
                    name for index, name in enumerate(columns) if index not in hidden
                ]
                if len({column.casefold() for column in visible_columns}) != len(visible_columns):
                    raise SecurityError("Analytics result columns must have unique names")
                visible_indexes = [index for index in range(len(columns)) if index not in hidden]
                result_rows: list[tuple[Any, ...]] = []
                result_size = 2
                while row := cursor.fetchone():
                    for column, index in zip(visible_columns, visible_indexes, strict=True):
                        cell = _analytics_json(row[index])
                        if len(cell) > self._max_analytics_cell_bytes:
                            raise SecurityError("Analytics result cell exceeded its byte budget")
                        result_size += len(column.encode("utf-8")) + len(cell) + 4
                    if result_size > self._max_analytics_result_bytes:
                        raise SecurityError("Analytics result exceeded its byte budget")
                    result_rows.append(row)
                rows, source_ids, source_rows, source_count, exact = self._lineage_rows(
                    result_rows,
                    columns,
                    visible_columns,
                    visible_indexes,
                    lineage_index,
                    count_index,
                    aggregate_lineage,
                )
                selected_ids = sorted(source_ids)[:source_limit]
                documents: list[Document] = []
                if selected_ids:
                    document_rows = connection.execute(
                        f"SELECT {_DOCUMENT_COLUMNS} FROM {_SCHEMA}.documents "  # noqa: S608  # nosec B608
                        "WHERE tenant_id = %s AND status = %s AND id = ANY(%s::uuid[])",
                        [tenant_id, DocumentStatus.READY.value, selected_ids],
                    ).fetchall()
                    by_id = {str(row[0]): self._document_from_row(row) for row in document_rows}
                    documents = [by_id[item] for item in selected_ids if item in by_id]
        except SecurityError:
            raise
        except self._psycopg.Error as exc:
            if getattr(exc, "sqlstate", None) == "57014":
                raise SecurityError("Analytics query exceeded its execution budget") from exc
            raise SecurityError("Analytics query failed safely") from exc
        return AnalyticsResult(
            sql=safe_sql,
            rows=rows,
            sources=documents,
            source_rows={key: source_rows[key] for key in selected_ids if key in source_rows},
            source_count=source_count,
            source_count_exact=exact,
        )

    @staticmethod
    def _lineage_rows(
        result_rows: list[tuple[Any, ...]],
        columns: list[str],
        visible_columns: list[str],
        visible_indexes: list[int],
        lineage_index: int | None,
        count_index: int | None,
        aggregate_lineage: bool,
    ) -> tuple[list[dict[str, Any]], set[str], dict[str, list[dict[str, Any]]], int, bool]:
        if lineage_index is None:
            return (
                [dict(zip(columns, row, strict=True)) for row in result_rows],
                set(),
                {},
                0,
                True,
            )
        rows: list[dict[str, Any]] = []
        source_ids: set[str] = set()
        source_rows: dict[str, list[dict[str, Any]]] = {}
        counts: list[int] = []
        truncated = False
        for result_row in result_rows:
            raw_lineage = result_row[lineage_index]
            row_ids = (
                {str(value) for value in raw_lineage}
                if isinstance(raw_lineage, list)
                else {str(raw_lineage)}
            )
            row_ids.discard("None")
            source_ids.update(row_ids)
            if count_index is not None:
                count = int(result_row[count_index])
                counts.append(count)
                truncated |= count > len(row_ids)
            visible = dict(
                zip(
                    visible_columns,
                    [result_row[index] for index in visible_indexes],
                    strict=True,
                )
            )
            rows.append(visible)
            for source_id in row_ids:
                source_rows.setdefault(source_id, []).append(visible)
        exact = not aggregate_lineage or len(counts) <= 1 or not truncated
        source_count = max([len(source_ids), *counts], default=0)
        if exact and len(counts) > 1:
            source_count = len(source_ids)
        return rows, source_ids, source_rows, source_count, exact

    def healthcheck(self) -> bool:
        try:
            with self._pool.connection() as connection:
                return bool(connection.execute("SELECT 1").fetchone() == (1,))
        except self._psycopg.Error:
            return False

    def record_query_audit(
        self,
        tenant_id: str,
        query: str,
        routes: list[str],
        citation_count: int,
        duration_ms: float,
        policy_flags: list[str],
    ) -> None:
        with self._tenant_connection(tenant_id) as connection:
            connection.execute(
                f"""INSERT INTO {_SCHEMA}.query_audit
                    (id, tenant_id, query_sha256, routes_json, citation_count, duration_ms,
                     policy_flags_json) VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s::jsonb)""",  # noqa: S608  # nosec B608
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
                connection.execute(
                    f"""DELETE FROM {_SCHEMA}.query_audit
                        WHERE created_at < current_timestamp - (%s * INTERVAL '1 day')""",  # noqa: S608  # nosec B608
                    [self._audit_retention_days],
                )
                connection.execute(
                    f"""DELETE FROM {_SCHEMA}.query_audit WHERE id IN (
                        SELECT id FROM {_SCHEMA}.query_audit
                        ORDER BY created_at DESC OFFSET %s)""",  # noqa: S608  # nosec B608
                    [self._max_audit_rows],
                )
                self._last_audit_prune = now

    @contextmanager
    def tenant_lock(self, tenant_id: str) -> Iterator[None]:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        digest = hashlib.sha256(f"crisisweave:{tenant_id}".encode()).digest()[:8]
        lock_id = int.from_bytes(digest, "big", signed=True)
        deadline = time.monotonic() + self._lock_timeout_seconds
        with self._pool.connection() as connection:
            acquired = False
            try:
                while time.monotonic() < deadline:
                    row = connection.execute(
                        "SELECT pg_try_advisory_lock(%s)", [lock_id]
                    ).fetchone()
                    if row and bool(row[0]):
                        acquired = True
                        break
                    time.sleep(0.05)
                if not acquired:
                    raise SecurityError("Timed out waiting for the tenant ingestion lock")
                yield
            finally:
                if acquired:
                    connection.execute("SELECT pg_advisory_unlock(%s)", [lock_id])

    @contextmanager
    def try_tenant_lock(self, tenant_id: str) -> Iterator[bool]:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        digest = hashlib.sha256(f"crisisweave:{tenant_id}".encode()).digest()[:8]
        lock_id = int.from_bytes(digest, "big", signed=True)
        with self._pool.connection() as connection:
            row = connection.execute("SELECT pg_try_advisory_lock(%s)", [lock_id]).fetchone()
            acquired = bool(row and row[0])
            try:
                yield acquired
            finally:
                if acquired:
                    connection.execute("SELECT pg_advisory_unlock(%s)", [lock_id])

    def close(self) -> None:
        self._pool.close()


def _analytics_json(value: Any) -> bytes:
    if isinstance(value, float) and not math.isfinite(value):
        raise SecurityError("Analytics result contained a non-finite number")
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise SecurityError("Analytics result could not be serialized safely") from exc
