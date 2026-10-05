from __future__ import annotations

import sys
import types
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

import crisisweave.postgres_storage as postgres_storage
from crisisweave.models import Chunk, Document, DocumentStatus, Modality
from crisisweave.postgres_storage import PostgresMetadataStore
from crisisweave.security import SecurityError


class _Result:
    def __init__(
        self,
        rows: list[tuple[Any, ...]] | None = None,
        *,
        rowcount: int = 0,
        columns: tuple[str, ...] = (),
    ) -> None:
        self.rows = list(rows or [])
        self.rowcount = rowcount
        self.description = [SimpleNamespace(name=name) for name in columns]

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self.rows = self.rows, []
        return rows


class _Pool:
    def __init__(self, connection: Any) -> None:
        self.value = connection
        self.closed = False

    @contextmanager
    def connection(self) -> Iterator[Any]:
        yield self.value

    def close(self) -> None:
        self.closed = True


def _document_row(tenant_id: str, document_id: str) -> tuple[Any, ...]:
    return (
        document_id,
        tenant_id,
        "evidence.pdf",
        "application/pdf",
        "a" * 64,
        17,
        DocumentStatus.READY.value,
        "https://example.test/evidence",
        datetime(2026, 1, 2, tzinfo=UTC),
        None,
        1,
        '["bounded warning"]',
        9,
        "s3://evidence/exact?versionId=1",
    )


class _CrudConnection:
    def __init__(self, tenant_id: str, document_id: str, chunk_id: str) -> None:
        self.tenant_id = tenant_id
        self.document_id = document_id
        self.chunk_id = chunk_id
        self.executions: list[tuple[str, Any]] = []
        self.many: list[tuple[str, list[tuple[Any, ...]]]] = []
        self.delete_rowcount = 1

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def execute(self, sql: str, parameters: Any = None) -> _Result:
        compact = " ".join(sql.split())
        self.executions.append((compact, parameters))
        if "COALESCE(SUM(size_bytes + derived_size_bytes)" in compact:
            return _Result([(2, 52)])
        if compact.startswith("SELECT COUNT(*) FROM crisisweave.storm_events"):
            return _Result([(7,)])
        if compact.startswith("SELECT COUNT(*) FROM crisisweave.documents AS document"):
            return _Result([(1,)])
        if "SELECT id FROM crisisweave.documents" in compact:
            return _Result([(self.document_id,)])
        if compact.startswith("SELECT DISTINCT artifact_path"):
            return _Result([("s3://evidence/frame?versionId=2",)])
        if compact.startswith("SELECT id, tenant_id, document_id, source_name"):
            return _Result(
                [
                    (
                        self.chunk_id,
                        self.tenant_id,
                        self.document_id,
                        "evidence.pdf",
                        None,
                        Modality.TEXT.value,
                        "trusted passage",
                        2,
                        None,
                        None,
                        '{"kind":"paragraph"}',
                    )
                ]
            )
        if compact.startswith("SELECT id, tenant_id, filename"):
            return _Result([_document_row(self.tenant_id, self.document_id)])
        if compact.startswith("SELECT COUNT(*) FROM crisisweave.documents"):
            return _Result([(1,)])
        if compact.startswith("DELETE FROM crisisweave.documents"):
            return _Result(rowcount=self.delete_rowcount)
        return _Result(rowcount=1)

    def executemany(self, sql: str, rows: list[tuple[Any, ...]]) -> None:
        self.many.append((" ".join(sql.split()), rows))


def _store(connection: Any) -> PostgresMetadataStore:
    store = object.__new__(PostgresMetadataStore)
    store._pool = _Pool(connection)  # noqa: SLF001
    store._psycopg = SimpleNamespace(Error=RuntimeError)  # noqa: SLF001
    store._analytics_timeout_seconds = 1.0  # noqa: SLF001
    store._max_analytics_result_bytes = 4096  # noqa: SLF001
    store._max_analytics_cell_bytes = 1024  # noqa: SLF001
    store._audit_retention_days = 30  # noqa: SLF001
    store._max_audit_rows = 100  # noqa: SLF001
    store._last_audit_prune = 0.0  # noqa: SLF001
    store._lock_timeout_seconds = 0.05  # noqa: SLF001
    return store


def test_postgres_initialization_applies_schema_under_migration_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InitConnection:
        def __init__(self) -> None:
            self.executions: list[tuple[str, Any]] = []

        @contextmanager
        def transaction(self) -> Iterator[None]:
            yield

        def execute(self, sql: str, parameters: Any = None) -> _Result:
            self.executions.append((" ".join(sql.split()), parameters))
            return _Result()

    class InitPool(_Pool):
        def __init__(self, connection: Any) -> None:
            super().__init__(connection)
            self.waits: list[float] = []
            self.kwargs: dict[str, Any] = {}

        def wait(self, timeout: float) -> None:
            self.waits.append(timeout)

    connection = InitConnection()
    pool = InitPool(connection)
    psycopg = types.ModuleType("psycopg")
    psycopg.Error = RuntimeError  # type: ignore[attr-defined]
    psycopg_pool = types.ModuleType("psycopg_pool")

    def connection_pool(**kwargs: Any) -> InitPool:
        pool.kwargs = kwargs
        return pool

    psycopg_pool.ConnectionPool = connection_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg_pool", psycopg_pool)

    store = PostgresMetadataStore(
        "postgresql://db.invalid/app",
        pool_min_size=2,
        pool_max_size=4,
        pool_timeout_seconds=2.5,
    )

    assert pool.waits == [2.5]
    assert pool.kwargs["min_size"] == 2
    assert pool.kwargs["max_size"] == 4
    assert pool.kwargs["kwargs"] == {"autocommit": True}
    statements = [sql for sql, _ in connection.executions]
    assert statements[0] == "SELECT pg_advisory_xact_lock(%s)"
    assert connection.executions[0][1] == [2_047_374_611]
    assert any("PRIMARY KEY (tenant_id, id)" in sql for sql in statements)
    assert any("schema_migrations" in sql for sql in statements)

    store.close()
    assert pool.closed


def test_postgres_crud_and_lineage_methods_bind_tenant_parameters() -> None:
    tenant_id = "b" * 32
    document_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    connection = _CrudConnection(tenant_id, document_id, chunk_id)
    store = _store(connection)
    document = Document(
        id=document_id,
        tenant_id=tenant_id,
        filename="evidence.pdf",
        media_type="application/pdf",
        sha256="a" * 64,
        size_bytes=17,
        status=DocumentStatus.PROCESSING,
        warnings=["bounded warning"],
    )

    store.create_document(document)
    assert store.find_document_by_sha(tenant_id, document.sha256) is not None
    assert store.get_document(tenant_id, document_id) is not None
    assert store.list_documents(tenant_id, limit=999)[0].tenant_id == tenant_id
    assert store.list_documents_by_status(()) == []
    assert store.list_documents_by_status((DocumentStatus.READY,))[0].id == document_id
    assert store.ready_document_ids(tenant_id, set()) == set()
    assert store.ready_document_ids(tenant_id, {document_id}) == {document_id}
    assert store.non_ready_document_ids(tenant_id) == {document_id}
    assert store.tenant_usage(tenant_id) == (2, 52)

    store.reset_document_for_retry(tenant_id, document_id)
    store.mark_document(
        tenant_id,
        document_id,
        DocumentStatus.READY,
        chunk_count=1,
        derived_size_bytes=9,
        warnings=["ocr"],
    )
    store.set_document_object_ref(tenant_id, document_id, "s3://exact?versionId=1")
    assert store.storm_event_count(tenant_id) == 7
    sources, source_count = store.analytics_sources(tenant_id, limit=100)
    assert source_count == 1
    assert [source.id for source in sources] == [document_id]
    store.purge_failed_documents(tenant_id, keep=-1)

    chunk = Chunk(
        id=chunk_id,
        tenant_id=tenant_id,
        document_id=document_id,
        source_name="evidence.pdf",
        modality=Modality.TEXT,
        text="trusted passage",
        metadata={"kind": "paragraph"},
    )
    store.replace_chunks(tenant_id, document_id, [chunk])
    store.replace_chunks(tenant_id, document_id, [])
    store.replace_storm_events(
        tenant_id,
        document_id,
        [{"event_id": "E-1", "state": "Sindh", "raw": {"source": "fixture"}}],
    )
    store.replace_storm_events(tenant_id, document_id, [])
    assert store.get_chunks(tenant_id, []) == []
    chunks = store.get_chunks(tenant_id, [chunk_id, str(uuid.uuid4())])
    assert [item.id for item in chunks] == [chunk_id]
    assert chunks[0].metadata == {"kind": "paragraph"}
    assert store.artifact_references(tenant_id, document_id) == ["s3://evidence/frame?versionId=2"]
    assert store.sha_reference_count(document.sha256) == 1
    assert store.object_reference_count("s3://exact?versionId=1") == 1
    assert store.delete_document(tenant_id, document_id)
    connection.delete_rowcount = 0
    assert not store.delete_document(tenant_id, document_id)

    assert connection.many and len(connection.many) == 2
    assert any(parameters == [tenant_id, 500] for _, parameters in connection.executions)
    assert all(
        tenant_id in parameters
        for sql, parameters in connection.executions
        if "WHERE tenant_id = %s" in sql and isinstance(parameters, list)
    )


class _DatabaseError(Exception):
    def __init__(self, sqlstate: str | None = None) -> None:
        super().__init__("database unavailable")
        self.sqlstate = sqlstate


class _AnalyticsFailureConnection:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def execute(self, _sql: str, _parameters: Any = None) -> _Result:
        self.calls += 1
        if self.calls == 1:
            return _Result()
        raise self.error


@pytest.mark.parametrize(
    ("sqlstate", "message"),
    [("57014", "execution budget"), (None, "failed safely")],
)
def test_postgres_analytics_normalizes_database_errors(sqlstate: str | None, message: str) -> None:
    connection = _AnalyticsFailureConnection(_DatabaseError(sqlstate))
    store = _store(connection)
    store._psycopg = SimpleNamespace(Error=_DatabaseError)  # noqa: SLF001

    with pytest.raises(SecurityError, match=message):
        store.execute_safe_analytics(
            "c" * 32,
            "SELECT COUNT(*) AS event_count FROM authorized_storm_events",
        )


def test_postgres_health_audit_and_analytics_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "d" * 32
    document_id = str(uuid.uuid4())
    connection = _CrudConnection(tenant_id, document_id, str(uuid.uuid4()))
    store = _store(connection)

    monkeypatch.setattr(postgres_storage.time, "monotonic", lambda: 4001.0)
    store.record_query_audit(
        tenant_id,
        "How many events?",
        ["sql"],
        1,
        2.5,
        ["bounded"],
    )
    audit_sql = [sql for sql, _ in connection.executions if "query_audit" in sql]
    assert len(audit_sql) == 3

    class HealthConnection:
        def __init__(self, result: tuple[int, ...] | Exception) -> None:
            self.result = result

        def execute(self, _sql: str) -> _Result:
            if isinstance(self.result, Exception):
                raise self.result
            return _Result([self.result])

    healthy = _store(HealthConnection((1,)))
    unhealthy = _store(HealthConnection((0,)))
    failed = _store(HealthConnection(_DatabaseError()))
    failed._psycopg = SimpleNamespace(Error=_DatabaseError)  # noqa: SLF001
    assert healthy.healthcheck()
    assert not unhealthy.healthcheck()
    assert not failed.healthcheck()

    with pytest.raises(SecurityError, match="Tenant identifier"):
        store.execute_safe_analytics("../other", "SELECT state FROM authorized_storm_events")
    with pytest.raises(SecurityError, match="Tenant identifier"), store.tenant_lock("../other"):
        pass
    with pytest.raises(SecurityError, match="Tenant identifier"), store.try_tenant_lock("../other"):
        pass


def test_postgres_lineage_and_json_budget_helpers_reject_unsafe_values() -> None:
    first_id = str(uuid.uuid4())
    second_id = str(uuid.uuid4())
    rows, source_ids, source_rows, source_count, exact = PostgresMetadataStore._lineage_rows(  # noqa: SLF001
        [("Sindh", [first_id], 2), ("Punjab", [second_id], 1)],
        ["state", "lineage", "count"],
        ["state"],
        [0],
        1,
        2,
        True,
    )
    assert rows == [{"state": "Sindh"}, {"state": "Punjab"}]
    assert source_ids == {first_id, second_id}
    assert source_rows[first_id] == [{"state": "Sindh"}]
    assert source_count == 2
    assert not exact

    exact_result = PostgresMetadataStore._lineage_rows(  # noqa: SLF001
        [("Sindh", first_id, 1), ("Punjab", second_id, 1)],
        ["state", "lineage", "count"],
        ["state"],
        [0],
        1,
        2,
        True,
    )
    assert exact_result[3:] == (2, True)

    with pytest.raises(SecurityError, match="non-finite"):
        postgres_storage._analytics_json(float("nan"))  # noqa: SLF001
    circular: list[Any] = []
    circular.append(circular)
    with pytest.raises(SecurityError, match="serialized safely"):
        postgres_storage._analytics_json(circular)  # noqa: SLF001
