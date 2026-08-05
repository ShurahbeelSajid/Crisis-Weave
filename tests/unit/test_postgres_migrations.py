from __future__ import annotations

import sys
import types
from contextlib import contextmanager
from typing import Any

import pytest

from crisisweave.job_store import PostgresIngestionJobStore
from crisisweave.postgres_migrations import (
    LATEST_SCHEMA_VERSION,
    grant_runtime_privileges,
    migrate_postgres,
)
from crisisweave.postgres_storage import PostgresMetadataStore


class Result:
    def __init__(self, row: tuple[object, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class Connection:
    def __init__(self, *, version: int = LATEST_SCHEMA_VERSION) -> None:
        self.version = version
        self.executions: list[tuple[str, object]] = []

    @contextmanager
    def transaction(self):  # type: ignore[no-untyped-def]
        yield

    def execute(self, statement: str, parameters: object = None) -> Result:
        compact = " ".join(statement.split())
        self.executions.append((compact, parameters))
        if compact == "SELECT MAX(version) FROM crisisweave.schema_migrations":
            return Result((self.version,))
        if compact.startswith("SELECT COUNT(*) AS role_count"):
            return Result((2, False))
        if compact == "SELECT current_user":
            return Result(("crisisweave_migration",))
        return Result()


class Pool:
    def __init__(self, connection: Connection) -> None:
        self.value = connection
        self.closed = False
        self.waited: list[float] = []
        self.kwargs: dict[str, Any] = {}

    @contextmanager
    def connection(self):  # type: ignore[no-untyped-def]
        yield self.value

    def wait(self, timeout: float) -> None:
        self.waited.append(timeout)

    def close(self) -> None:
        self.closed = True


def _install_pool_modules(
    monkeypatch: pytest.MonkeyPatch,
    pool: Pool,
) -> None:
    psycopg = types.ModuleType("psycopg")
    psycopg.Error = RuntimeError  # type: ignore[attr-defined]
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = object()  # type: ignore[attr-defined]
    pool_module = types.ModuleType("psycopg_pool")

    def connection_pool(**kwargs: Any) -> Pool:
        pool.kwargs = kwargs
        return pool

    pool_module.ConnectionPool = connection_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows)
    monkeypatch.setitem(sys.modules, "psycopg_pool", pool_module)


def test_explicit_migration_applies_all_schema_and_dml_only_grants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert LATEST_SCHEMA_VERSION == 5
    connection = Connection()
    pool = Pool(connection)
    _install_pool_modules(monkeypatch, pool)

    migrate_postgres(
        "postgresql://migrator.invalid/app",
        api_role="crisisweave_api",
        worker_role="crisisweave_worker",
        timeout_seconds=3.0,
        enable_rls=True,
    )

    statements = "\n".join(statement for statement, _ in connection.executions)
    assert connection.executions[0][0] == "SELECT pg_advisory_xact_lock(%s)"
    assert "CREATE TABLE IF NOT EXISTS crisisweave.documents" in statements
    assert "CREATE INDEX IF NOT EXISTS documents_status_created" in statements
    assert "CREATE TABLE IF NOT EXISTS crisisweave.ingestion_jobs" in statements
    assert "CREATE TABLE IF NOT EXISTS crisisweave.ingestion_orphan_cleanup" in statements
    assert "CREATE TABLE IF NOT EXISTS crisisweave.ingestion_lifecycle_outbox" in statements
    assert "ADD COLUMN IF NOT EXISTS lifecycle_started_at" in statements
    assert "INSERT INTO crisisweave.ingestion_lifecycle_outbox" in statements
    assert "ADD COLUMN IF NOT EXISTS usage_estimated" in statements
    assert "VALUES (5)" in statements
    assert "CREATE TABLE IF NOT EXISTS crisisweave.identity_events" in statements
    assert "CREATE TABLE IF NOT EXISTS crisisweave.review_records" in statements
    assert "ALTER TABLE crisisweave.documents ENABLE ROW LEVEL SECURITY" in statements
    assert "ALTER TABLE crisisweave.documents FORCE ROW LEVEL SECURITY" in statements
    assert "current_setting('crisisweave.tenant_id', true)" in statements
    assert "REVOKE CREATE ON SCHEMA crisisweave" in statements
    assert "GRANT SELECT ON TABLE crisisweave.schema_migrations" in statements
    assert "GRANT INSERT, DELETE ON TABLE crisisweave.query_audit" in statements
    assert "GRANT SELECT, UPDATE, DELETE ON TABLE crisisweave.documents" in statements
    assert "crisisweave.ingestion_lifecycle_outbox" in statements
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" not in statements
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES" not in statements
    assert "GRANT ALL" not in statements
    audit_grant = next(
        statement
        for statement, _ in connection.executions
        if "GRANT INSERT, DELETE ON TABLE crisisweave.query_audit" in statement
    )
    assert '"crisisweave_api"' in audit_grant
    assert '"crisisweave_worker"' not in audit_grant
    api_outbox_grants = [
        statement
        for statement, _ in connection.executions
        if "GRANT" in statement
        and "crisisweave.ingestion_lifecycle_outbox" in statement
        and '"crisisweave_api"' in statement
    ]
    assert api_outbox_grants == [
        'GRANT INSERT ON TABLE crisisweave.ingestion_lifecycle_outbox TO "crisisweave_api"'
    ]
    assert pool.waited == [3.0]
    assert pool.closed


def test_migration_rejects_unsafe_role_identifier_before_grant() -> None:
    connection = Connection()
    with pytest.raises(ValueError, match="canonical"):
        grant_runtime_privileges(
            connection,
            api_role='api"; DROP SCHEMA public; --',
            worker_role="worker",
        )
    assert connection.executions == []


def test_migration_refuses_runtime_owned_schema_objects() -> None:
    class RuntimeOwnedConnection(Connection):
        def execute(self, statement: str, parameters: object = None) -> Result:
            result = super().execute(statement, parameters)
            if "SELECT EXISTS" in statement:
                return Result((True,))
            return result

    connection = RuntimeOwnedConnection()
    with pytest.raises(RuntimeError, match="transfer ownership"):
        grant_runtime_privileges(
            connection,
            api_role="crisisweave_api",
            worker_role="crisisweave_worker",
        )
    statements = "\n".join(statement for statement, _ in connection.executions)
    assert "GRANT " not in statements


def test_migration_refuses_runtime_roles_that_bypass_rls() -> None:
    class BypassConnection(Connection):
        def execute(self, statement: str, parameters: object = None) -> Result:
            result = super().execute(statement, parameters)
            if "SELECT COUNT(*) AS role_count" in statement:
                return Result((2, True))
            return result

    connection = BypassConnection()
    with pytest.raises(RuntimeError, match="SUPERUSER or BYPASSRLS"):
        grant_runtime_privileges(
            connection,
            api_role="crisisweave_api",
            worker_role="crisisweave_worker",
        )
    assert not any("GRANT " in statement for statement, _ in connection.executions)


@pytest.mark.parametrize("store_kind", ["metadata", "jobs"])
def test_production_store_startup_verifies_version_without_ddl(
    monkeypatch: pytest.MonkeyPatch,
    store_kind: str,
) -> None:
    connection = Connection()
    pool = Pool(connection)
    _install_pool_modules(monkeypatch, pool)

    if store_kind == "metadata":
        store = PostgresMetadataStore(
            "postgresql://runtime.invalid/app",
            pool_timeout_seconds=2.0,
            migrate_on_startup=False,
        )
    else:
        store = PostgresIngestionJobStore(
            "postgresql://runtime.invalid/app",
            min_size=1,
            max_size=2,
            timeout_seconds=2.0,
            migrate_on_startup=False,
        )
    try:
        assert [item[0] for item in connection.executions] == [
            "SELECT MAX(version) FROM crisisweave.schema_migrations"
        ]
    finally:
        store.close()


def test_validate_only_startup_rejects_outdated_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = Connection(version=LATEST_SCHEMA_VERSION - 1)
    pool = Pool(connection)
    _install_pool_modules(monkeypatch, pool)
    with pytest.raises(RuntimeError, match="outdated"):
        PostgresMetadataStore(
            "postgresql://runtime.invalid/app",
            migrate_on_startup=False,
        )
