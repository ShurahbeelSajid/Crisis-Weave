"""Explicit PostgreSQL schema migrations for privileged deployment jobs only."""

from __future__ import annotations

import re
from typing import Any

MIGRATION_LOCK = 2_047_374_611
LATEST_SCHEMA_VERSION = 5

_METADATA_STATEMENTS = (
    "CREATE SCHEMA IF NOT EXISTS crisisweave",
    """CREATE TABLE IF NOT EXISTS crisisweave.schema_migrations (
           version INTEGER PRIMARY KEY,
           applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
       )""",
    """CREATE TABLE IF NOT EXISTS crisisweave.documents (
           id UUID NOT NULL,
           tenant_id VARCHAR(32) NOT NULL,
           filename TEXT NOT NULL,
           media_type TEXT NOT NULL,
           sha256 CHAR(64) NOT NULL,
           size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
           status TEXT NOT NULL,
           source_uri TEXT,
           created_at TIMESTAMPTZ NOT NULL,
           error TEXT,
           chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
           warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
           derived_size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (derived_size_bytes >= 0),
           object_ref TEXT,
           PRIMARY KEY (tenant_id, id),
           UNIQUE (tenant_id, sha256)
       )""",
    """CREATE INDEX IF NOT EXISTS documents_status_created
           ON crisisweave.documents (status, created_at, tenant_id, id)""",
    """CREATE TABLE IF NOT EXISTS crisisweave.chunks (
           id UUID NOT NULL,
           tenant_id VARCHAR(32) NOT NULL,
           document_id UUID NOT NULL,
           source_name TEXT NOT NULL,
           source_uri TEXT,
           modality TEXT NOT NULL,
           text TEXT NOT NULL,
           page INTEGER,
           timestamp_seconds DOUBLE PRECISION,
           artifact_path TEXT,
           metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
           PRIMARY KEY (tenant_id, id),
           FOREIGN KEY (tenant_id, document_id)
             REFERENCES crisisweave.documents (tenant_id, id) ON DELETE CASCADE
       )""",
    """CREATE INDEX IF NOT EXISTS chunks_tenant_document
           ON crisisweave.chunks (tenant_id, document_id)""",
    """CREATE TABLE IF NOT EXISTS crisisweave.storm_events (
           tenant_id VARCHAR(32) NOT NULL,
           document_id UUID NOT NULL,
           row_index INTEGER NOT NULL CHECK (row_index >= 0),
           event_id TEXT,
           begin_year INTEGER,
           state TEXT,
           event_type TEXT,
           cz_name TEXT,
           injuries_direct DOUBLE PRECISION,
           deaths_direct DOUBLE PRECISION,
           damage_property DOUBLE PRECISION,
           damage_crops DOUBLE PRECISION,
           magnitude DOUBLE PRECISION,
           episode_narrative TEXT,
           raw_json JSONB NOT NULL,
           PRIMARY KEY (tenant_id, document_id, row_index),
           FOREIGN KEY (tenant_id, document_id)
             REFERENCES crisisweave.documents (tenant_id, id) ON DELETE CASCADE
       )""",
    """CREATE INDEX IF NOT EXISTS storm_events_tenant_document
           ON crisisweave.storm_events (tenant_id, document_id)""",
    """CREATE TABLE IF NOT EXISTS crisisweave.query_audit (
           id UUID PRIMARY KEY,
           tenant_id VARCHAR(32) NOT NULL,
           created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
           query_sha256 CHAR(64) NOT NULL,
           routes_json JSONB NOT NULL,
           citation_count INTEGER NOT NULL CHECK (citation_count >= 0),
           duration_ms DOUBLE PRECISION NOT NULL CHECK (duration_ms >= 0),
           policy_flags_json JSONB NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS query_audit_tenant_created
           ON crisisweave.query_audit (tenant_id, created_at DESC)""",
    """INSERT INTO crisisweave.schema_migrations (version) VALUES (1)
           ON CONFLICT (version) DO NOTHING""",
)

_JOB_STATEMENTS = (
    """DO $migration$
       BEGIN
           IF to_regclass('crisisweave.ingestion_jobs') IS NULL
              AND to_regclass('public.ingestion_jobs') IS NOT NULL THEN
               EXECUTE 'ALTER TABLE public.ingestion_jobs SET SCHEMA crisisweave';
           END IF;
       END
       $migration$""",
    """CREATE TABLE IF NOT EXISTS crisisweave.ingestion_jobs (
           id UUID PRIMARY KEY,
           tenant_id VARCHAR(32) NOT NULL,
           filename VARCHAR(255) NOT NULL,
           source_uri TEXT,
           input_object_ref TEXT NOT NULL,
           sha256 VARCHAR(64) NOT NULL,
           size_bytes BIGINT NOT NULL CHECK(size_bytes > 0),
           status VARCHAR(24) NOT NULL,
           progress SMALLINT NOT NULL CHECK(progress BETWEEN 0 AND 100),
           stage VARCHAR(80) NOT NULL,
           attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
           max_attempts INTEGER NOT NULL CHECK(max_attempts >= 1),
           available_at TIMESTAMPTZ NOT NULL,
           lease_owner VARCHAR(128),
           lease_expires_at TIMESTAMPTZ,
           cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
           document_id UUID,
           error_code VARCHAR(80),
           input_cleanup_pending BOOLEAN NOT NULL DEFAULT FALSE,
           delete_requested BOOLEAN NOT NULL DEFAULT FALSE,
           lifecycle_started_at TIMESTAMPTZ NOT NULL,
           lifecycle_generation INTEGER NOT NULL DEFAULT 1
             CONSTRAINT ingestion_jobs_lifecycle_generation_valid
             CHECK(lifecycle_generation >= 1),
           processing_seconds DOUBLE PRECISION NOT NULL DEFAULT 0
             CONSTRAINT ingestion_jobs_processing_seconds_finite
             CHECK(processing_seconds >= 0
                   AND processing_seconds < 'Infinity'::double precision),
           compute_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0
             CONSTRAINT ingestion_jobs_compute_cost_finite
             CHECK(compute_cost_usd >= 0
                   AND compute_cost_usd < 'Infinity'::double precision),
           usage_estimated BOOLEAN NOT NULL DEFAULT FALSE,
           current_attempt_started_at TIMESTAMPTZ,
           compute_cost_per_hour_usd DOUBLE PRECISION NOT NULL DEFAULT 0
             CONSTRAINT ingestion_jobs_compute_rate_finite
             CHECK(compute_cost_per_hour_usd >= 0
                   AND compute_cost_per_hour_usd < 'Infinity'::double precision),
           created_at TIMESTAMPTZ NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL
       )""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS input_cleanup_pending BOOLEAN NOT NULL DEFAULT FALSE""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS delete_requested BOOLEAN NOT NULL DEFAULT FALSE""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS lifecycle_started_at TIMESTAMPTZ""",
    """UPDATE crisisweave.ingestion_jobs SET lifecycle_started_at = created_at
           WHERE lifecycle_started_at IS NULL""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ALTER COLUMN lifecycle_started_at SET NOT NULL""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS lifecycle_generation INTEGER NOT NULL DEFAULT 1""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS processing_seconds DOUBLE PRECISION NOT NULL DEFAULT 0""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS compute_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS usage_estimated BOOLEAN NOT NULL DEFAULT FALSE""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS current_attempt_started_at TIMESTAMPTZ""",
    """ALTER TABLE crisisweave.ingestion_jobs
           ADD COLUMN IF NOT EXISTS compute_cost_per_hour_usd
             DOUBLE PRECISION NOT NULL DEFAULT 0""",
    """DO $migration$
       BEGIN
           IF NOT EXISTS (
               SELECT 1 FROM pg_constraint
               WHERE conrelid = 'crisisweave.ingestion_jobs'::regclass
                 AND conname = 'ingestion_jobs_lifecycle_generation_valid'
           ) THEN
               ALTER TABLE crisisweave.ingestion_jobs
                 ADD CONSTRAINT ingestion_jobs_lifecycle_generation_valid
                 CHECK(lifecycle_generation >= 1);
           END IF;
       END
       $migration$""",
    """DO $migration$
       BEGIN
           IF NOT EXISTS (
               SELECT 1 FROM pg_constraint
               WHERE conrelid = 'crisisweave.ingestion_jobs'::regclass
                 AND conname = 'ingestion_jobs_processing_seconds_finite'
           ) THEN
               ALTER TABLE crisisweave.ingestion_jobs
                 ADD CONSTRAINT ingestion_jobs_processing_seconds_finite
                 CHECK(processing_seconds >= 0
                       AND processing_seconds < 'Infinity'::double precision);
           END IF;
       END
       $migration$""",
    """DO $migration$
       BEGIN
           IF NOT EXISTS (
               SELECT 1 FROM pg_constraint
               WHERE conrelid = 'crisisweave.ingestion_jobs'::regclass
                 AND conname = 'ingestion_jobs_compute_cost_finite'
           ) THEN
               ALTER TABLE crisisweave.ingestion_jobs
                 ADD CONSTRAINT ingestion_jobs_compute_cost_finite
                 CHECK(compute_cost_usd >= 0
                       AND compute_cost_usd < 'Infinity'::double precision);
           END IF;
       END
       $migration$""",
    """DO $migration$
       BEGIN
           IF NOT EXISTS (
               SELECT 1 FROM pg_constraint
               WHERE conrelid = 'crisisweave.ingestion_jobs'::regclass
                 AND conname = 'ingestion_jobs_compute_rate_finite'
           ) THEN
               ALTER TABLE crisisweave.ingestion_jobs
                 ADD CONSTRAINT ingestion_jobs_compute_rate_finite
                 CHECK(compute_cost_per_hour_usd >= 0
                       AND compute_cost_per_hour_usd < 'Infinity'::double precision);
           END IF;
       END
       $migration$""",
    """CREATE TABLE IF NOT EXISTS crisisweave.ingestion_lifecycle_outbox (
           event_id UUID PRIMARY KEY,
           job_id UUID NOT NULL,
           lifecycle_generation INTEGER NOT NULL CHECK(lifecycle_generation >= 1),
           status VARCHAR(24) NOT NULL
             CHECK(status IN ('succeeded', 'cancelled', 'dead_letter')),
           lifecycle_started_at TIMESTAMPTZ NOT NULL,
           terminal_at TIMESTAMPTZ NOT NULL,
           processing_seconds DOUBLE PRECISION NOT NULL
             CHECK(processing_seconds >= 0
                   AND processing_seconds < 'Infinity'::double precision),
           compute_cost_usd DOUBLE PRECISION NOT NULL
             CHECK(compute_cost_usd >= 0
                   AND compute_cost_usd < 'Infinity'::double precision),
           usage_estimated BOOLEAN NOT NULL DEFAULT FALSE,
           delivery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(delivery_attempts >= 0),
           delivery_owner VARCHAR(128),
           delivery_lease_expires_at TIMESTAMPTZ,
           delivered_at TIMESTAMPTZ,
           UNIQUE(job_id, lifecycle_generation)
       )""",
    """ALTER TABLE crisisweave.ingestion_lifecycle_outbox
           ADD COLUMN IF NOT EXISTS usage_estimated BOOLEAN NOT NULL DEFAULT TRUE""",
    """INSERT INTO crisisweave.ingestion_lifecycle_outbox (
           event_id, job_id, lifecycle_generation, status, lifecycle_started_at,
           terminal_at, processing_seconds, compute_cost_usd, usage_estimated
       ) SELECT (
           md5('crisisweave:ingestion-lifecycle-event:v1:' || id::text || ':' ||
               lifecycle_generation::text)::uuid
       ), id, lifecycle_generation, status, lifecycle_started_at, updated_at,
          processing_seconds, compute_cost_usd, TRUE
       FROM crisisweave.ingestion_jobs
       WHERE status IN ('succeeded', 'cancelled', 'dead_letter')
       ON CONFLICT (job_id, lifecycle_generation) DO NOTHING""",
    """CREATE INDEX IF NOT EXISTS ingestion_lifecycle_outbox_pending
           ON crisisweave.ingestion_lifecycle_outbox(
               delivered_at, delivery_lease_expires_at, terminal_at, event_id
           )""",
    """CREATE INDEX IF NOT EXISTS ingestion_lifecycle_outbox_delivered
           ON crisisweave.ingestion_lifecycle_outbox(delivered_at, event_id)
           WHERE delivered_at IS NOT NULL""",
    """CREATE TABLE IF NOT EXISTS crisisweave.ingestion_orphan_cleanup (
           input_object_ref TEXT PRIMARY KEY,
           attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
           last_error TEXT,
           created_at TIMESTAMPTZ NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS ingestion_jobs_tenant_created
           ON crisisweave.ingestion_jobs(tenant_id, created_at DESC, id DESC)""",
    """CREATE INDEX IF NOT EXISTS ingestion_jobs_claim
           ON crisisweave.ingestion_jobs(status, available_at, created_at, id)""",
    """CREATE INDEX IF NOT EXISTS ingestion_jobs_active_sha
           ON crisisweave.ingestion_jobs(tenant_id, sha256, status)""",
    """CREATE INDEX IF NOT EXISTS ingestion_jobs_active_tenant
           ON crisisweave.ingestion_jobs(tenant_id)
           WHERE status IN ('running', 'cancelling')""",
    """INSERT INTO crisisweave.schema_migrations (version) VALUES (2)
           ON CONFLICT (version) DO NOTHING""",
    """INSERT INTO crisisweave.schema_migrations (version) VALUES (4)
           ON CONFLICT (version) DO NOTHING""",
    """INSERT INTO crisisweave.schema_migrations (version) VALUES (5)
           ON CONFLICT (version) DO NOTHING""",
)

_GOVERNANCE_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS crisisweave.identity_events (
           id UUID PRIMARY KEY,
           tenant_id VARCHAR(32),
           subject_id VARCHAR(255) NOT NULL,
           identity_type VARCHAR(24) NOT NULL,
           auth_method VARCHAR(24) NOT NULL,
           event_type VARCHAR(80) NOT NULL,
           outcome VARCHAR(16) NOT NULL,
           request_id VARCHAR(80),
           details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
           previous_hash CHAR(64),
           event_hash CHAR(64) NOT NULL UNIQUE,
           created_at TIMESTAMPTZ NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS identity_events_tenant_created
           ON crisisweave.identity_events(tenant_id, created_at DESC, id DESC)""",
    """CREATE TABLE IF NOT EXISTS crisisweave.review_records (
           id UUID PRIMARY KEY,
           tenant_id VARCHAR(32) NOT NULL,
           query_text TEXT NOT NULL,
           query_sha256 CHAR(64) NOT NULL,
           requester_subject VARCHAR(255) NOT NULL,
           requester_identity_type VARCHAR(24) NOT NULL,
           response_json JSONB NOT NULL,
           risk_level VARCHAR(16) NOT NULL,
           reasons_json JSONB NOT NULL,
           confidence DOUBLE PRECISION NOT NULL CHECK(confidence BETWEEN 0 AND 1),
           oldest_source_age_days DOUBLE PRECISION CHECK(oldest_source_age_days >= 0),
           contradiction_score DOUBLE PRECISION NOT NULL
             CHECK(contradiction_score BETWEEN 0 AND 1),
           status VARCHAR(16) NOT NULL,
           reviewed_by VARCHAR(255),
           decision_reason TEXT,
           created_at TIMESTAMPTZ NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS reviews_tenant_status_created
           ON crisisweave.review_records(tenant_id, status, created_at DESC, id DESC)""",
    """CREATE OR REPLACE FUNCTION crisisweave.protect_identity_events()
       RETURNS trigger LANGUAGE plpgsql AS $function$
       BEGIN
           IF TG_OP = 'DELETE'
              AND current_setting('crisisweave.audit_retention', true) = 'on' THEN
               RETURN OLD;
           END IF;
           RAISE EXCEPTION 'identity audit events are immutable';
       END
       $function$""",
    "DROP TRIGGER IF EXISTS identity_events_immutable ON crisisweave.identity_events",
    """CREATE TRIGGER identity_events_immutable BEFORE UPDATE OR DELETE
           ON crisisweave.identity_events FOR EACH ROW
           EXECUTE FUNCTION crisisweave.protect_identity_events()""",
    """CREATE OR REPLACE FUNCTION crisisweave.prune_identity_events(
           retention_days INTEGER, retained_rows INTEGER)
       RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER
       SET search_path = pg_catalog, crisisweave AS $function$
       DECLARE removed BIGINT := 0;
       DECLARE changed BIGINT := 0;
       BEGIN
           IF retention_days < 1 OR retention_days > 3650
              OR retained_rows < 100 OR retained_rows > 10000000 THEN
               RAISE EXCEPTION 'identity audit retention parameters are invalid';
           END IF;
           PERFORM set_config('crisisweave.audit_retention', 'on', true);
           DELETE FROM crisisweave.identity_events
             WHERE created_at < current_timestamp - (retention_days * INTERVAL '1 day');
           GET DIAGNOSTICS removed = ROW_COUNT;
           DELETE FROM crisisweave.identity_events WHERE id IN (
               SELECT id FROM crisisweave.identity_events
               ORDER BY created_at DESC, id DESC OFFSET retained_rows
           );
           GET DIAGNOSTICS changed = ROW_COUNT;
           RETURN removed + changed;
       END
       $function$""",
    "REVOKE ALL ON FUNCTION crisisweave.prune_identity_events(INTEGER, INTEGER) FROM PUBLIC",
    """INSERT INTO crisisweave.schema_migrations (version) VALUES (3)
           ON CONFLICT (version) DO NOTHING""",
)

_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def _role_identifier(role: str) -> str:
    """Return a safely quoted, deliberately restricted PostgreSQL role name."""

    if not _ROLE_NAME.fullmatch(role):
        raise ValueError("PostgreSQL runtime role names must be canonical lowercase identifiers")
    return f'"{role}"'


def apply_metadata_migrations(connection: Any) -> None:
    for statement in _METADATA_STATEMENTS:
        connection.execute(statement)


def apply_job_migrations(connection: Any) -> None:
    for statement in _JOB_STATEMENTS:
        connection.execute(statement)


def apply_governance_migrations(connection: Any) -> None:
    for statement in _GOVERNANCE_STATEMENTS:
        connection.execute(statement)


def apply_tenant_rls(
    connection: Any,
    *,
    api_role: str,
    worker_role: str,
) -> None:
    """Enable tenant policies for runtime roles without granting either role ownership."""

    api = _role_identifier(api_role)
    worker = _role_identifier(worker_role)
    migration_row = connection.execute("SELECT current_user").fetchone()
    if not migration_row or not isinstance(migration_row[0], str):
        raise RuntimeError("PostgreSQL migration role could not be identified")
    migration = _role_identifier(migration_row[0])
    tables = (
        "documents",
        "chunks",
        "storm_events",
        "query_audit",
        "ingestion_jobs",
        "review_records",
        "identity_events",
    )
    for table in tables:
        connection.execute(  # noqa: S608  # nosec B608
            f"ALTER TABLE crisisweave.{table} ENABLE ROW LEVEL SECURITY"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"ALTER TABLE crisisweave.{table} FORCE ROW LEVEL SECURITY"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"DROP POLICY IF EXISTS {table}_api_tenant ON crisisweave.{table}"
        )
        null_clause = "tenant_id IS NULL OR " if table == "identity_events" else ""
        predicate = f"({null_clause}tenant_id = current_setting('crisisweave.tenant_id', true))"
        connection.execute(  # noqa: S608  # nosec B608
            f"CREATE POLICY {table}_api_tenant ON crisisweave.{table} TO {api} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"DROP POLICY IF EXISTS {table}_worker_all ON crisisweave.{table}"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"CREATE POLICY {table}_worker_all ON crisisweave.{table} TO {worker} "
            "USING (true) WITH CHECK (true)"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"DROP POLICY IF EXISTS {table}_migration_all ON crisisweave.{table}"
        )
        connection.execute(  # noqa: S608  # nosec B608
            f"CREATE POLICY {table}_migration_all ON crisisweave.{table} TO {migration} "
            "USING (true) WITH CHECK (true)"
        )


def grant_runtime_privileges(connection: Any, *, api_role: str, worker_role: str) -> None:
    """Grant only table DML and schema usage to the two runtime identities."""

    role_identifiers = (_role_identifier(api_role), _role_identifier(worker_role))
    roles = ", ".join(role_identifiers)
    attributes = connection.execute(
        """SELECT COUNT(*) AS role_count,
                  COALESCE(bool_or(rolsuper OR rolbypassrls), FALSE) AS bypasses_rls
           FROM pg_roles WHERE rolname = ANY(%s)""",
        [[api_role, worker_role]],
    ).fetchone()
    if not attributes or int(attributes[0]) != 2:
        raise RuntimeError("Both PostgreSQL runtime roles must exist before migration")
    if bool(attributes[1]):
        raise RuntimeError("PostgreSQL runtime roles must not be SUPERUSER or BYPASSRLS")
    ownership = connection.execute(
        """SELECT EXISTS (
               SELECT 1 FROM pg_namespace namespace
               JOIN pg_roles owner ON owner.oid = namespace.nspowner
               WHERE namespace.nspname = 'crisisweave' AND owner.rolname = ANY(%s)
               UNION ALL
               SELECT 1 FROM pg_class relation
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
               JOIN pg_roles owner ON owner.oid = relation.relowner
               WHERE namespace.nspname = 'crisisweave' AND owner.rolname = ANY(%s)
           )""",
        [[api_role, worker_role], [api_role, worker_role]],
    ).fetchone()
    if ownership and ownership[0] is True:
        raise RuntimeError(
            "A runtime role owns PostgreSQL schema objects; an administrator must transfer "
            "ownership to the migration role before rollout"
        )
    connection.execute("REVOKE CREATE ON SCHEMA crisisweave FROM PUBLIC")
    connection.execute(  # noqa: S608  # nosec B608
        f"REVOKE ALL PRIVILEGES ON SCHEMA crisisweave FROM {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA crisisweave FROM {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA crisisweave FROM {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA crisisweave REVOKE ALL ON TABLES FROM {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT USAGE ON SCHEMA crisisweave TO {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT SELECT ON TABLE crisisweave.schema_migrations TO {roles}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT SELECT, UPDATE, DELETE ON TABLE crisisweave.documents TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        "GRANT SELECT ON TABLE crisisweave.chunks, crisisweave.storm_events "
        f"TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT INSERT, DELETE ON TABLE crisisweave.query_audit TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        "GRANT SELECT, INSERT ON TABLE crisisweave.identity_events, "
        f"crisisweave.review_records TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT UPDATE, DELETE ON TABLE crisisweave.review_records TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        "GRANT EXECUTE ON FUNCTION crisisweave.prune_identity_events(INTEGER, INTEGER) "
        f"TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE crisisweave.ingestion_jobs, "
        f"crisisweave.ingestion_orphan_cleanup TO {role_identifiers[0]}"
    )
    # API transitions may create immutable terminal events, but only ingestion workers
    # may inspect, claim, acknowledge, or prune the global content-free outbox.
    connection.execute(  # noqa: S608  # nosec B608
        f"GRANT INSERT ON TABLE crisisweave.ingestion_lifecycle_outbox TO {role_identifiers[0]}"
    )
    connection.execute(  # noqa: S608  # nosec B608
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE crisisweave.documents, "
        "crisisweave.chunks, crisisweave.storm_events, crisisweave.ingestion_jobs, "
        "crisisweave.ingestion_orphan_cleanup, crisisweave.ingestion_lifecycle_outbox "
        f"TO {role_identifiers[1]}"
    )


def migrate_postgres(
    dsn: str,
    *,
    api_role: str,
    worker_role: str,
    timeout_seconds: float,
    enable_rls: bool = False,
) -> None:
    """Apply all migrations atomically under one advisory lock, then grant runtime DML."""

    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(
        conninfo=dsn,
        min_size=1,
        max_size=1,
        timeout=timeout_seconds,
        kwargs={"autocommit": True},
        open=True,
    )
    try:
        pool.wait(timeout=timeout_seconds)
        with pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(%s)", [MIGRATION_LOCK])
            apply_metadata_migrations(connection)
            apply_job_migrations(connection)
            apply_governance_migrations(connection)
            grant_runtime_privileges(
                connection,
                api_role=api_role,
                worker_role=worker_role,
            )
            if enable_rls:
                apply_tenant_rls(
                    connection,
                    api_role=api_role,
                    worker_role=worker_role,
                )
    finally:
        pool.close()


def verify_postgres_schema(connection: Any) -> None:
    """Fail closed without DDL when a runtime starts before the migration job."""

    try:
        row = connection.execute(
            "SELECT MAX(version) FROM crisisweave.schema_migrations"
        ).fetchone()
    except Exception as exc:
        raise RuntimeError(
            "PostgreSQL schema is unavailable; run `crisisweave migrate` with the migration role"
        ) from exc
    version = row[0] if row else None
    if isinstance(version, bool) or not isinstance(version, int) or version < LATEST_SCHEMA_VERSION:
        raise RuntimeError(
            "PostgreSQL schema is outdated; run `crisisweave migrate` with the migration role"
        )
