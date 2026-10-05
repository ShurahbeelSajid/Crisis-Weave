from __future__ import annotations

import uuid
from pathlib import Path

import duckdb
import pytest

from crisisweave.models import Document, DocumentStatus
from crisisweave.security import SecurityError
from crisisweave.storage import MetadataStore

TENANT_ID = "a" * 32


def _document(filename: str) -> Document:
    return Document(
        id=str(uuid.uuid4()),
        tenant_id=TENANT_ID,
        filename=filename,
        media_type="text/csv",
        sha256=uuid.uuid4().hex * 2,
        size_bytes=100,
        status=DocumentStatus.READY,
    )


def _event(*, year: int, state: str, damage: float) -> dict[str, object]:
    return {
        "event_id": str(uuid.uuid4()),
        "begin_year": year,
        "state": state,
        "event_type": "Wildfire",
        "cz_name": "Test county",
        "injuries_direct": 0.0,
        "deaths_direct": 0.0,
        "damage_property": damage,
        "damage_crops": 0.0,
        "magnitude": None,
        "episode_narrative": "bounded narrative",
        "raw": {"state": state},
    }


def test_legacy_documents_schema_migrates_on_duckdb_1_5(tmp_path: Path) -> None:
    database = tmp_path / "legacy.duckdb"
    connection = duckdb.connect(database)
    connection.execute(
        """CREATE TABLE documents (
            id VARCHAR PRIMARY KEY, tenant_id VARCHAR NOT NULL,
            filename VARCHAR NOT NULL, media_type VARCHAR NOT NULL,
            sha256 VARCHAR NOT NULL, size_bytes UBIGINT NOT NULL,
            status VARCHAR NOT NULL, source_uri VARCHAR,
            created_at TIMESTAMPTZ NOT NULL, error VARCHAR,
            chunk_count INTEGER NOT NULL DEFAULT 0,
            warnings_json VARCHAR NOT NULL DEFAULT '[]'
        )"""
    )
    legacy_id = str(uuid.uuid4())
    connection.execute(
        "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, NULL, "
        "current_timestamp, NULL, 0, '[]')",
        [
            legacy_id,
            TENANT_ID,
            "legacy.csv",
            "text/csv",
            uuid.uuid4().hex * 2,
            100,
            DocumentStatus.READY.value,
        ],
    )
    connection.close()

    store = MetadataStore(database)
    try:
        columns = {
            row[1]: row
            for row in store._connection.execute(  # noqa: SLF001
                "PRAGMA table_info('documents')"
            ).fetchall()
        }
        assert columns["derived_size_bytes"][4] is not None
        migrated = store.get_document(TENANT_ID, legacy_id)
        assert migrated is not None
        assert migrated.derived_size_bytes == 0
    finally:
        store.close()


def test_filtered_and_grouped_analytics_preserve_per_source_rows(tmp_path: Path) -> None:
    store = MetadataStore(tmp_path / "analytics.duckdb")
    older = _document("older.csv")
    newer = _document("newer.csv")
    try:
        store.create_document(older)
        store.create_document(newer)
        store.replace_storm_events(
            TENANT_ID, older.id, [_event(year=2097, state="TEXAS", damage=1500)]
        )
        store.replace_storm_events(
            TENANT_ID, newer.id, [_event(year=2098, state="ALASKA", damage=2000)]
        )

        filtered = store.execute_safe_analytics_with_sources(
            TENANT_ID,
            "SELECT SUM(damage_property) AS total_damage "
            "FROM authorized_storm_events WHERE begin_year = 2097",
        )
        assert filtered.rows == [{"total_damage": 1500.0}]
        assert [source.id for source in filtered.sources] == [older.id]
        assert filtered.source_rows == {older.id: filtered.rows}
        assert filtered.source_count == 1
        assert filtered.source_count_exact

        grouped = store.execute_safe_analytics_with_sources(
            TENANT_ID,
            "SELECT state, SUM(damage_property) AS total_damage "
            "FROM authorized_storm_events GROUP BY state ORDER BY state",
        )
        assert grouped.source_rows[older.id] == [{"state": "TEXAS", "total_damage": 1500.0}]
        assert grouped.source_rows[newer.id] == [{"state": "ALASKA", "total_damage": 2000.0}]

        with pytest.raises(SecurityError, match="unique names"):
            store.execute_safe_analytics(
                TENANT_ID,
                "SELECT state, COUNT(*) AS STATE FROM authorized_storm_events GROUP BY state",
            )
    finally:
        store.close()


def test_analytics_result_byte_budget_is_enforced_while_fetching(tmp_path: Path) -> None:
    store = MetadataStore(
        tmp_path / "bounded.duckdb",
        max_analytics_result_bytes=100,
        max_analytics_cell_bytes=1024,
    )
    document = _document("wide.csv")
    try:
        store.create_document(document)
        store.replace_storm_events(
            TENANT_ID,
            document.id,
            [
                _event(year=2097, state=f"STATE-{index}-" + ("x" * 80), damage=1)
                for index in range(3)
            ],
        )

        with pytest.raises(SecurityError, match="byte budget"):
            store.execute_safe_analytics(
                TENANT_ID,
                "SELECT row_index, state FROM authorized_storm_events ORDER BY row_index",
            )
    finally:
        store.close()
