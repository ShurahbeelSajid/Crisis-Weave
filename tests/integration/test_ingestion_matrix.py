from __future__ import annotations

import asyncio
from pathlib import Path

import pypdfium2 as pdfium
import pytest
from PIL import Image

from crisisweave.auth import tenant_identifier
from crisisweave.bootstrap import build_container
from crisisweave.extractors import Extractor
from crisisweave.models import DocumentStatus, Modality, QueryRequest
from crisisweave.security import SecurityError


def _blank_pdf(path: Path) -> None:
    document = pdfium.PdfDocument.new()
    try:
        document.new_page(width=120, height=80)
        document.save(path)
    finally:
        document.close()


def test_supported_non_video_ingestion_matrix(settings, tmp_path: Path) -> None:
    files: list[tuple[Path, str]] = []
    pdf = tmp_path / "report.pdf"
    _blank_pdf(pdf)
    files.append((pdf, "application/pdf"))
    for suffix, image_format in (("jpg", "JPEG"), ("webp", "WEBP")):
        path = tmp_path / f"image.{suffix}"
        Image.new("RGB", (32, 24), "orange").save(path, format=image_format)
        files.append((path, f"image/{'jpeg' if suffix == 'jpg' else 'webp'}"))
    fixtures = {
        "events.json": b'[{"EVENT_ID":"1","STATE":"TEXAS","EVENT_TYPE":"Wildfire"}]',
        "notes.txt": b"plain evidence text",
        "notes.md": b"# markdown evidence",
        "captions.srt": b"1\n00:00:00,000 --> 00:00:01,000\nsmoke plume\n",
        "captions.vtt": b"WEBVTT\n\n00:00.000 --> 00:01.000\nvisible smoke\n",
    }
    for name, content in fixtures.items():
        path = tmp_path / name
        path.write_bytes(content)
        files.append((path, "application/json" if name.endswith(".json") else "text/plain"))

    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    try:
        for path, expected_type in files:
            result = container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
            assert result.document.status == DocumentStatus.READY
            assert result.document.media_type == expected_type
            assert result.document.chunk_count > 0
        pdf_hits = container.index.search(tenant, "report", 5, [Modality.PDF_PAGE])
        pdf_evidence = container.store.get_chunks(tenant, [item.id for item in pdf_hits])
        assert pdf_evidence
        assert pdf_evidence[0].page == 1
        assert pdf_evidence[0].artifact_path
        assert pdf_evidence[0].text == "Rendered page 1 from report.pdf"
        transcript_hits = container.index.search(tenant, "visible smoke", 10, [Modality.TRANSCRIPT])
        transcript_evidence = container.store.get_chunks(
            tenant, [item.id for item in transcript_hits]
        )
        assert transcript_evidence
        assert any(item.timestamp_seconds == 0.0 for item in transcript_evidence)
    finally:
        container.close()


def test_cross_tenant_vector_sql_and_shared_object_isolation(settings, tmp_path: Path) -> None:
    alpha = tenant_identifier("alpha")
    beta = tenant_identifier("beta")
    image = tmp_path / "shared.png"
    Image.new("RGB", (24, 24), "red").save(image)
    alpha_csv = tmp_path / "alpha.csv"
    alpha_csv.write_text("EVENT_ID,STATE,EVENT_TYPE\n1,TEXAS,Wildfire\n", encoding="utf-8")
    beta_csv = tmp_path / "beta.csv"
    beta_csv.write_text("EVENT_ID,STATE,EVENT_TYPE\n2,ALASKA,Blizzard\n", encoding="utf-8")

    container = build_container(settings)
    try:
        alpha_image = container.ingestion.ingest_path(
            image, tenant_id=alpha, filename="shared.png"
        ).document
        beta_image = container.ingestion.ingest_path(
            image, tenant_id=beta, filename="shared.png"
        ).document
        alpha_table = container.ingestion.ingest_path(
            alpha_csv, tenant_id=alpha, filename="alpha.csv"
        ).document
        container.ingestion.ingest_path(beta_csv, tenant_id=beta, filename="beta.csv")

        alpha_hits = container.index.search(alpha, "shared red image", 10)
        beta_hits = container.index.search(beta, "shared red image", 10)
        alpha_evidence = container.store.get_chunks(alpha, [item.id for item in alpha_hits])
        beta_evidence = container.store.get_chunks(beta, [item.id for item in beta_hits])
        assert alpha_hits and beta_hits
        assert {item.tenant_id for item in alpha_evidence} == {alpha}
        assert {item.tenant_id for item in beta_evidence} == {beta}
        _, alpha_rows = container.store.execute_safe_analytics(
            alpha,
            "SELECT state, COUNT(*) AS event_count FROM authorized_storm_events GROUP BY state",
        )
        _, beta_rows = container.store.execute_safe_analytics(
            beta,
            "SELECT state, COUNT(*) AS event_count FROM authorized_storm_events GROUP BY state",
        )
        _, qualified_rows = container.store.execute_safe_analytics(
            alpha,
            "SELECT authorized_storm_events.state, COUNT(*) AS event_count "
            "FROM authorized_storm_events GROUP BY authorized_storm_events.state",
        )
        assert alpha_rows == [{"state": "TEXAS", "event_count": 1}]
        assert beta_rows == [{"state": "ALASKA", "event_count": 1}]
        assert qualified_rows == alpha_rows

        alpha_object_files = list(
            (settings.object_dir / "tenants" / alpha / "originals" / alpha_image.sha256[:2]).glob(
                f"{alpha_image.sha256}.*"
            )
        )
        beta_object_files = list(
            (settings.object_dir / "tenants" / beta / "originals" / beta_image.sha256[:2]).glob(
                f"{beta_image.sha256}.*"
            )
        )
        assert len(alpha_object_files) == len(beta_object_files) == 1
        assert alpha_object_files[0] != beta_object_files[0]
        assert container.ingestion.delete(alpha, alpha_image.id)
        assert not alpha_object_files[0].exists()
        assert beta_object_files[0].exists(), "the beta tenant owns an isolated original"
        assert not container.index.search(alpha, "shared red image", 10, [Modality.IMAGE])
        assert container.ingestion.delete(beta, beta_image.id)
        assert not beta_object_files[0].exists()

        assert container.ingestion.delete(alpha, alpha_table.id)
        _, rows_after_delete = container.store.execute_safe_analytics(
            alpha,
            "SELECT state, COUNT(*) AS event_count FROM authorized_storm_events GROUP BY state",
        )
        assert rows_after_delete == []
    finally:
        container.close()


def test_analytics_provenance_contains_only_documents_matching_query_filters(
    settings, tmp_path: Path
) -> None:
    tenant = tenant_identifier("provenance")
    older_csv = tmp_path / "older.csv"
    older_csv.write_text(
        "EVENT_ID,BEGIN_YEARMONTH,STATE,EVENT_TYPE,DAMAGE_PROPERTY\n1,209701,TEXAS,Wildfire,1500\n",
        encoding="utf-8",
    )
    newer_csv = tmp_path / "newer.csv"
    newer_csv.write_text(
        "EVENT_ID,BEGIN_YEARMONTH,STATE,EVENT_TYPE,DAMAGE_PROPERTY\n"
        "2,209801,ALASKA,Blizzard,2000\n",
        encoding="utf-8",
    )

    container = build_container(settings)
    try:
        older = container.ingestion.ingest_path(
            older_csv, tenant_id=tenant, filename=older_csv.name
        ).document
        newer = container.ingestion.ingest_path(
            newer_csv, tenant_id=tenant, filename=newer_csv.name
        ).document

        analytics = container.store.execute_safe_analytics_with_sources(
            tenant,
            "SELECT SUM(damage_property) AS total_damage "
            "FROM authorized_storm_events WHERE begin_year = 2097",
        )

        assert analytics.rows == [{"total_damage": 1500.0}]
        assert analytics.source_count == 1
        assert analytics.source_count_exact
        assert [source.id for source in analytics.sources] == [older.id]
        assert newer.id not in {source.id for source in analytics.sources}

        grouped = container.store.execute_safe_analytics_with_sources(
            tenant,
            "SELECT state, SUM(damage_property) AS total_damage "
            "FROM authorized_storm_events GROUP BY state ORDER BY state",
        )
        assert grouped.source_rows[older.id] == [{"state": "TEXAS", "total_damage": 1500.0}]
        assert grouped.source_rows[newer.id] == [{"state": "ALASKA", "total_damage": 2000.0}]

        response = asyncio.run(
            container.agent.ask(
                tenant,
                QueryRequest(query="What is the total property damage by state?", top_k=8),
            )
        )
        table_evidence = {
            item.source_name: item.excerpt
            for item in response.evidence
            if item.modality == Modality.TABLE
        }
        assert "TEXAS" in table_evidence[older.filename]
        assert "ALASKA" not in table_evidence[older.filename]
        assert "ALASKA" in table_evidence[newer.filename]
        assert "TEXAS" not in table_evidence[newer.filename]
    finally:
        container.close()


def test_analytics_result_byte_budget_fails_closed(settings, tmp_path: Path) -> None:
    configured = settings.model_copy(
        update={
            "max_analytics_result_bytes": 16 * 1024,
            "max_structured_cell_chars": 512,
        }
    )
    tenant = tenant_identifier("analytics-budget")
    path = tmp_path / "wide-results.csv"
    rows = ["EVENT_ID,STATE,EVENT_TYPE"]
    rows.extend(f"{index},TEXAS,{index:03d}-" + ("x" * 490) for index in range(100))
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    container = build_container(configured)
    try:
        container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
        with pytest.raises(SecurityError, match="byte budget"):
            container.store.execute_safe_analytics(
                tenant,
                "SELECT row_index, event_type FROM authorized_storm_events ORDER BY row_index",
            )
    finally:
        container.close()


def test_partial_vector_write_with_failed_cleanup_cannot_crowd_ready_evidence(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = settings.model_copy(update={"chunk_chars": 200, "chunk_overlap_chars": 0})
    tenant = tenant_identifier("orphan-cleanup")
    ready_path = tmp_path / "ready.txt"
    ready_path.write_text("survivor-evidence-unique", encoding="utf-8")
    failing_path = tmp_path / "failing.txt"
    failing_path.write_text(("survivor-evidence-unique orphan " * 1200), encoding="utf-8")

    container = build_container(configured)
    try:
        ready = container.ingestion.ingest_path(
            ready_path, tenant_id=tenant, filename=ready_path.name
        ).document
        original_index = container.index.index
        original_delete = container.index.delete_document

        def partial_index(chunks, *, deadline=None, visual_vectors=None) -> None:
            materialized = list(chunks)
            assert len(materialized) > 64
            original_index(
                materialized[:64],
                deadline=deadline,
                visual_vectors=visual_vectors,
            )
            raise RuntimeError("simulated later Qdrant batch failure")

        def failed_delete(_tenant_id: str, _document_id: str) -> None:
            raise RuntimeError("simulated Qdrant cleanup failure")

        monkeypatch.setattr(container.index, "index", partial_index)
        monkeypatch.setattr(container.index, "delete_document", failed_delete)
        with pytest.raises(RuntimeError, match="later Qdrant batch"):
            container.ingestion.ingest_path(
                failing_path, tenant_id=tenant, filename=failing_path.name
            )

        pending = [
            document
            for document in container.store.list_documents(tenant, 10)
            if document.status == DocumentStatus.CLEANUP_PENDING
        ]
        assert len(pending) == 1
        assert pending[0].id in container.store.non_ready_document_ids(tenant)

        response = asyncio.run(
            container.agent.ask(tenant, QueryRequest(query="survivor-evidence-unique", top_k=8))
        )
        assert response.citations
        assert {item.source_name for item in response.evidence} == {ready.filename}

        monkeypatch.setattr(container.index, "index", original_index)
        monkeypatch.setattr(container.index, "delete_document", original_delete)
        container.ingestion.reconcile()
        recovered = container.store.get_document(tenant, pending[0].id)
        assert recovered is not None
        assert recovered.status == DocumentStatus.FAILED
    finally:
        container.close()


class _FailOnceExtractor:
    def __init__(self, delegate: Extractor) -> None:
        self.delegate = delegate
        self.calls = 0

    def extract(self, *args: object, **kwargs: object):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("deliberate first-attempt failure")
        return self.delegate.extract(*args, **kwargs)


def test_failed_ingestion_can_retry_same_hash(settings, tmp_path: Path) -> None:
    path = tmp_path / "retry.txt"
    path.write_text("retryable authorized evidence", encoding="utf-8")
    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    container.ingestion.extractor = _FailOnceExtractor(container.ingestion.extractor)
    try:
        with pytest.raises(RuntimeError, match="deliberate"):
            container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
        failed = container.store.find_document_by_sha(
            tenant,
            container.store.list_documents(tenant)[0].sha256,
        )
        assert failed is not None and failed.status == DocumentStatus.FAILED
        retried = container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
        assert retried.document.id == failed.id
        assert retried.document.status == DocumentStatus.READY
        assert not retried.deduplicated
    finally:
        container.close()


def test_failed_document_does_not_permanently_consume_active_quota(
    settings, tmp_path: Path
) -> None:
    first = tmp_path / "first.txt"
    first.write_text("first payload that deliberately fails", encoding="utf-8")
    second = tmp_path / "second.txt"
    second.write_text("second payload succeeds", encoding="utf-8")
    configured = settings.model_copy(update={"max_documents_per_tenant": 1})
    tenant = tenant_identifier("alpha")
    container = build_container(configured)
    container.ingestion.extractor = _FailOnceExtractor(container.ingestion.extractor)
    try:
        with pytest.raises(RuntimeError):
            container.ingestion.ingest_path(first, tenant_id=tenant, filename=first.name)
        result = container.ingestion.ingest_path(second, tenant_id=tenant, filename=second.name)
        assert result.document.status == DocumentStatus.READY
    finally:
        container.close()


def test_derived_bytes_are_accounted_in_tenant_storage(settings, tmp_path: Path) -> None:
    path = tmp_path / "accounted.txt"
    path.write_text("bounded derived evidence", encoding="utf-8")
    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    try:
        document = container.ingestion.ingest_path(
            path, tenant_id=tenant, filename=path.name
        ).document
        count, used_bytes = container.store.tenant_usage(tenant)
        assert count == 1
        assert document.derived_size_bytes > 0
        assert used_bytes == document.size_bytes + document.derived_size_bytes
    finally:
        container.close()


def test_tenant_structured_record_quota_is_enforced(settings, tmp_path: Path) -> None:
    first = tmp_path / "first.csv"
    first.write_text("EVENT_ID,STATE\n1,TEXAS\n", encoding="utf-8")
    second = tmp_path / "second.csv"
    second.write_text("EVENT_ID,STATE\n2,ALASKA\n", encoding="utf-8")
    configured = settings.model_copy(update={"max_structured_rows_per_tenant": 1})
    tenant = tenant_identifier("alpha")
    container = build_container(configured)
    try:
        container.ingestion.ingest_path(first, tenant_id=tenant, filename=first.name)
        with pytest.raises(SecurityError, match="structured-record quota"):
            container.ingestion.ingest_path(second, tenant_id=tenant, filename=second.name)
    finally:
        container.close()


def test_delete_tombstone_can_be_reconciled_after_index_failure(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "delete.txt"
    path.write_text("deletion evidence", encoding="utf-8")
    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    try:
        document = container.ingestion.ingest_path(
            path, tenant_id=tenant, filename=path.name
        ).document
        original_delete = container.index.delete_document

        def fail_delete(_tenant: str, _document: str) -> None:
            raise RuntimeError("temporary Qdrant outage")

        monkeypatch.setattr(container.index, "delete_document", fail_delete)
        with pytest.raises(RuntimeError, match="Qdrant"):
            container.ingestion.delete(tenant, document.id)
        tombstone = container.store.get_document(tenant, document.id)
        assert tombstone is not None and tombstone.status == DocumentStatus.DELETING
        monkeypatch.setattr(container.index, "delete_document", original_delete)
        assert container.ingestion.delete(tenant, document.id)
        assert container.store.get_document(tenant, document.id) is None
    finally:
        container.close()


def test_parser_isolation_spawn_path_ingests_text(settings, tmp_path: Path) -> None:
    path = tmp_path / "isolated.txt"
    path.write_text("isolated parser evidence", encoding="utf-8")
    configured = settings.model_copy(update={"isolate_parsers": True})
    tenant = tenant_identifier("alpha")
    container = build_container(configured)
    try:
        result = container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
        assert result.document.status == DocumentStatus.READY
    finally:
        container.close()
