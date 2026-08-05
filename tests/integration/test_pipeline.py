from __future__ import annotations

import asyncio
from pathlib import Path

from PIL import Image

from crisisweave.auth import tenant_identifier
from crisisweave.bootstrap import build_container
from crisisweave.models import DocumentStatus, Modality, QueryRequest, Route


def test_csv_ingest_query_and_delete(settings, tmp_path: Path) -> None:
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(
        "EVENT_ID,BEGIN_YEARMONTH,STATE,EVENT_TYPE,DAMAGE_PROPERTY,"
        "DEATHS_DIRECT,EPISODE_NARRATIVE\n"
        "1,201701,TEXAS,Wildfire,2.5M,1,Large grass fire with heavy smoke\n"
        "2,201702,CALIFORNIA,Wildfire,750K,0,Satellite imagery showed a smoke plume\n"
        "3,201703,TEXAS,Hail,10K,0,Hail damaged roofs\n",
        encoding="utf-8",
    )
    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    try:
        result = container.ingestion.ingest_path(
            csv_path,
            tenant_id=tenant,
            filename="events.csv",
            source_uri="https://www.ncei.noaa.gov/stormevents/",
        )
        assert result.document.status == DocumentStatus.READY
        assert result.document.chunk_count >= 1

        duplicate = container.ingestion.ingest_path(csv_path, tenant_id=tenant, filename="copy.csv")
        assert duplicate.deduplicated
        assert duplicate.document.id == result.document.id

        response = asyncio.run(
            container.agent.ask(
                tenant,
                QueryRequest(query="What is the total property damage by state?", top_k=6),
            )
        )
        assert Route.VECTOR in response.routes
        assert Route.SQL in response.routes
        assert response.citations
        assert any(item.modality == Modality.TABLE for item in response.evidence)
        assert "TEXAS" in response.answer or "Texas" in response.answer

        assert container.ingestion.delete(tenant, result.document.id)
        assert container.store.get_document(tenant, result.document.id) is None
    finally:
        container.close()


def test_image_ingestion_creates_visual_evidence(settings, tmp_path: Path) -> None:
    path = tmp_path / "fire.png"
    Image.new("RGB", (64, 64), "orange").save(path)
    tenant = tenant_identifier("alpha")
    container = build_container(settings)
    try:
        result = container.ingestion.ingest_path(path, tenant_id=tenant, filename=path.name)
        assert result.document.status == DocumentStatus.READY
        hits = container.index.search(tenant, "orange fire", 5, [Modality.IMAGE])
        evidence = container.store.get_chunks(tenant, [item.id for item in hits])
        assert evidence
        assert evidence[0].modality == Modality.IMAGE
        assert evidence[0].text == "Visual evidence from fire.png"
    finally:
        container.close()
