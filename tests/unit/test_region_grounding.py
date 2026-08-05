from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
from PIL import Image
from pydantic import ValidationError

from crisisweave.agent import CrisisAgent
from crisisweave.extractors import ExtractionResult, Extractor
from crisisweave.ingestion import IngestionService
from crisisweave.models import (
    ChartElementRegion,
    ChartElementType,
    Chunk,
    Document,
    DocumentStatus,
    Evidence,
    EvidenceView,
    ImageBoundingBoxRegion,
    Modality,
    NormalizedBoundingBox,
    PdfBoundingBoxRegion,
    QueryRequest,
    RegionSource,
    Route,
    VideoTimeRangeRegion,
)
from crisisweave.postgres_storage import PostgresMetadataStore
from crisisweave.security import SecurityError
from crisisweave.storage import MetadataStore


def _box(
    x_min: float = 0.1,
    y_min: float = 0.2,
    x_max: float = 0.8,
    y_max: float = 0.9,
) -> NormalizedBoundingBox:
    return NormalizedBoundingBox(
        x_min=x_min,
        y_min=y_min,
        x_max=x_max,
        y_max=y_max,
    )


def test_typed_regions_validate_geometry_lineage_and_bounded_labels() -> None:
    with pytest.raises(ValidationError, match="positive width"):
        NormalizedBoundingBox(x_min=0.7, y_min=0.1, x_max=0.7, y_max=0.9)
    with pytest.raises(ValidationError):
        NormalizedBoundingBox(x_min=float("nan"), y_min=0.1, x_max=0.7, y_max=0.9)
    with pytest.raises(ValidationError, match="PDF regions must match"):
        Chunk(
            id="chunk",
            document_id="document",
            source_name="report.pdf",
            modality=Modality.PDF_PAGE,
            page=2,
            regions=[
                PdfBoundingBoxRegion(
                    page=1,
                    bbox=_box(),
                    source=RegionSource.HUMAN_ANNOTATION,
                )
            ],
        )
    with pytest.raises(ValidationError, match="video time range must contain"):
        Chunk(
            id="chunk",
            document_id="document",
            source_name="clip.mp4",
            modality=Modality.VIDEO_FRAME,
            timestamp_seconds=20,
            regions=[
                VideoTimeRangeRegion(
                    start_seconds=1,
                    end_seconds=2,
                    source=RegionSource.MODEL_PROPOSAL,
                )
            ],
        )
    with pytest.raises(ValidationError):
        ImageBoundingBoxRegion(
            bbox=_box(),
            label="unsafe\nlabel",
            source=RegionSource.MODEL_PROPOSAL,
        )


def test_chart_element_reference_is_typed_and_page_bound() -> None:
    region = ChartElementRegion(
        element_id="damage-series:2024",
        element_type=ChartElementType.BAR,
        bbox=_box(),
        page=3,
        series_label="Damage",
        category_label="2024",
        source=RegionSource.HUMAN_ANNOTATION,
    )
    chunk = Chunk(
        id="chunk",
        document_id="document",
        source_name="report.pdf",
        modality=Modality.PDF_PAGE,
        page=3,
        regions=[region],
    )
    assert chunk.regions[0].kind == "chart_element"

    with pytest.raises(ValidationError, match="standalone image"):
        Chunk(
            id="chunk",
            document_id="document",
            source_name="chart.png",
            modality=Modality.IMAGE,
            regions=[region],
        )


def test_duckdb_round_trip_preserves_typed_regions_without_leaking_reserved_metadata(
    tmp_path: Path,
) -> None:
    store = MetadataStore(tmp_path / "metadata.duckdb")
    document_id = str(uuid.uuid4())
    tenant_id = "a" * 32
    document = Document(
        id=document_id,
        tenant_id=tenant_id,
        filename="scene.png",
        media_type="image/png",
        sha256="b" * 64,
        size_bytes=10,
        status=DocumentStatus.PROCESSING,
    )
    chunk = Chunk(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        document_id=document_id,
        source_name=document.filename,
        modality=Modality.IMAGE,
        text="scene",
        metadata={"ocr_available": False},
        regions=[
            ImageBoundingBoxRegion(
                bbox=_box(),
                label="smoke plume",
                source=RegionSource.HUMAN_ANNOTATION,
            )
        ],
    )
    try:
        store.create_document(document)
        store.replace_chunks(tenant_id, document_id, [chunk])
        restored = store.get_chunks(tenant_id, [chunk.id])[0]
    finally:
        store.close()

    assert restored.regions == chunk.regions
    assert restored.metadata == {"ocr_available": False}


def test_postgres_row_hydration_reconstructs_region_envelope() -> None:
    row = (
        uuid.uuid4(),
        "a" * 32,
        uuid.uuid4(),
        "report.pdf",
        None,
        "pdf_page",
        "page text",
        2,
        None,
        "s3://example/artifact?versionId=1",
        {
            "text_available": True,
            "_crisisweave_grounding_regions_v1": [
                {
                    "kind": "pdf_bbox",
                    "page": 2,
                    "bbox": {"x_min": 0.0, "y_min": 0.0, "x_max": 1.0, "y_max": 1.0},
                    "coordinate_space": "normalized_top_left",
                    "source": "derived_provenance",
                }
            ],
        },
    )

    chunk = PostgresMetadataStore._chunk_from_row(row)  # noqa: SLF001

    assert isinstance(chunk.regions[0], PdfBoundingBoxRegion)
    assert chunk.metadata == {"text_available": True}


def test_image_extractor_emits_only_full_surface_provenance_locator(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "scene.png"
    Image.new("RGB", (20, 10), color="orange").save(source)
    extractor = Extractor(settings)
    monkeypatch.setattr(extractor, "_ocr", lambda *_args: ("", None))

    result = extractor.extract(
        source,
        media_type="image/png",
        tenant_id="a" * 32,
        document_id=str(uuid.uuid4()),
        source_name="scene.png",
        source_uri=None,
    )

    assert len(result.chunks) == 1
    region = result.chunks[0].regions[0]
    assert isinstance(region, ImageBoundingBoxRegion)
    assert region.bbox == NormalizedBoundingBox(x_min=0, y_min=0, x_max=1, y_max=1)
    assert region.source is RegionSource.DERIVED_PROVENANCE


def test_parser_validation_rejects_forged_human_region_source(settings, tmp_path: Path) -> None:
    document_id = str(uuid.uuid4())
    artifact_dir = settings.artifact_dir / document_id
    artifact_dir.mkdir(parents=True)
    artifact = artifact_dir / "image.jpg"
    artifact.write_bytes(b"pixels")
    chunk = Chunk(
        id=str(uuid.uuid5(uuid.UUID(document_id), "chunk:0")),
        tenant_id="a" * 32,
        document_id=document_id,
        source_name="scene.png",
        modality=Modality.IMAGE,
        artifact_path=str(artifact),
        regions=[
            ImageBoundingBoxRegion(
                bbox=_box(),
                source=RegionSource.HUMAN_ANNOTATION,
            )
        ],
    )
    service = object.__new__(IngestionService)
    service.settings = settings

    with pytest.raises(SecurityError, match="unauthorized region source"):
        service._validate_extracted(  # noqa: SLF001
            ExtractionResult(chunks=[chunk]),
            tenant_id="a" * 32,
            document_id=document_id,
            source_name="scene.png",
            source_uri=None,
        )


@pytest.mark.parametrize(
    ("regions", "message"),
    [
        (
            [
                ChartElementRegion(
                    element_id="untrusted",
                    element_type=ChartElementType.BAR,
                    bbox=_box(),
                    source=RegionSource.DERIVED_PROVENANCE,
                )
            ],
            "inferred chart region",
        ),
        (
            [
                ImageBoundingBoxRegion(
                    bbox=_box(),
                    source=RegionSource.DERIVED_PROVENANCE,
                )
            ],
            "cover the full artifact",
        ),
        ([], "incomplete visual-region provenance"),
    ],
)
def test_parser_validation_rejects_untrusted_inference_or_incomplete_provenance(
    settings,
    regions: list[ChartElementRegion | ImageBoundingBoxRegion],
    message: str,
) -> None:
    document_id = str(uuid.uuid4())
    artifact_dir = settings.artifact_dir / document_id
    artifact_dir.mkdir(parents=True)
    artifact = artifact_dir / "image.jpg"
    artifact.write_bytes(b"pixels")
    chunk = Chunk(
        id=str(uuid.uuid5(uuid.UUID(document_id), "chunk:0")),
        tenant_id="a" * 32,
        document_id=document_id,
        source_name="scene.png",
        modality=Modality.IMAGE,
        artifact_path=str(artifact),
        regions=regions,
    )
    service = object.__new__(IngestionService)
    service.settings = settings

    with pytest.raises(SecurityError, match=message):
        service._validate_extracted(  # noqa: SLF001
            ExtractionResult(chunks=[chunk]),
            tenant_id="a" * 32,
            document_id=document_id,
            source_name="scene.png",
            source_uri=None,
        )


def test_public_evidence_and_citation_expose_locator_but_not_local_path(tmp_path: Path) -> None:
    artifact = tmp_path / "image.jpg"
    artifact.write_bytes(b"pixels")
    region = ImageBoundingBoxRegion(
        bbox=_box(),
        source=RegionSource.DERIVED_PROVENANCE,
    )
    evidence = Evidence(
        id="evidence-1",
        document_id="document-1",
        source_name="scene.jpg",
        modality=Modality.IMAGE,
        text="Orange flames are visible.",
        artifact_path=str(artifact),
        score=0.9,
        regions=[region],
    )
    view = EvidenceView.from_internal(evidence).model_dump(mode="json")
    assert view["regions"][0]["kind"] == "image_bbox"
    assert "artifact_path" not in view

    agent = object.__new__(CrisisAgent)
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What is visible?"),
                "started_at": 0.0,
                "answer": "Orange flames are visible [E1].",
                "evidence": [evidence],
                "pixel_labels": {1},
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert result["citations"][0].regions == [region]
    assert any("does not assert claim-level" in warning for warning in result["warnings"])
