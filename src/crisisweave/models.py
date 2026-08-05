"""Shared, transport-safe domain models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

GROUNDING_REGIONS_METADATA_KEY = "_crisisweave_grounding_regions_v1"
SOURCE_OBSERVED_AT_METADATA_KEY = "source_observed_at"
SOURCE_TIME_KIND_METADATA_KEY = "source_time_kind"
MAX_GROUNDING_REGIONS = 32
MAX_REGION_TIME_SECONDS = 7 * 24 * 60 * 60


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Modality(StrEnum):
    TEXT = "text"
    PDF_PAGE = "pdf_page"
    IMAGE = "image"
    VIDEO_FRAME = "video_frame"
    TRANSCRIPT = "transcript"
    TABLE = "table"
    WEB = "web"


class DocumentStatus(StrEnum):
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"
    CLEANUP_PENDING = "cleanup_pending"
    DELETING = "deleting"


class Route(StrEnum):
    VECTOR = "vector"
    SQL = "sql"
    WEB = "web"


class SourceTimeKind(StrEnum):
    PUBLICATION = "publication"
    OBSERVATION = "observation"


class SourceFreshnessStatus(StrEnum):
    UNKNOWN = "unknown"
    FRESH = "fresh"
    STALE = "stale"
    PARTIAL = "partial"


class ConflictStatus(StrEnum):
    UNKNOWN = "unknown"
    NOT_DETECTED = "not_detected"
    DETECTED = "detected"


def source_time_from_metadata(
    metadata: dict[str, Any],
) -> tuple[datetime, SourceTimeKind] | None:
    raw_time = metadata.get(SOURCE_OBSERVED_AT_METADATA_KEY)
    raw_kind = metadata.get(SOURCE_TIME_KIND_METADATA_KEY)
    if not isinstance(raw_time, str) or not isinstance(raw_kind, str):
        return None
    try:
        observed_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        kind = SourceTimeKind(raw_kind)
    except ValueError:
        return None
    if observed_at.tzinfo is None:
        return None
    return observed_at.astimezone(UTC), kind


class RegionSource(StrEnum):
    """Who supplied a locator; this is deliberately not an entailment verdict."""

    DERIVED_PROVENANCE = "derived_provenance"
    HUMAN_ANNOTATION = "human_annotation"
    MODEL_PROPOSAL = "model_proposal"


class NormalizedBoundingBox(StrictModel):
    """Top-left-origin coordinates normalized to the containing visual surface."""

    x_min: float = Field(ge=0.0, le=1.0)
    y_min: float = Field(ge=0.0, le=1.0)
    x_max: float = Field(ge=0.0, le=1.0)
    y_max: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def ordered_area(self) -> NormalizedBoundingBox:
        if self.x_max <= self.x_min or self.y_max <= self.y_min:
            raise ValueError("bounding boxes must have positive width and height")
        return self


class ImageBoundingBoxRegion(StrictModel):
    kind: Literal["image_bbox"] = "image_bbox"
    bbox: NormalizedBoundingBox
    label: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    source: RegionSource


class PdfBoundingBoxRegion(StrictModel):
    kind: Literal["pdf_bbox"] = "pdf_bbox"
    page: int = Field(ge=1, le=100_000)
    bbox: NormalizedBoundingBox
    coordinate_space: Literal["normalized_top_left"] = "normalized_top_left"
    label: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    source: RegionSource


class ChartElementType(StrEnum):
    BAR = "bar"
    LINE = "line"
    POINT = "point"
    SLICE = "slice"
    AXIS = "axis"
    LEGEND = "legend"
    TABLE_CELL = "table_cell"
    ANNOTATION = "annotation"
    OTHER = "other"


class ChartElementRegion(StrictModel):
    kind: Literal["chart_element"] = "chart_element"
    element_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    element_type: ChartElementType
    bbox: NormalizedBoundingBox
    page: int | None = Field(default=None, ge=1, le=100_000)
    series_label: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    category_label: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    source: RegionSource


class VideoTimeRangeRegion(StrictModel):
    kind: Literal["video_time_range"] = "video_time_range"
    start_seconds: float = Field(ge=0.0, le=MAX_REGION_TIME_SECONDS)
    end_seconds: float = Field(gt=0.0, le=MAX_REGION_TIME_SECONDS)
    bbox: NormalizedBoundingBox | None = None
    label: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    )
    source: RegionSource

    @model_validator(mode="after")
    def ordered_time_range(self) -> VideoTimeRangeRegion:
        if self.end_seconds <= self.start_seconds:
            raise ValueError("video time ranges must have positive duration")
        return self


GroundingRegion = Annotated[
    ImageBoundingBoxRegion | PdfBoundingBoxRegion | ChartElementRegion | VideoTimeRangeRegion,
    Field(discriminator="kind"),
]


class Chunk(StrictModel):
    id: str
    tenant_id: str = "default"
    document_id: str
    source_name: str
    source_uri: str | None = None
    modality: Modality
    text: str = ""
    page: int | None = None
    timestamp_seconds: float | None = None
    artifact_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    regions: list[GroundingRegion] = Field(default_factory=list, max_length=MAX_GROUNDING_REGIONS)

    @model_validator(mode="after")
    def validate_region_lineage(self) -> Chunk:
        if GROUNDING_REGIONS_METADATA_KEY in self.metadata:
            raise ValueError("grounding region storage key is reserved")
        serialized_regions = [item.model_dump_json() for item in self.regions]
        if len(set(serialized_regions)) != len(serialized_regions):
            raise ValueError("grounding regions must not contain duplicates")
        for region in self.regions:
            if isinstance(region, ImageBoundingBoxRegion) and self.modality is not Modality.IMAGE:
                raise ValueError("image bounding boxes require image evidence")
            if isinstance(region, PdfBoundingBoxRegion) and (
                self.modality is not Modality.PDF_PAGE or self.page != region.page
            ):
                raise ValueError("PDF regions must match their PDF evidence page")
            if isinstance(region, ChartElementRegion):
                if self.modality not in {Modality.IMAGE, Modality.PDF_PAGE}:
                    raise ValueError("chart elements require image or PDF-page evidence")
                if self.modality is Modality.PDF_PAGE and region.page != self.page:
                    raise ValueError("chart element page must match its PDF evidence page")
                if self.modality is Modality.IMAGE and region.page is not None:
                    raise ValueError("standalone image chart elements cannot declare a PDF page")
            if isinstance(region, VideoTimeRangeRegion):
                if self.modality is not Modality.VIDEO_FRAME:
                    raise ValueError("video time ranges require video-frame evidence")
                if self.timestamp_seconds is not None and not (
                    region.start_seconds <= self.timestamp_seconds <= region.end_seconds
                ):
                    raise ValueError("video time range must contain the frame timestamp")
        return self


def chunk_metadata_for_storage(chunk: Chunk) -> dict[str, Any]:
    """Persist typed regions in the existing metadata envelope without exposing the key."""

    metadata = dict(chunk.metadata)
    if chunk.regions:
        metadata[GROUNDING_REGIONS_METADATA_KEY] = [
            item.model_dump(mode="json") for item in chunk.regions
        ]
    return metadata


def split_chunk_storage_metadata(metadata: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    """Separate the reserved typed-region envelope from ordinary internal metadata."""

    public_metadata = dict(metadata)
    raw_regions = public_metadata.pop(GROUNDING_REGIONS_METADATA_KEY, [])
    if not isinstance(raw_regions, list):
        raise ValueError("stored grounding regions must be a list")
    return public_metadata, raw_regions


class Evidence(Chunk):
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    rerank_score: float | None = Field(default=None, ge=0.0, le=1.0)


class EvidenceView(StrictModel):
    """Public evidence projection without tenant IDs, document IDs, or local paths."""

    id: str
    source_name: str
    source_uri: str | None = None
    modality: Modality
    excerpt: str
    page: int | None = None
    timestamp_seconds: float | None = None
    source_observed_at: datetime | None = None
    source_time_kind: SourceTimeKind | None = None
    score: float = Field(ge=0.0, le=1.0)
    rerank_score: float | None = Field(default=None, ge=0.0, le=1.0)
    regions: list[GroundingRegion] = Field(default_factory=list, max_length=MAX_GROUNDING_REGIONS)

    @classmethod
    def from_internal(cls, evidence: Evidence) -> EvidenceView:
        source_time = source_time_from_metadata(evidence.metadata)
        return cls(
            id=evidence.id,
            source_name=evidence.source_name,
            source_uri=evidence.source_uri,
            modality=evidence.modality,
            excerpt=evidence.text[:4000],
            page=evidence.page,
            timestamp_seconds=evidence.timestamp_seconds,
            source_observed_at=source_time[0] if source_time else None,
            source_time_kind=source_time[1] if source_time else None,
            score=evidence.score,
            rerank_score=evidence.rerank_score,
            regions=evidence.regions,
        )


class Document(StrictModel):
    id: str
    tenant_id: str = "default"
    filename: str
    media_type: str
    sha256: str
    size_bytes: int
    derived_size_bytes: int = 0
    status: DocumentStatus
    source_uri: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    error: str | None = None
    chunk_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    object_ref: str | None = Field(default=None, exclude=True)


class IngestionResult(StrictModel):
    document: Document
    deduplicated: bool = False


class DeleteDocumentsResult(StrictModel):
    deleted_count: int = Field(ge=0)


class QueryRequest(StrictModel):
    query: str = Field(min_length=3, max_length=4000)
    top_k: int = Field(default=8, ge=1, le=30)
    allow_web: bool = False
    include_modalities: list[Modality] | None = Field(
        default=None, min_length=1, max_length=len(Modality)
    )


class ToolTrace(StrictModel):
    tool: Route
    input_summary: str
    result_count: int
    duration_ms: float
    status: str = "ok"


class Citation(StrictModel):
    evidence_id: str
    label: str
    source_name: str
    source_uri: str | None = None
    page: int | None = None
    timestamp_seconds: float | None = None
    source_observed_at: datetime | None = None
    source_time_kind: SourceTimeKind | None = None
    regions: list[GroundingRegion] = Field(default_factory=list, max_length=MAX_GROUNDING_REGIONS)


class Concordance(StrictModel):
    score: float = Field(ge=0.0, le=1.0)
    source_count: int = 0
    modality_count: int = 0
    rationale: str


class SourceFreshness(StrictModel):
    status: SourceFreshnessStatus = SourceFreshnessStatus.UNKNOWN
    known_source_count: int = Field(default=0, ge=0)
    unknown_source_count: int = Field(default=0, ge=0)
    oldest_source_age_days: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def freshness_is_consistent(self) -> SourceFreshness:
        if self.status == SourceFreshnessStatus.UNKNOWN and (
            self.known_source_count != 0 or self.oldest_source_age_days is not None
        ):
            raise ValueError("unknown source freshness cannot claim a known source age")
        if self.status != SourceFreshnessStatus.UNKNOWN and (
            self.known_source_count == 0 or self.oldest_source_age_days is None
        ):
            raise ValueError("known source freshness requires a source age")
        return self


class ConflictSignal(StrictModel):
    status: ConflictStatus = ConflictStatus.UNKNOWN
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    method: str | None = Field(default=None, min_length=1, max_length=120)

    @model_validator(mode="after")
    def signal_is_consistent(self) -> ConflictSignal:
        if self.status == ConflictStatus.UNKNOWN and (
            self.score is not None or self.method is not None
        ):
            raise ValueError("unknown conflict state cannot claim a score or method")
        if self.status != ConflictStatus.UNKNOWN and (self.score is None or self.method is None):
            raise ValueError("evaluated conflict state requires a score and method")
        if self.status == ConflictStatus.DETECTED and self.score == 0:
            raise ValueError("detected conflict score must be positive")
        return self


class QueryUsageSummary(StrictModel):
    input_tokens: int = Field(default=0, ge=0, le=100_000_000)
    output_tokens: int = Field(default=0, ge=0, le=100_000_000)
    model_cost_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    compute_cost_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    total_cost_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)

    @model_validator(mode="after")
    def cost_total_matches_components(self) -> QueryUsageSummary:
        expected = self.model_cost_usd + self.compute_cost_usd
        if abs(self.total_cost_usd - expected) > max(1e-9, abs(expected) * 1e-9):
            raise ValueError("total query cost must equal model plus compute cost")
        return self


class QueryResponse(StrictModel):
    answer: str
    routes: list[Route]
    citations: list[Citation] = Field(default_factory=list)
    evidence: list[EvidenceView] = Field(default_factory=list)
    tool_trace: list[ToolTrace] = Field(default_factory=list)
    concordance: Concordance
    claim_evidence_conflict: ConflictSignal = Field(default_factory=ConflictSignal)
    cross_source_conflict: ConflictSignal = Field(default_factory=ConflictSignal)
    source_freshness: SourceFreshness = Field(default_factory=SourceFreshness)
    warnings: list[str] = Field(default_factory=list)
    usage: QueryUsageSummary = Field(default_factory=QueryUsageSummary)
    request_id: str | None = None


class RiskLevel(StrEnum):
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ReviewSubmission(StrictModel):
    review_id: str
    status: ReviewStatus = ReviewStatus.PENDING
    risk_level: RiskLevel
    reasons: list[str]
    request_id: str | None = None


class ReviewDecisionRequest(StrictModel):
    decision: ReviewDecision
    reason: str = Field(min_length=3, max_length=1000)


class ReviewRecord(StrictModel):
    id: str
    query: str = Field(min_length=3, max_length=4000)
    status: ReviewStatus
    risk_level: RiskLevel
    reasons: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    oldest_source_age_days: float | None = Field(default=None, ge=0.0)
    contradiction_score: float | None = Field(default=None, ge=0.0, le=1.0)
    source_freshness: SourceFreshness = Field(default_factory=SourceFreshness)
    claim_evidence_conflict: ConflictSignal = Field(default_factory=ConflictSignal)
    cross_source_conflict: ConflictSignal = Field(default_factory=ConflictSignal)
    requester_subject: str
    requester_identity_type: str
    created_at: datetime
    updated_at: datetime
    reviewed_by: str | None = None
    decision_reason: str | None = None
    candidate_response: QueryResponse | None = None


class IdentityAuditEvent(StrictModel):
    id: str
    tenant_id: str | None = Field(default=None, exclude=True)
    subject_id: str
    identity_type: str
    auth_method: str
    event_type: str
    outcome: str
    request_id: str | None = None
    details: dict[str, str] = Field(default_factory=dict)
    previous_hash: str | None = None
    event_hash: str
    created_at: datetime


class HealthResponse(StrictModel):
    status: str
    version: str
    checks: dict[str, str] = Field(default_factory=dict)
