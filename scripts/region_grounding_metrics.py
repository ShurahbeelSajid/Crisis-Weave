"""Strict, deterministic region-grounding contracts for benchmark scoring.

This module intentionally has no application or model-provider dependencies.  A system may
propose regions, but only geometric/temporal overlap with custodian annotations determines the
score; a self-reported entailment flag is never accepted.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

JsonObject = dict[str, Any]

REGION_KINDS = {"image_bbox", "pdf_bbox", "chart_element", "video_time_range"}
CHART_ELEMENT_TYPES = {
    "bar",
    "line",
    "point",
    "slice",
    "axis",
    "legend",
    "table_cell",
    "annotation",
    "other",
}
MAX_PREDICTED_REGIONS = 32
MAX_GOLD_REGIONS = 128
MAX_REGION_TIME_SECONDS = 7 * 24 * 60 * 60
DEFAULT_IOU_THRESHOLD = 0.5


class RegionGroundingError(ValueError):
    """Raised when a region artifact violates the frozen scorer contract."""


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegionGroundingError(f"{label} must be a non-empty string")
    if len(value) > 160 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RegionGroundingError(f"{label} must be at most 160 printable characters")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _number(value: object, label: str, *, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RegionGroundingError(f"{label} must be a finite number")
    parsed = float(value)
    if not math.isfinite(parsed) or not 0 <= parsed <= maximum:
        raise RegionGroundingError(f"{label} must be between 0 and {maximum}")
    return parsed


def _bbox(value: object, label: str) -> JsonObject:
    required = {"x_min", "y_min", "x_max", "y_max"}
    if not isinstance(value, dict) or set(value) != required:
        raise RegionGroundingError(f"{label} must define exactly {sorted(required)}")
    normalized = {
        key: _number(value[key], f"{label}.{key}", maximum=1.0) for key in sorted(required)
    }
    if normalized["x_max"] <= normalized["x_min"] or normalized["y_max"] <= normalized["y_min"]:
        raise RegionGroundingError(f"{label} must have positive width and height")
    return normalized


def _page(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100_000:
        raise RegionGroundingError(f"{label} must be an integer from 1 to 100000")
    return value


def normalize_region(value: object, label: str, *, required_source: str) -> JsonObject:
    """Validate and canonicalize one untrusted region object."""

    if required_source not in {"human_annotation", "model_proposal"}:
        raise RegionGroundingError("required_source is not a benchmark region source")
    if not isinstance(value, dict):
        raise RegionGroundingError(f"{label} must be an object")
    kind = value.get("kind")
    if kind not in REGION_KINDS:
        raise RegionGroundingError(f"{label}.kind must be one of {sorted(REGION_KINDS)}")
    source = value.get("source")
    if source != required_source:
        raise RegionGroundingError(f"{label}.source must equal {required_source!r}")

    if kind == "image_bbox":
        required = {"kind", "bbox", "source"}
        if not required <= set(value) or not set(value) <= required | {"label"}:
            raise RegionGroundingError(f"{label} has invalid image-bbox fields")
        normalized: JsonObject = {
            "kind": kind,
            "bbox": _bbox(value["bbox"], f"{label}.bbox"),
            "source": source,
        }
    elif kind == "pdf_bbox":
        required = {"kind", "page", "bbox", "coordinate_space", "source"}
        if not required <= set(value) or not set(value) <= required | {"label"}:
            raise RegionGroundingError(f"{label} has invalid PDF-bbox fields")
        if value.get("coordinate_space") != "normalized_top_left":
            raise RegionGroundingError(f"{label}.coordinate_space must be normalized_top_left")
        normalized = {
            "kind": kind,
            "page": _page(value.get("page"), f"{label}.page"),
            "bbox": _bbox(value["bbox"], f"{label}.bbox"),
            "coordinate_space": "normalized_top_left",
            "source": source,
        }
    elif kind == "chart_element":
        required = {"kind", "element_id", "element_type", "bbox", "source"}
        optional = {"page", "series_label", "category_label"}
        if not required <= set(value) or not set(value) <= required | optional:
            raise RegionGroundingError(f"{label} has invalid chart-element fields")
        element_type = value.get("element_type")
        if element_type not in CHART_ELEMENT_TYPES:
            raise RegionGroundingError(f"{label}.element_type is invalid")
        page = value.get("page")
        normalized = {
            "kind": kind,
            "element_id": _text(value.get("element_id"), f"{label}.element_id"),
            "element_type": element_type,
            "bbox": _bbox(value["bbox"], f"{label}.bbox"),
            "page": None if page is None else _page(page, f"{label}.page"),
            "series_label": _optional_text(value.get("series_label"), f"{label}.series_label"),
            "category_label": _optional_text(
                value.get("category_label"), f"{label}.category_label"
            ),
            "source": source,
        }
    else:
        required = {"kind", "start_seconds", "end_seconds", "source"}
        optional = {"bbox", "label"}
        if not required <= set(value) or not set(value) <= required | optional:
            raise RegionGroundingError(f"{label} has invalid video-time-range fields")
        start = _number(
            value.get("start_seconds"),
            f"{label}.start_seconds",
            maximum=MAX_REGION_TIME_SECONDS,
        )
        end = _number(
            value.get("end_seconds"),
            f"{label}.end_seconds",
            maximum=MAX_REGION_TIME_SECONDS,
        )
        if end <= start:
            raise RegionGroundingError(f"{label} must have positive duration")
        normalized = {
            "kind": kind,
            "start_seconds": start,
            "end_seconds": end,
            "bbox": (
                _bbox(value["bbox"], f"{label}.bbox") if value.get("bbox") is not None else None
            ),
            "source": source,
        }
    if "label" in value:
        normalized["label"] = _optional_text(value.get("label"), f"{label}.label")
    return normalized


def _no_duplicate_regions(regions: list[JsonObject], label: str) -> list[JsonObject]:
    canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in regions]
    if len(set(canonical)) != len(canonical):
        raise RegionGroundingError(f"{label} must not contain duplicates")
    return regions


def normalize_prediction_regions(value: object, label: str) -> list[JsonObject]:
    """Validate model proposals without accepting a model-provided entailment verdict."""

    if not isinstance(value, list) or len(value) > MAX_PREDICTED_REGIONS:
        raise RegionGroundingError(
            f"{label} must be a list of at most {MAX_PREDICTED_REGIONS} items"
        )
    return _no_duplicate_regions(
        [
            normalize_region(item, f"{label}[{index}]", required_source="model_proposal")
            for index, item in enumerate(value)
        ],
        label,
    )


def normalize_gold_regions(
    value: object,
    label: str,
    *,
    visual_evidence_ids: Sequence[str],
) -> list[JsonObject]:
    """Validate custodian annotations and bind every region to visual evidence."""

    if not isinstance(value, list) or len(value) > MAX_GOLD_REGIONS:
        raise RegionGroundingError(f"{label} must be a list of at most {MAX_GOLD_REGIONS} items")
    allowed_evidence = set(visual_evidence_ids)
    normalized: list[JsonObject] = []
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict) or set(item) != {"evidence_id", "region"}:
            raise RegionGroundingError(f"{item_label} must define exactly evidence_id and region")
        evidence_id = _text(item.get("evidence_id"), f"{item_label}.evidence_id")
        if evidence_id not in allowed_evidence:
            raise RegionGroundingError(
                f"{item_label}.evidence_id must be visual supporting evidence"
            )
        normalized.append(
            {
                "evidence_id": evidence_id,
                "region": normalize_region(
                    item.get("region"),
                    f"{item_label}.region",
                    required_source="human_annotation",
                ),
            }
        )
    return _no_duplicate_regions(normalized, label)


def bbox_iou(left: Mapping[str, Any], right: Mapping[str, Any]) -> float:
    """Return intersection-over-union for already validated normalized boxes."""

    intersection_width = max(
        0.0, min(left["x_max"], right["x_max"]) - max(left["x_min"], right["x_min"])
    )
    intersection_height = max(
        0.0,
        min(left["y_max"], right["y_max"]) - max(left["y_min"], right["y_min"]),
    )
    intersection = intersection_width * intersection_height
    left_area = (left["x_max"] - left["x_min"]) * (left["y_max"] - left["y_min"])
    right_area = (right["x_max"] - right["x_min"]) * (right["y_max"] - right["y_min"])
    union = left_area + right_area - intersection
    return intersection / union if union > 0 else 0.0


def temporal_iou(left: Mapping[str, Any], right: Mapping[str, Any]) -> float:
    """Return temporal intersection-over-union for validated half-open time ranges."""

    intersection = max(
        0.0,
        min(left["end_seconds"], right["end_seconds"])
        - max(left["start_seconds"], right["start_seconds"]),
    )
    union = (
        left["end_seconds"]
        - left["start_seconds"]
        + right["end_seconds"]
        - right["start_seconds"]
        - intersection
    )
    return intersection / union if union > 0 else 0.0


def _same_text(left: object, right: object) -> bool:
    if left is None or right is None:
        return left is right
    return str(left).strip().casefold() == str(right).strip().casefold()


def region_similarity(proposal: Mapping[str, Any], gold: Mapping[str, Any]) -> float:
    """Return a deterministic compatibility score; zero means the regions cannot match."""

    if proposal.get("kind") != gold.get("kind"):
        return 0.0
    kind = gold["kind"]
    if kind == "image_bbox":
        return bbox_iou(proposal["bbox"], gold["bbox"])
    if kind == "pdf_bbox":
        if proposal.get("page") != gold.get("page"):
            return 0.0
        return bbox_iou(proposal["bbox"], gold["bbox"])
    if kind == "chart_element":
        identity_fields = ("element_id", "element_type", "page", "series_label", "category_label")
        if any(not _same_text(proposal.get(key), gold.get(key)) for key in identity_fields):
            return 0.0
        return bbox_iou(proposal["bbox"], gold["bbox"])
    temporal = temporal_iou(proposal, gold)
    gold_bbox = gold.get("bbox")
    if gold_bbox is None:
        return temporal
    proposal_bbox = proposal.get("bbox")
    if proposal_bbox is None:
        return 0.0
    return min(temporal, bbox_iou(proposal_bbox, gold_bbox))


def _harmonic_mean(precision: float, coverage: float) -> float:
    return 0.0 if precision + coverage == 0 else 2 * precision * coverage / (precision + coverage)


def score_region_visual_entailment(
    gold_cases: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    *,
    iou_threshold: float = DEFAULT_IOU_THRESHOLD,
) -> JsonObject:
    """One-to-one match proposals to human regions within the same case/claim/evidence.

    Labels and model-provided prose are ignored.  Matching requires a compatible region type,
    the same evidence lineage, and at least the configured spatial/temporal IoU.
    """

    if len(gold_cases) != len(predictions):
        raise RegionGroundingError("gold cases and predictions must have equal length")
    if not math.isfinite(iou_threshold) or not 0 < iou_threshold <= 1:
        raise RegionGroundingError("iou_threshold must be finite and in (0, 1]")

    gold_targets: list[tuple[str, str, str, JsonObject]] = []
    proposals: list[tuple[str, str, str, JsonObject]] = []
    for case_index, (gold_case, prediction) in enumerate(zip(gold_cases, predictions, strict=True)):
        case_id = _text(gold_case.get("case_id"), f"gold_cases[{case_index}].case_id")
        claims = gold_case.get("claims", [])
        if not isinstance(claims, list):
            raise RegionGroundingError(f"gold_cases[{case_index}].claims must be a list")
        for claim_index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                raise RegionGroundingError(
                    f"gold_cases[{case_index}].claims[{claim_index}] must be an object"
                )
            claim_id = _text(
                claim.get("claim_id"),
                f"gold_cases[{case_index}].claims[{claim_index}].claim_id",
            )
            visual_ids = claim.get("visual_evidence_ids", [])
            if not isinstance(visual_ids, list) or not all(
                isinstance(item, str) for item in visual_ids
            ):
                raise RegionGroundingError(f"claim {claim_id} visual_evidence_ids is invalid")
            annotations = normalize_gold_regions(
                claim.get("entailed_regions", []),
                f"claim {claim_id}.entailed_regions",
                visual_evidence_ids=visual_ids,
            )
            gold_targets.extend(
                (case_id, claim_id, item["evidence_id"], item["region"]) for item in annotations
            )

        citations = prediction.get("citations", [])
        if not isinstance(citations, list):
            raise RegionGroundingError(f"predictions[{case_index}].citations must be a list")
        for citation_index, citation in enumerate(citations):
            if not isinstance(citation, dict):
                raise RegionGroundingError(
                    f"predictions[{case_index}].citations[{citation_index}] must be an object"
                )
            claim_id = _text(citation.get("claim_id"), f"citation {citation_index}.claim_id")
            evidence_id = _text(
                citation.get("evidence_id"), f"citation {citation_index}.evidence_id"
            )
            regions = normalize_prediction_regions(
                citation.get("regions", []), f"citation {citation_index}.regions"
            )
            proposals.extend((case_id, claim_id, evidence_id, item) for item in regions)

    if not gold_targets:
        return {
            "region_visual_entailment": None,
            "region_visual_entailment_precision": None,
            "region_visual_entailment_coverage": None,
            "gold_visual_regions": 0,
            "predicted_visual_regions": len(proposals),
            "matched_visual_regions": 0,
        }

    candidates: dict[int, list[tuple[float, int]]] = {}
    for proposal_index, proposal in enumerate(proposals):
        for gold_index, target in enumerate(gold_targets):
            if proposal[:3] != target[:3]:
                continue
            similarity = region_similarity(proposal[3], target[3])
            if similarity >= iou_threshold:
                candidates.setdefault(proposal_index, []).append((similarity, gold_index))
    adjacency = {
        proposal_index: [
            gold_index
            for _similarity, gold_index in sorted(
                matches,
                key=lambda item: (-item[0], item[1]),
            )
        ]
        for proposal_index, matches in candidates.items()
    }
    gold_match: dict[int, int] = {}

    def augment(proposal_index: int, visited_gold: set[int]) -> bool:
        for gold_index in adjacency.get(proposal_index, []):
            if gold_index in visited_gold:
                continue
            visited_gold.add(gold_index)
            prior = gold_match.get(gold_index)
            if prior is None or augment(prior, visited_gold):
                gold_match[gold_index] = proposal_index
                return True
        return False

    for proposal_index in range(len(proposals)):
        augment(proposal_index, set())

    matched = len(gold_match)
    precision = matched / len(proposals) if proposals else 0.0
    coverage = matched / len(gold_targets)
    return {
        "region_visual_entailment": round(_harmonic_mean(precision, coverage), 6),
        "region_visual_entailment_precision": round(precision, 6),
        "region_visual_entailment_coverage": round(coverage, 6),
        "gold_visual_regions": len(gold_targets),
        "predicted_visual_regions": len(proposals),
        "matched_visual_regions": matched,
    }
