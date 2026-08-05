from __future__ import annotations

import hashlib

import pytest

import scripts.region_grounding_metrics as region_metrics
from scripts.benchmark_metrics import SYSTEM_CONFIGURATIONS, BenchmarkError, attest_run, score_run
from scripts.region_grounding_metrics import (
    RegionGroundingError,
    normalize_gold_regions,
    normalize_prediction_regions,
    region_similarity,
    score_region_visual_entailment,
)

TRACE = b'{"collector":"region-test"}'
KEY = b"region-grounding-attestation-key-32-bytes"


def _bbox(
    x_min: float = 0.1,
    y_min: float = 0.1,
    x_max: float = 0.9,
    y_max: float = 0.9,
) -> dict[str, float]:
    return {"x_min": x_min, "y_min": y_min, "x_max": x_max, "y_max": y_max}


def _region(kind: str, *, source: str) -> dict[str, object]:
    if kind == "image_bbox":
        return {"kind": kind, "bbox": _bbox(), "source": source}
    if kind == "pdf_bbox":
        return {
            "kind": kind,
            "page": 4,
            "bbox": _bbox(),
            "coordinate_space": "normalized_top_left",
            "source": source,
        }
    if kind == "chart_element":
        return {
            "kind": kind,
            "element_id": "loss-2024",
            "element_type": "bar",
            "bbox": _bbox(),
            "page": 4,
            "series_label": "Loss",
            "category_label": "2024",
            "source": source,
        }
    return {
        "kind": "video_time_range",
        "start_seconds": 10.0,
        "end_seconds": 20.0,
        "bbox": _bbox(),
        "source": source,
    }


def test_region_contract_rejects_self_attestation_nonfinite_geometry_and_duplicates() -> None:
    proposal = _region("image_bbox", source="model_proposal")
    proposal["entailed"] = True
    with pytest.raises(RegionGroundingError, match="invalid image-bbox fields"):
        normalize_prediction_regions([proposal], "citation.regions")

    proposal = _region("image_bbox", source="human_annotation")
    with pytest.raises(RegionGroundingError, match="source"):
        normalize_prediction_regions([proposal], "citation.regions")

    proposal = _region("image_bbox", source="model_proposal")
    proposal["bbox"] = _bbox(x_min=float("nan"))
    with pytest.raises(RegionGroundingError, match="between"):
        normalize_prediction_regions([proposal], "citation.regions")

    proposal = _region("image_bbox", source="model_proposal")
    with pytest.raises(RegionGroundingError, match="duplicates"):
        normalize_prediction_regions([proposal, proposal], "citation.regions")


def test_gold_regions_must_bind_to_visual_support() -> None:
    annotation = {
        "evidence_id": "text-only",
        "region": _region("image_bbox", source="human_annotation"),
    }
    with pytest.raises(RegionGroundingError, match="visual supporting evidence"):
        normalize_gold_regions(
            [annotation],
            "claim.entailed_regions",
            visual_evidence_ids=["visual"],
        )


def test_pdf_page_and_video_frame_box_constraints_fail_closed() -> None:
    gold_pdf = _region("pdf_bbox", source="human_annotation")
    proposal_pdf = _region("pdf_bbox", source="model_proposal")
    proposal_pdf["page"] = 5
    assert region_similarity(proposal_pdf, gold_pdf) == 0.0

    gold_video = _region("video_time_range", source="human_annotation")
    proposal_video = _region("video_time_range", source="model_proposal")
    proposal_video.pop("bbox")
    assert region_similarity(proposal_video, gold_video) == 0.0


def test_deterministic_region_scorer_matches_all_supported_locator_types() -> None:
    kinds = ("image_bbox", "pdf_bbox", "chart_element", "video_time_range")
    annotations = [
        {
            "evidence_id": f"evidence-{index}",
            "region": _region(kind, source="human_annotation"),
        }
        for index, kind in enumerate(kinds)
    ]
    proposals = [_region(kind, source="model_proposal") for kind in kinds]
    gold_cases = [
        {
            "case_id": "case",
            "claims": [
                {
                    "claim_id": "claim",
                    "visual_evidence_ids": [f"evidence-{index}" for index in range(4)],
                    "entailed_regions": annotations,
                }
            ],
        }
    ]
    predictions = [
        {
            "citations": [
                {
                    "claim_id": "claim",
                    "evidence_id": f"evidence-{index}",
                    "regions": [proposal],
                }
                for index, proposal in enumerate(proposals)
            ]
        }
    ]

    report = score_region_visual_entailment(gold_cases, predictions)

    assert report["region_visual_entailment"] == 1.0
    assert report["matched_visual_regions"] == 4


def test_region_scorer_requires_identity_lineage_and_one_to_one_overlap() -> None:
    gold_region = _region("chart_element", source="human_annotation")
    wrong_identity = _region("chart_element", source="model_proposal")
    wrong_identity["element_id"] = "different-bar"
    matching = _region("chart_element", source="model_proposal")
    gold_cases = [
        {
            "case_id": "case",
            "claims": [
                {
                    "claim_id": "claim",
                    "visual_evidence_ids": ["evidence"],
                    "entailed_regions": [{"evidence_id": "evidence", "region": gold_region}],
                }
            ],
        }
    ]
    predictions = [
        {
            "citations": [
                {
                    "claim_id": "claim",
                    "evidence_id": "evidence",
                    "regions": [wrong_identity, matching],
                }
            ]
        }
    ]

    report = score_region_visual_entailment(gold_cases, predictions)

    assert report["matched_visual_regions"] == 1
    assert report["region_visual_entailment_precision"] == 0.5
    assert report["region_visual_entailment_coverage"] == 1.0
    assert report["region_visual_entailment"] == pytest.approx(0.666667)


def test_region_matching_maximizes_cardinality_instead_of_greedy_iou(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def labeled_region(label: str, source: str) -> dict[str, object]:
        return {
            "kind": "image_bbox",
            "bbox": _bbox(),
            "label": label,
            "source": source,
        }

    similarities = {
        ("p1", "g1"): 0.9,
        ("p1", "g2"): 0.8,
        ("p2", "g1"): 0.85,
        ("p2", "g2"): 0.0,
    }
    monkeypatch.setattr(
        region_metrics,
        "region_similarity",
        lambda proposal, gold: similarities[(proposal["label"], gold["label"])],
    )
    gold_cases = [
        {
            "case_id": "case",
            "claims": [
                {
                    "claim_id": "claim",
                    "visual_evidence_ids": ["evidence"],
                    "entailed_regions": [
                        {
                            "evidence_id": "evidence",
                            "region": labeled_region("g1", "human_annotation"),
                        },
                        {
                            "evidence_id": "evidence",
                            "region": labeled_region("g2", "human_annotation"),
                        },
                    ],
                }
            ],
        }
    ]
    predictions = [
        {
            "citations": [
                {
                    "claim_id": "claim",
                    "evidence_id": "evidence",
                    "regions": [
                        labeled_region("p1", "model_proposal"),
                        labeled_region("p2", "model_proposal"),
                    ],
                }
            ]
        }
    ]

    report = score_region_visual_entailment(gold_cases, predictions)

    assert report["matched_visual_regions"] == 2
    assert report["region_visual_entailment"] == 1.0


def test_region_scorer_is_undefined_without_human_region_gold() -> None:
    report = score_region_visual_entailment(
        [
            {
                "case_id": "case",
                "claims": [
                    {
                        "claim_id": "claim",
                        "visual_evidence_ids": ["evidence"],
                    }
                ],
            }
        ],
        [
            {
                "citations": [
                    {
                        "claim_id": "claim",
                        "evidence_id": "evidence",
                        "regions": [_region("image_bbox", source="model_proposal")],
                    }
                ]
            }
        ],
    )

    assert report["region_visual_entailment"] is None
    assert report["predicted_visual_regions"] == 1


def test_public_benchmark_hook_scores_region_entailment_and_rejects_wrong_source() -> None:
    gold = {
        "schema_version": 1,
        "benchmark_id": "region-fixture",
        "benchmark_version": "1",
        "annotation_status": "adjudicated",
        "cases": [
            {
                "case_id": "case",
                "event_id": "event",
                "split": "test",
                "question": "What is visible?",
                "task_types": ["retrieval", "routing", "citation", "visual"],
                "expected_routes": ["vector"],
                "expected_behavior": "answer",
                "relevance": {"evidence": 3},
                "claims": [
                    {
                        "claim_id": "claim",
                        "supporting_evidence_ids": ["evidence"],
                        "supporting_modalities": ["image"],
                        "visual_evidence_ids": ["evidence"],
                        "visual": True,
                        "entailed_regions": [
                            {
                                "evidence_id": "evidence",
                                "region": _region("image_bbox", source="human_annotation"),
                            }
                        ],
                    }
                ],
                "injection_attack": False,
            }
        ],
    }
    system_id = "agentic_multimodal_rag"
    run = {
        "schema_version": 1,
        "benchmark_id": "region-fixture",
        "benchmark_version": "1",
        "split": "test",
        "system": {
            "system_id": system_id,
            "artifact_id": f"sha256:{hashlib.sha256(system_id.encode()).hexdigest()}",
            "configuration": SYSTEM_CONFIGURATIONS[system_id],
        },
        "predictions": [
            {
                "case_id": "case",
                "retrieved": ["evidence"],
                "routes": ["vector"],
                "behavior": "answer",
                "citations": [
                    {
                        "claim_id": "claim",
                        "evidence_id": "evidence",
                        "regions": [_region("image_bbox", source="model_proposal")],
                    }
                ],
                "usage": {
                    "latency_ms": 1,
                    "cost_usd": 0,
                    "input_tokens": 1,
                    "output_tokens": 1,
                },
            }
        ],
    }
    attested = attest_run(run, TRACE, KEY)

    report = score_run(
        gold,
        attested,
        split="test",
        trace_payload=TRACE,
        attestation_key=KEY,
        k_values=(1,),
    )
    assert report["metrics"]["region_visual_entailment"] == 1.0
    assert report["sample_counts"]["visual_regions"] == 1

    run["predictions"][0]["citations"][0]["regions"][0]["source"] = "human_annotation"
    with pytest.raises(BenchmarkError, match="source"):
        score_run(
            gold,
            attest_run(run, TRACE, KEY),
            split="test",
            trace_payload=TRACE,
            attestation_key=KEY,
            k_values=(1,),
        )
