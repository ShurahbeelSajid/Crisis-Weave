from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.performance_report import (
    MINIMUM_RELEASE_TAIL_SAMPLES,
    PerformanceSample,
    SLOPolicy,
    build_report,
    load_samples,
    percentile,
    write_json_atomic,
)

PRICE_SHEET = "sha256:" + "a" * 64


def _sample(
    index: int,
    stage: str,
    *,
    operation_type: str,
    duration_ms: float | None = None,
    status: str = "ok",
    cost_usd: float | None = None,
    warmup: bool = False,
) -> PerformanceSample:
    root_stage = "query" if operation_type == "query" else "ingestion"
    is_root = stage == root_stage
    return PerformanceSample.model_validate(
        {
            "schema_version": 2,
            "profile_id": "gpu-a10-v1",
            "run_id": "run-00000001",
            "sample_id": f"sample-{stage}-{index:04d}",
            "operation_id": f"operation-{operation_type}-{index:04d}",
            "operation_type": operation_type,
            "stage": stage,
            "duration_ms": duration_ms if duration_ms is not None else float(index + 1),
            "status": status,
            "measurement_scope": "end_to_end" if is_root else "core_operation",
            "observed_at": datetime(2026, 8, 3, tzinfo=UTC),
            "cost_usd": (0.001 if cost_usd is None else cost_usd) if is_root else 0.0,
            "input_tokens": 10 if operation_type == "query" and is_root else 0,
            "output_tokens": 5 if operation_type == "query" and is_root else 0,
            "input_bytes": 100 if operation_type == "document" and is_root else 0,
            "accounting_status": "complete" if is_root else "not_applicable",
            "price_sheet_digest": PRICE_SHEET if is_root else None,
            "price_sheet_effective_at": (datetime(2026, 8, 1, tzinfo=UTC) if is_root else None),
            "cost_basis": "blended" if is_root else None,
            "warmup": warmup,
        }
    )


def test_percentile_uses_linear_interpolation() -> None:
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.50) == 2.5
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.95) == pytest.approx(3.85)
    with pytest.raises(ValueError):
        percentile([], 0.5)


def test_build_report_covers_all_phases_cost_and_slo() -> None:
    samples: list[PerformanceSample] = []
    for index in range(MINIMUM_RELEASE_TAIL_SAMPLES):
        for stage in ("ingestion", "ocr", "transcription"):
            samples.append(_sample(index, stage, operation_type="document", cost_usd=0.001))
        for stage in ("retrieval", "reranking", "llm_generation", "query"):
            samples.append(_sample(index, stage, operation_type="query", cost_usd=0.002))
    samples.append(_sample(9999, "query", operation_type="query", warmup=True))
    policy = SLOPolicy(
        max_stage_p95_ms={stage: 2_000 for stage in {item.stage for item in samples}},
        max_stage_p99_ms={"query": 2_000},
        max_error_rate=0.01,
        max_query_cost_usd_p95=0.01,
        max_document_cost_usd_p95=0.01,
    )
    report = build_report(
        samples,
        expected_profile="gpu-a10-v1",
        minimum_samples_per_stage=MINIMUM_RELEASE_TAIL_SAMPLES,
        slo=policy,
    )
    assert report["warmup_samples_excluded"] == 1
    assert report["stages"]["query"]["duration_ms"]["p99"] == pytest.approx(990.01)
    assert report["cost"]["query"]["per_operation_usd"]["p95"] == 0.002
    assert report["cost"]["document"]["per_operation_usd"]["p95"] == 0.001
    assert report["operation_error_rate"] == 0.0
    assert report["stage_observation_error_rate"] == 0.0
    assert report["accounting"] == {
        "status": "complete",
        "price_sheet_digest": PRICE_SHEET,
        "price_sheet_effective_at": "2026-08-01T00:00:00+00:00",
        "cost_bases": ["blended"],
        "zero_cost_operations": 0,
    }
    assert report["slo"] == {"passed": True, "violations": []}


def test_slo_failures_and_insufficient_samples_are_explicit() -> None:
    samples = [
        _sample(index, "query", operation_type="query", duration_ms=200.0)
        for index in range(MINIMUM_RELEASE_TAIL_SAMPLES)
    ]
    samples[0] = _sample(
        0,
        "query",
        operation_type="query",
        duration_ms=200.0,
        status="error",
    )
    policy = SLOPolicy(max_stage_p95_ms={"query": 100.0}, max_error_rate=0.0)
    report = build_report(
        samples,
        expected_profile="gpu-a10-v1",
        minimum_samples_per_stage=MINIMUM_RELEASE_TAIL_SAMPLES,
        required_stages={"query"},
        slo=policy,
    )
    assert report["slo"] == {
        "passed": False,
        "violations": ["operation_error_rate", "query.p95"],
    }
    with pytest.raises(ValueError, match="requires 1000"):
        build_report(
            samples[:-1],
            expected_profile="gpu-a10-v1",
            minimum_samples_per_stage=MINIMUM_RELEASE_TAIL_SAMPLES,
            required_stages={"query"},
        )
    with pytest.raises(ValueError, match="release tail percentiles require at least 1000"):
        build_report(
            samples,
            expected_profile="gpu-a10-v1",
            minimum_samples_per_stage=999,
            required_stages={"query"},
        )


def test_sample_rejects_nonfinite_cross_operation_and_unknown_fields() -> None:
    base = _sample(1, "query", operation_type="query").model_dump()
    for change in (
        {"duration_ms": float("nan")},
        {"operation_type": "query", "stage": "ocr"},
        {"cost_basis": "provider_usage", "input_tokens": 0, "output_tokens": 0},
        {"cost_basis": "allocated_compute", "duration_ms": 0.0},
        {"observed_at": datetime(2026, 7, 1, tzinfo=UTC)},
        {"unknown": "field"},
    ):
        with pytest.raises(ValidationError):
            PerformanceSample.model_validate({**base, **change})


def test_nonroot_cost_and_incomplete_root_accounting_fail_closed() -> None:
    nonroot = _sample(1, "retrieval", operation_type="query").model_dump()
    with pytest.raises(ValidationError, match="child stages"):
        PerformanceSample.model_validate(
            {
                **nonroot,
                "cost_usd": 0.25,
                "accounting_status": "complete",
                "price_sheet_digest": PRICE_SHEET,
            }
        )

    root = _sample(1, "query", operation_type="query")
    incomplete = root.model_copy(update={"accounting_status": "incomplete"})
    with pytest.raises(ValueError, match="accounting is incomplete"):
        build_report(
            [incomplete],
            expected_profile="gpu-a10-v1",
            minimum_samples_per_stage=MINIMUM_RELEASE_TAIL_SAMPLES,
            required_stages={"query"},
        )

    zero_cost = root.model_dump()
    zero_cost["cost_usd"] = 0.0
    with pytest.raises(ValidationError, match="positive measured or allocated cost"):
        PerformanceSample.model_validate(zero_cost)


def test_measurement_scope_is_explicit_and_fail_closed() -> None:
    root = _sample(1, "query", operation_type="query").model_dump()
    root["measurement_scope"] = "core_operation"
    with pytest.raises(ValidationError, match="end-to-end"):
        PerformanceSample.model_validate(root)

    child = _sample(1, "retrieval", operation_type="query").model_dump()
    child["measurement_scope"] = "end_to_end"
    with pytest.raises(ValidationError, match="core operations"):
        PerformanceSample.model_validate(child)


def test_load_samples_rejects_mixed_runs_duplicates_and_profiles(tmp_path: Path) -> None:
    first = _sample(1, "query", operation_type="query").model_dump(mode="json")
    second = {**first, "sample_id": "sample-query-0002", "run_id": "run-00000002"}
    path = tmp_path / "samples.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in (first, second)), encoding="utf-8")
    with pytest.raises(ValueError, match="one run_id"):
        load_samples(path, expected_profile="gpu-a10-v1")
    second["run_id"] = first["run_id"]
    second["sample_id"] = first["sample_id"]
    path.write_text("\n".join(json.dumps(item) for item in (first, second)), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate sample_id"):
        load_samples(path, expected_profile="gpu-a10-v1")
    first["profile_id"] = "other-profile"
    path.write_text(json.dumps(first), encoding="utf-8")
    with pytest.raises(ValueError, match="different profile"):
        load_samples(path, expected_profile="gpu-a10-v1")


def test_atomic_report_write_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "report.json"
    payload = {"schema_version": 1, "slo": {"passed": True}}
    write_json_atomic(path, payload)
    assert json.loads(path.read_text(encoding="utf-8")) == payload
    assert list(path.parent.glob(f".{path.name}.*")) == []
