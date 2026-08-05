"""Create reproducible latency, reliability, and cost reports from raw stage samples."""

from __future__ import annotations

import argparse
import json
import math
import os
import tempfile
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

STAGES = (
    "ingestion",
    "ocr",
    "transcription",
    "retrieval",
    "reranking",
    "llm_generation",
    "query",
)
PRICE_SHEET_PATTERN = r"^sha256:[a-f0-9]{64}$"
MINIMUM_RELEASE_TAIL_SAMPLES = 1_000
MAX_RELEASE_RUN_DURATION = timedelta(days=7)


class PerformanceSample(BaseModel):
    """One collector-originated measurement; IDs must contain no tenant or user data."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[2]
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    sample_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    operation_type: Literal["query", "document"]
    stage: Literal[
        "ingestion",
        "ocr",
        "transcription",
        "retrieval",
        "reranking",
        "llm_generation",
        "query",
    ]
    duration_ms: float = Field(ge=0.0, le=7_200_000.0)
    status: Literal["ok", "error", "cancelled"]
    measurement_scope: Literal["end_to_end", "core_operation"]
    observed_at: AwareDatetime
    cost_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    input_tokens: int = Field(default=0, ge=0, le=100_000_000)
    output_tokens: int = Field(default=0, ge=0, le=100_000_000)
    input_bytes: int = Field(default=0, ge=0, le=1_099_511_627_776)
    accounting_status: Literal["not_applicable", "complete", "incomplete"]
    price_sheet_digest: str | None = Field(default=None, pattern=PRICE_SHEET_PATTERN)
    price_sheet_effective_at: AwareDatetime | None = None
    cost_basis: Literal["provider_usage", "allocated_compute", "blended"] | None = None
    warmup: bool = False

    @model_validator(mode="after")
    def validate_stage_operation(self) -> PerformanceSample:
        if not all(math.isfinite(item) for item in (self.duration_ms, self.cost_usd)):
            raise ValueError("numeric measurements must be finite")
        if self.operation_type == "query" and self.stage in {
            "ingestion",
            "ocr",
            "transcription",
        }:
            raise ValueError("query operations cannot contain ingestion-only stages")
        if self.operation_type == "document" and self.stage in {
            "retrieval",
            "reranking",
            "llm_generation",
            "query",
        }:
            raise ValueError("document operations cannot contain query-only stages")
        root_stage = "query" if self.operation_type == "query" else "ingestion"
        if self.stage == root_stage:
            if self.measurement_scope != "end_to_end":
                raise ValueError("root samples must measure end-to-end operation latency")
            if (
                self.accounting_status == "not_applicable"
                or self.price_sheet_digest is None
                or self.price_sheet_effective_at is None
                or self.cost_basis is None
            ):
                raise ValueError(
                    "root samples require accounting status, basis, effective date, and price sheet"
                )
            if self.price_sheet_digest == "sha256:" + "0" * 64:
                raise ValueError("root samples require a non-placeholder price-sheet digest")
            if self.cost_usd <= 0.0:
                raise ValueError("root samples require a positive measured or allocated cost")
            if self.price_sheet_effective_at > self.observed_at:
                raise ValueError("price sheet must be effective when the operation is observed")
            if self.cost_basis in {"provider_usage", "blended"}:
                if self.operation_type == "query" and self.input_tokens + self.output_tokens == 0:
                    raise ValueError("provider-priced query cost requires measured token usage")
                if self.operation_type == "document" and self.input_bytes == 0:
                    raise ValueError("provider-priced document cost requires measured input bytes")
            if self.cost_basis in {"allocated_compute", "blended"} and self.duration_ms <= 0.0:
                raise ValueError("compute-allocated cost requires a positive measured duration")
        elif (
            self.measurement_scope != "core_operation"
            or self.accounting_status != "not_applicable"
            or self.price_sheet_digest is not None
            or self.price_sheet_effective_at is not None
            or self.cost_basis is not None
            or self.cost_usd != 0.0
            or self.input_tokens != 0
            or self.output_tokens != 0
            or self.input_bytes != 0
        ):
            raise ValueError(
                "child stages must be core operations without cost or accounting metadata"
            )
        return self


class SLOPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_stage_p95_ms: dict[str, float] = Field(default_factory=dict)
    max_stage_p99_ms: dict[str, float] = Field(default_factory=dict)
    max_error_rate: float = Field(default=0.01, ge=0.0, lt=1.0)
    max_query_cost_usd_p95: float | None = Field(default=None, gt=0.0)
    max_document_cost_usd_p95: float | None = Field(default=None, gt=0.0)

    @model_validator(mode="after")
    def validate_stages(self) -> SLOPolicy:
        for mapping in (self.max_stage_p95_ms, self.max_stage_p99_ms):
            unknown = set(mapping) - set(STAGES)
            if unknown:
                raise ValueError(f"unknown SLO stage: {sorted(unknown)[0]}")
            if any(not math.isfinite(value) or value <= 0 for value in mapping.values()):
                raise ValueError("stage SLO values must be finite and positive")
        return self


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile without values")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _distribution(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(sum(values) / len(values), 6),
        "p50": round(percentile(values, 0.50), 6),
        "p95": round(percentile(values, 0.95), 6),
        "p99": round(percentile(values, 0.99), 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
    }


def load_samples(path: Path, *, expected_profile: str) -> list[PerformanceSample]:
    samples: list[PerformanceSample] = []
    sample_ids: set[str] = set()
    run_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if len(line) > 1_000_000:
                raise ValueError(f"line {line_number} exceeds the byte limit")
            if not line.strip():
                continue
            try:
                sample = PerformanceSample.model_validate_json(line)
            except ValidationError as exc:
                raise ValueError(f"invalid performance sample on line {line_number}") from exc
            if sample.profile_id != expected_profile:
                raise ValueError(f"line {line_number} belongs to a different profile")
            if sample.sample_id in sample_ids:
                raise ValueError(f"duplicate sample_id on line {line_number}")
            sample_ids.add(sample.sample_id)
            run_ids.add(sample.run_id)
            samples.append(sample)
    if not samples:
        raise ValueError("the performance sample file is empty")
    if len(run_ids) != 1:
        raise ValueError("one report must contain exactly one run_id")
    return samples


def build_report(
    samples: list[PerformanceSample],
    *,
    expected_profile: str,
    minimum_samples_per_stage: int = MINIMUM_RELEASE_TAIL_SAMPLES,
    required_stages: set[str] | None = None,
    slo: SLOPolicy | None = None,
) -> dict[str, Any]:
    if minimum_samples_per_stage < MINIMUM_RELEASE_TAIL_SAMPLES:
        raise ValueError(
            "release tail percentiles require at least "
            f"{MINIMUM_RELEASE_TAIL_SAMPLES} samples per stage"
        )
    required = set(STAGES) if required_stages is None else set(required_stages)
    unknown = required - set(STAGES)
    if unknown:
        raise ValueError(f"unknown required stage: {sorted(unknown)[0]}")
    measured = [item for item in samples if not item.warmup]
    if not measured:
        raise ValueError("all performance samples are marked as warmup")
    if any(item.profile_id != expected_profile for item in measured):
        raise ValueError("samples contain an unexpected profile")
    measurement_started_at = min(item.observed_at for item in measured)
    measurement_ended_at = max(item.observed_at for item in measured)
    if measurement_ended_at - measurement_started_at > MAX_RELEASE_RUN_DURATION:
        raise ValueError("one performance run cannot span more than seven days")

    by_stage: dict[str, list[PerformanceSample]] = defaultdict(list)
    by_operation: dict[tuple[str, str], list[PerformanceSample]] = defaultdict(list)
    for sample in measured:
        by_stage[sample.stage].append(sample)
        by_operation[(sample.operation_type, sample.operation_id)].append(sample)

    root_samples: list[PerformanceSample] = []
    for (operation_type, operation_id), operation_samples in by_operation.items():
        root_stage = "query" if operation_type == "query" else "ingestion"
        roots = [item for item in operation_samples if item.stage == root_stage]
        if len(roots) != 1:
            raise ValueError(
                f"operation {operation_id} must contain exactly one {root_stage} root sample"
            )
        root_samples.append(roots[0])
    incomplete = [
        item.operation_id for item in root_samples if item.accounting_status != "complete"
    ]
    if incomplete:
        raise ValueError(f"operation accounting is incomplete: {sorted(incomplete)[0]}")
    price_after_observation = [
        item.operation_id
        for item in root_samples
        if item.price_sheet_effective_at is not None
        and item.price_sheet_effective_at > item.observed_at
    ]
    if price_after_observation:
        raise ValueError(
            f"price sheet became effective after operation: {sorted(price_after_observation)[0]}"
        )
    price_sheets = {item.price_sheet_digest for item in root_samples}
    if len(price_sheets) != 1 or None in price_sheets:
        raise ValueError("one report must use exactly one price-sheet digest")
    price_sheet_digest = next(item for item in price_sheets if item is not None)
    price_sheet_effective_times = {item.price_sheet_effective_at for item in root_samples}
    if len(price_sheet_effective_times) != 1:
        raise ValueError("one report must use exactly one price-sheet effective time")
    price_sheet_effective_at = next(iter(price_sheet_effective_times))
    if price_sheet_effective_at is None:
        raise ValueError("root samples require a price-sheet effective time")
    cost_bases = {item.cost_basis for item in root_samples}
    if None in cost_bases:
        raise ValueError("root samples require a cost basis")
    zero_cost_operations = [item.operation_id for item in root_samples if item.cost_usd <= 0.0]
    if zero_cost_operations:
        raise ValueError(f"operation cost is not positive: {sorted(zero_cost_operations)[0]}")

    for stage in sorted(set(by_stage) | required):
        if len(by_stage[stage]) < minimum_samples_per_stage:
            raise ValueError(
                f"stage {stage} has {len(by_stage[stage])} samples; "
                f"requires {minimum_samples_per_stage}"
            )

    stage_report: dict[str, Any] = {}
    stage_observation_errors = 0
    for stage, stage_samples in sorted(by_stage.items()):
        durations = [item.duration_ms for item in stage_samples]
        errors = sum(item.status != "ok" for item in stage_samples)
        stage_observation_errors += errors
        stage_report[stage] = {
            "measurement_scope": (
                "end_to_end" if stage in {"query", "ingestion"} else "core_operation"
            ),
            "samples": len(stage_samples),
            "errors": errors,
            "error_rate": round(errors / len(stage_samples), 6),
            "duration_ms": _distribution(durations),
            "cost_usd_total": round(sum(item.cost_usd for item in stage_samples), 8),
            "input_tokens_total": sum(item.input_tokens for item in stage_samples),
            "output_tokens_total": sum(item.output_tokens for item in stage_samples),
            "input_bytes_total": sum(item.input_bytes for item in stage_samples),
        }

    operation_costs: dict[str, list[float]] = {"query": [], "document": []}
    for root in root_samples:
        operation_costs[root.operation_type].append(root.cost_usd)
    cost_report: dict[str, dict[str, Any]] = {
        name: {
            "operations": len(costs),
            "total_usd": round(sum(costs), 8),
            "per_operation_usd": _distribution(costs),
        }
        for name, costs in operation_costs.items()
        if costs
    }
    operation_errors = sum(item.status != "ok" for item in root_samples)

    report: dict[str, Any] = {
        "schema_version": 2,
        "profile_id": expected_profile,
        "run_id": measured[0].run_id,
        "warmup_samples_excluded": len(samples) - len(measured),
        "measured_samples": len(measured),
        "measurement_started_at": measurement_started_at.isoformat(),
        "measurement_ended_at": measurement_ended_at.isoformat(),
        "operation_errors": operation_errors,
        "operation_error_rate": round(operation_errors / len(root_samples), 6),
        "stage_observation_errors": stage_observation_errors,
        "stage_observation_error_rate": round(stage_observation_errors / len(measured), 6),
        "accounting": {
            "status": "complete",
            "price_sheet_digest": price_sheet_digest,
            "price_sheet_effective_at": price_sheet_effective_at.isoformat(),
            "cost_bases": sorted(item for item in cost_bases if item is not None),
            "zero_cost_operations": 0,
        },
        "measurement_contract": {
            "child_scope": "core_operation",
            "latency_population": "all_terminal_statuses",
            "minimum_tail_samples_per_stage": minimum_samples_per_stage,
            "percentile_method": "linear_interpolation",
            "root_scope": "end_to_end",
        },
        "stages": stage_report,
        "cost": cost_report,
    }
    if slo is not None:
        violations: list[str] = []
        if report["operation_error_rate"] > slo.max_error_rate:
            violations.append("operation_error_rate")
        for stage, threshold in slo.max_stage_p95_ms.items():
            measured_value = stage_report.get(stage, {}).get("duration_ms", {}).get("p95")
            if measured_value is None or measured_value > threshold:
                violations.append(f"{stage}.p95")
        for stage, threshold in slo.max_stage_p99_ms.items():
            measured_value = stage_report.get(stage, {}).get("duration_ms", {}).get("p99")
            if measured_value is None or measured_value > threshold:
                violations.append(f"{stage}.p99")
        for operation, cost_threshold in (
            ("query", slo.max_query_cost_usd_p95),
            ("document", slo.max_document_cost_usd_p95),
        ):
            if cost_threshold is None:
                continue
            measured_value = cost_report.get(operation, {}).get("per_operation_usd", {}).get("p95")
            if measured_value is None or measured_value > cost_threshold:
                violations.append(f"{operation}.cost.p95")
        report["slo"] = {"passed": not violations, "violations": violations}
    return report


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument(
        "--minimum-samples-per-stage",
        type=int,
        default=MINIMUM_RELEASE_TAIL_SAMPLES,
    )
    parser.add_argument("--required-stage", action="append", choices=STAGES)
    parser.add_argument("--slo", type=Path)
    args = parser.parse_args()
    samples = load_samples(args.input, expected_profile=args.profile)
    policy = None
    if args.slo:
        policy = SLOPolicy.model_validate_json(args.slo.read_text(encoding="utf-8"))
    report = build_report(
        samples,
        expected_profile=args.profile,
        minimum_samples_per_stage=args.minimum_samples_per_stage,
        required_stages=set(args.required_stage) if args.required_stage else None,
        slo=policy,
    )
    write_json_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if policy is not None and not report["slo"]["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
