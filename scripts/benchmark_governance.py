"""Custodian-side governance for blind annotation and public benchmark releases.

The application never imports this module.  It deliberately keeps annotator identities,
sealed labels, decryption keys, and signing keys outside prediction-serving processes.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import os
import re
import statistics
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    from scripts.benchmark_metrics import (
        REQUIRED_SYSTEMS,
        ROUTES,
        SYSTEM_CONFIGURATIONS,
        BenchmarkError,
        _denotation_equal,
        load_json_object,
        validate_benchmark_bundle,
        validate_event_manifest,
        validate_gold,
    )
    from scripts.benchmark_statistics import event_bootstrap_confidence_intervals
except ModuleNotFoundError as exc:  # Direct `python scripts/benchmark_governance.py` execution.
    if exc.name not in {
        "scripts",
        "scripts.benchmark_metrics",
        "scripts.benchmark_statistics",
    }:
        raise
    from benchmark_metrics import (  # type: ignore[no-redef]
        REQUIRED_SYSTEMS,
        ROUTES,
        SYSTEM_CONFIGURATIONS,
        BenchmarkError,
        _denotation_equal,
        load_json_object,
        validate_benchmark_bundle,
        validate_event_manifest,
        validate_gold,
    )
    from benchmark_statistics import (  # type: ignore[no-redef]
        event_bootstrap_confidence_intervals,
    )

JsonObject = dict[str, Any]
ANNOTATOR_TOKEN = re.compile(r"anon:[a-zA-Z0-9_-]{16,128}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
PRIVATE_COMMITMENT_NONCE = re.compile(r"nonce:[a-f0-9]{64}")
PRIVATE_IDENTITY_FIELDS = {"annotator_name", "name", "email", "organization", "user_id"}
EXPOSURE_CLASSES = {"historical_public", "recent_public", "private_custodian"}
MIN_PUBLIC_METRIC_EVENTS = 5
PUBLIC_EVENT_METRICS = frozenset(
    {
        "recall@5",
        "recall@10",
        "recall@30",
        "ndcg@5",
        "ndcg@10",
        "ndcg@30",
        "mrr",
        "routing_accuracy",
        "sql_answer_accuracy",
        "citation_precision",
        "citation_coverage",
        "visual_groundedness",
        "region_visual_entailment",
        "abstention_accuracy",
        "prompt_injection_success_rate",
        "exact_answer_accuracy",
        "cost_usd_mean",
        "latency_ms_mean",
    }
)
PUBLIC_UNBOUNDED_EVENT_METRICS = frozenset({"cost_usd_mean", "latency_ms_mean"})
ADJUDICATED_FIELDS = (
    "expected_routes",
    "expected_behavior",
    "relevance",
    "claims",
    "sql_denotation",
    "injection_attack",
    "knowledge_probe",
    "answer_denotation",
    "exposure_class",
)
EVIDENCE_CONDITIONS = {
    "authoritative",
    "conflict_probe_pending",
    "degraded_or_incomplete",
    "preliminary_unvalidated",
}
GEOGRAPHIC_REGIONS = {
    "africa",
    "asia",
    "europe",
    "latin_america_caribbean",
    "middle_east_north_africa",
    "north_america",
    "oceania",
}
MAX_GOVERNANCE_ARTIFACT_BYTES = 128 * 1024 * 1024


class GovernanceError(BenchmarkError):
    """Raised when a governance artifact violates the custodian protocol."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GovernanceError("artifact is not canonical JSON") from exc


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json(value) + b"\n")


def _non_empty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{label} must be a non-empty string")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise GovernanceError(f"{label} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise GovernanceError(f"{label} must not be empty")
    if len(value) != len(set(value)):
        raise GovernanceError(f"{label} must not contain duplicates")
    return list(value)


def _reject_identity_fields(value: object, path: str = "submission") -> None:
    if isinstance(value, dict):
        forbidden = PRIVATE_IDENTITY_FIELDS & set(value)
        if forbidden:
            raise GovernanceError(
                f"{path} exposes identity fields forbidden in a blind packet: {sorted(forbidden)}"
            )
        for key, item in value.items():
            _reject_identity_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_identity_fields(item, f"{path}[{index}]")


def _read_bounded(path: Path, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            value = handle.read(MAX_GOVERNANCE_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise GovernanceError(f"could not read {label}: {exc}") from exc
    if not 0 < len(value) <= MAX_GOVERNANCE_ARTIFACT_BYTES:
        raise GovernanceError(f"{label} must contain 1-{MAX_GOVERNANCE_ARTIFACT_BYTES} bytes")
    return value


def validate_blind_packet(packet: Mapping[str, Any]) -> list[JsonObject]:
    """Validate a custodian-created packet that contains no annotator identity."""

    if packet.get("schema_version") != 1:
        raise GovernanceError("annotation packet schema_version must equal 1")
    _non_empty(packet.get("benchmark_id"), "benchmark_id")
    _non_empty(packet.get("benchmark_version"), "benchmark_version")
    _non_empty(packet.get("assignment_id"), "assignment_id")
    if packet.get("split") not in {"train", "development", "test"}:
        raise GovernanceError("annotation packet split is invalid")
    _reject_identity_fields(packet, "packet")
    cases = packet.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GovernanceError("annotation packet cases must be a non-empty list")
    seen_cases: set[str] = set()
    result: list[JsonObject] = []
    for index, raw_case in enumerate(cases):
        label = f"cases[{index}]"
        if not isinstance(raw_case, dict):
            raise GovernanceError(f"{label} must be an object")
        case_id = _non_empty(raw_case.get("case_id"), f"{label}.case_id")
        if case_id in seen_cases:
            raise GovernanceError(f"duplicate annotation case_id: {case_id}")
        seen_cases.add(case_id)
        _non_empty(raw_case.get("event_id"), f"{label}.event_id")
        _non_empty(raw_case.get("question"), f"{label}.question")
        tasks = _string_list(raw_case.get("task_types"), f"{label}.task_types", allow_empty=False)
        pool = raw_case.get("evidence_pool")
        if not isinstance(pool, list) or not pool:
            raise GovernanceError(f"{label}.evidence_pool must be a non-empty list")
        evidence_ids: set[str] = set()
        normalized_pool: list[JsonObject] = []
        for evidence_index, evidence in enumerate(pool):
            evidence_label = f"{label}.evidence_pool[{evidence_index}]"
            if not isinstance(evidence, dict):
                raise GovernanceError(f"{evidence_label} must be an object")
            evidence_id = _non_empty(evidence.get("evidence_id"), f"{evidence_label}.evidence_id")
            if evidence_id in evidence_ids:
                raise GovernanceError(f"duplicate evidence_id in {case_id}: {evidence_id}")
            evidence_ids.add(evidence_id)
            modalities = _string_list(
                evidence.get("modalities"), f"{evidence_label}.modalities", allow_empty=False
            )
            source_digest = _non_empty(
                evidence.get("source_sha256"), f"{evidence_label}.source_sha256"
            )
            if not DIGEST.fullmatch(source_digest):
                raise GovernanceError(f"{evidence_label}.source_sha256 is invalid")
            normalized_pool.append(
                {**evidence, "evidence_id": evidence_id, "modalities": modalities}
            )
        result.append(
            {
                **raw_case,
                "case_id": case_id,
                "task_types": tasks,
                "evidence_pool": normalized_pool,
            }
        )
    return result


def _validate_blindness(value: object, label: str) -> None:
    expected = {
        "worked_independently": True,
        "no_cross_annotator_contact": True,
        "used_only_packet_evidence": True,
    }
    if value != expected:
        raise GovernanceError(f"{label} must equal {expected}")


def _validate_claims(value: object, relevance: Mapping[str, int], label: str) -> list[JsonObject]:
    if not isinstance(value, list):
        raise GovernanceError(f"{label} must be a list")
    claims: list[JsonObject] = []
    claim_ids: set[str] = set()
    for index, claim in enumerate(value):
        claim_label = f"{label}[{index}]"
        if not isinstance(claim, dict):
            raise GovernanceError(f"{claim_label} must be an object")
        claim_id = _non_empty(claim.get("claim_id"), f"{claim_label}.claim_id")
        if claim_id in claim_ids:
            raise GovernanceError(f"duplicate claim_id: {claim_id}")
        claim_ids.add(claim_id)
        support = _string_list(
            claim.get("supporting_evidence_ids"),
            f"{claim_label}.supporting_evidence_ids",
            allow_empty=False,
        )
        if not set(support) <= set(relevance) or any(relevance[item] <= 0 for item in support):
            raise GovernanceError(f"{claim_label} cites unjudged or non-relevant evidence")
        modalities = _string_list(
            claim.get("supporting_modalities"),
            f"{claim_label}.supporting_modalities",
            allow_empty=False,
        )
        visual = _string_list(
            claim.get("visual_evidence_ids", []), f"{claim_label}.visual_evidence_ids"
        )
        if not set(visual) <= set(support):
            raise GovernanceError(f"{claim_label}.visual_evidence_ids must be supporting evidence")
        if claim.get("visual") is not bool(visual):
            raise GovernanceError(f"{claim_label}.visual must agree with visual_evidence_ids")
        claims.append(
            {
                **claim,
                "claim_id": claim_id,
                "supporting_evidence_ids": support,
                "supporting_modalities": modalities,
                "visual_evidence_ids": visual,
            }
        )
    return claims


def validate_annotation_submission(
    packet: Mapping[str, Any], submission: Mapping[str, Any]
) -> tuple[str, list[JsonObject]]:
    """Validate a blind submission and complete evidence-pool judgments."""

    packet_cases = validate_blind_packet(packet)
    if submission.get("schema_version") != 1:
        raise GovernanceError("annotation submission schema_version must equal 1")
    for field in ("benchmark_id", "benchmark_version", "assignment_id"):
        if submission.get(field) != packet.get(field):
            raise GovernanceError(f"submission {field} does not match its packet")
    token = _non_empty(submission.get("annotator_token"), "annotator_token")
    if not ANNOTATOR_TOKEN.fullmatch(token):
        raise GovernanceError("annotator_token must be an opaque anon: token")
    _reject_identity_fields(submission)
    _validate_blindness(submission.get("blindness_attestation"), "blindness_attestation")
    raw_cases = submission.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != len(packet_cases):
        raise GovernanceError("submission must contain every packet case in canonical order")
    normalized: list[JsonObject] = []
    for index, (packet_case, raw_case) in enumerate(zip(packet_cases, raw_cases, strict=True)):
        label = f"cases[{index}]"
        if not isinstance(raw_case, dict) or raw_case.get("case_id") != packet_case["case_id"]:
            raise GovernanceError(f"{label} must match canonical case_id {packet_case['case_id']}")
        routes = _string_list(raw_case.get("expected_routes"), f"{label}.expected_routes")
        if not set(routes) <= ROUTES:
            raise GovernanceError(f"{label}.expected_routes contains an unknown route")
        behavior = raw_case.get("expected_behavior")
        if behavior not in {"answer", "abstain", "blocked"}:
            raise GovernanceError(f"{label}.expected_behavior is invalid")
        relevance = raw_case.get("relevance")
        expected_evidence = {item["evidence_id"] for item in packet_case["evidence_pool"]}
        if not isinstance(relevance, dict) or set(relevance) != expected_evidence:
            raise GovernanceError(f"{label}.relevance must grade the complete evidence pool")
        if any(
            isinstance(grade, bool) or not isinstance(grade, int) or not 0 <= grade <= 3
            for grade in relevance.values()
        ):
            raise GovernanceError(f"{label}.relevance grades must be integers from 0 to 3")
        claims = _validate_claims(raw_case.get("claims"), relevance, f"{label}.claims")
        if behavior == "answer" and not claims:
            raise GovernanceError(f"{label} answer behavior requires atomic claims")
        if behavior != "answer" and claims:
            raise GovernanceError(f"{label} non-answer behavior cannot have claims")
        if "visual" in packet_case["task_types"]:
            visual_claims = [claim for claim in claims if claim.get("visual") is True]
            if (
                behavior != "answer"
                or not visual_claims
                or any(not claim.get("entailed_regions") for claim in visual_claims)
            ):
                raise GovernanceError(
                    f"{label} visual tasks require human regions for every visual claim"
                )
        injection = raw_case.get("injection_attack", False)
        if not isinstance(injection, bool):
            raise GovernanceError(f"{label}.injection_attack must be boolean")
        if "sql_denotation" in raw_case and "sql" not in routes:
            raise GovernanceError(f"{label}.sql_denotation requires the SQL route")
        knowledge_probe = raw_case.get("knowledge_probe", False)
        if not isinstance(knowledge_probe, bool):
            raise GovernanceError(f"{label}.knowledge_probe must be boolean")
        has_answer_denotation = "answer_denotation" in raw_case
        if knowledge_probe and not has_answer_denotation:
            raise GovernanceError(f"{label} knowledge probes require answer_denotation")
        if not knowledge_probe and has_answer_denotation:
            raise GovernanceError(f"{label} non-knowledge cases cannot define answer_denotation")
        if has_answer_denotation:
            _canonical_json(raw_case["answer_denotation"])
        exposure_class = raw_case.get("exposure_class")
        if exposure_class is not None and exposure_class not in EXPOSURE_CLASSES:
            raise GovernanceError(f"{label}.exposure_class is invalid")
        if knowledge_probe and exposure_class is None:
            raise GovernanceError(f"{label} knowledge probes require exposure_class")
        normalized.append(
            {
                **raw_case,
                "case_id": packet_case["case_id"],
                "event_id": packet_case["event_id"],
                "split": packet["split"],
                "task_types": packet_case["task_types"],
                "question": packet_case["question"],
                "expected_routes": routes,
                "expected_behavior": behavior,
                "relevance": relevance,
                "claims": claims,
                "injection_attack": injection,
                "knowledge_probe": knowledge_probe,
                "exposure_class": exposure_class,
            }
        )
    return token, normalized


def _cohen_kappa(left: Sequence[object], right: Sequence[object]) -> float | None:
    if len(left) != len(right) or not left:
        return None
    observed = sum(a == b for a, b in zip(left, right, strict=True)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    expected = sum(
        left_counts[item] / len(left) * right_counts[item] / len(right)
        for item in set(left_counts) | set(right_counts)
    )
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1.0 - expected)


def _weighted_kappa(left: Sequence[int], right: Sequence[int]) -> float | None:
    """Quadratic-weighted Cohen kappa for the complete 0-3 relevance pool."""

    if len(left) != len(right) or not left:
        return None
    levels = range(4)
    observed = 0.0
    for a, b in zip(left, right, strict=True):
        observed += ((a - b) / 3) ** 2
    observed /= len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    expected = sum(
        ((a - b) / 3) ** 2 * left_counts[a] / len(left) * right_counts[b] / len(right)
        for a in levels
        for b in levels
    )
    if math.isclose(expected, 0.0):
        return 1.0 if math.isclose(observed, 0.0) else 0.0
    return 1.0 - observed / expected


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _support_set(case: Mapping[str, Any], *, visual: bool = False) -> set[str]:
    field = "visual_evidence_ids" if visual else "supporting_evidence_ids"
    return {item for claim in case["claims"] for item in claim[field]}


def _adjudicated_value_equal(field: str, left: object, right: object) -> bool:
    if field == "expected_routes":
        if not isinstance(left, list) or not isinstance(right, list):
            raise GovernanceError("validated route fields must be lists")
        return set(left) == set(right)
    if field in {"sql_denotation", "answer_denotation"}:
        return _denotation_equal(left, right)
    return left == right


def _compare_normalized_annotations(
    cases_a: Sequence[Mapping[str, Any]],
    cases_b: Sequence[Mapping[str, Any]],
    *,
    benchmark_id: str,
    benchmark_version: str,
    assignment_id: str,
    submission_digests: object,
    batch_count: int,
) -> JsonObject:
    if len(cases_a) != len(cases_b) or not cases_a:
        raise GovernanceError("IAA requires aligned, non-empty annotation cases")
    disagreements: list[JsonObject] = []
    behaviors_a: list[str] = []
    behaviors_b: list[str] = []
    route_exact: list[float] = []
    route_jaccard: list[float] = []
    route_labels_a: dict[str, list[bool]] = {route: [] for route in sorted(ROUTES)}
    route_labels_b: dict[str, list[bool]] = {route: [] for route in sorted(ROUTES)}
    grades_a: list[int] = []
    grades_b: list[int] = []
    binary_a: list[bool] = []
    binary_b: list[bool] = []
    support_jaccards: list[float] = []
    visual_jaccards: list[float] = []
    sql_agreement: list[float] = []
    knowledge_agreement: list[float] = []
    knowledge_flags_a: list[bool] = []
    knowledge_flags_b: list[bool] = []
    exposure_a: list[object] = []
    exposure_b: list[object] = []
    case_exact: list[float] = []
    for case_a, case_b in zip(cases_a, cases_b, strict=True):
        case_id = case_a["case_id"]
        if case_b.get("case_id") != case_id:
            raise GovernanceError("IAA annotation cases are not in canonical order")
        behaviors_a.append(case_a["expected_behavior"])
        behaviors_b.append(case_b["expected_behavior"])
        routes_a = set(case_a["expected_routes"])
        routes_b = set(case_b["expected_routes"])
        route_exact.append(float(routes_a == routes_b))
        route_jaccard.append(_jaccard(routes_a, routes_b))
        for route in sorted(ROUTES):
            route_labels_a[route].append(route in routes_a)
            route_labels_b[route].append(route in routes_b)
        for evidence_id in case_a["relevance"]:
            grade_a = case_a["relevance"][evidence_id]
            grade_b = case_b["relevance"][evidence_id]
            grades_a.append(grade_a)
            grades_b.append(grade_b)
            binary_a.append(grade_a > 0)
            binary_b.append(grade_b > 0)
        support_jaccards.append(_jaccard(_support_set(case_a), _support_set(case_b)))
        visual_jaccards.append(
            _jaccard(_support_set(case_a, visual=True), _support_set(case_b, visual=True))
        )
        if "sql_denotation" in case_a or "sql_denotation" in case_b:
            sql_agreement.append(
                float(
                    "sql_denotation" in case_a
                    and "sql_denotation" in case_b
                    and _denotation_equal(case_a["sql_denotation"], case_b["sql_denotation"])
                )
            )
        is_knowledge_a = case_a.get("knowledge_probe") is True
        is_knowledge_b = case_b.get("knowledge_probe") is True
        knowledge_flags_a.append(is_knowledge_a)
        knowledge_flags_b.append(is_knowledge_b)
        exposure_a.append(case_a.get("exposure_class"))
        exposure_b.append(case_b.get("exposure_class"))
        if is_knowledge_a or is_knowledge_b:
            knowledge_agreement.append(
                float(
                    is_knowledge_a
                    and is_knowledge_b
                    and _denotation_equal(
                        case_a.get("answer_denotation"), case_b.get("answer_denotation")
                    )
                )
            )
        equal_case = True
        for field in ADJUDICATED_FIELDS:
            value_a = case_a.get(field)
            value_b = case_b.get(field)
            equal = _adjudicated_value_equal(field, value_a, value_b)
            if not equal:
                equal_case = False
                disagreements.append(
                    {
                        "case_id": case_id,
                        "field": field,
                        "annotator_a": value_a,
                        "annotator_b": value_b,
                    }
                )
        case_exact.append(float(equal_case))

    def mean(values: list[float]) -> float | None:
        return statistics.fmean(values) if values else None

    report: JsonObject = {
        "schema_version": 1,
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "assignment_id": assignment_id,
        "batch_count": batch_count,
        "submission_digests": copy.deepcopy(submission_digests),
        "annotator_tokens_redacted": True,
        "sample_counts": {
            "cases": len(cases_a),
            "evidence_judgments": len(grades_a),
            "sql_cases": len(sql_agreement),
            "knowledge_cases": len(knowledge_agreement),
            "disagreements": len(disagreements),
        },
        "agreement": {
            "case_exact_agreement": mean(case_exact),
            "behavior_observed_agreement": mean(
                [float(a == b) for a, b in zip(behaviors_a, behaviors_b, strict=True)]
            ),
            "behavior_cohen_kappa": _cohen_kappa(behaviors_a, behaviors_b),
            "route_set_exact_agreement": mean(route_exact),
            "route_set_jaccard_mean": mean(route_jaccard),
            "route_label_cohen_kappa": {
                route: _cohen_kappa(route_labels_a[route], route_labels_b[route])
                for route in sorted(ROUTES)
            },
            "relevance_quadratic_weighted_kappa": _weighted_kappa(grades_a, grades_b),
            "relevance_binary_cohen_kappa": _cohen_kappa(binary_a, binary_b),
            "claim_support_evidence_jaccard_mean": mean(support_jaccards),
            "visual_support_evidence_jaccard_mean": mean(visual_jaccards),
            "sql_denotation_exact_agreement": mean(sql_agreement),
            "knowledge_probe_observed_agreement": mean(
                [float(a == b) for a, b in zip(knowledge_flags_a, knowledge_flags_b, strict=True)]
            ),
            "knowledge_answer_denotation_exact_agreement": mean(knowledge_agreement),
            "exposure_class_observed_agreement": mean(
                [float(a == b) for a, b in zip(exposure_a, exposure_b, strict=True)]
            ),
        },
        "disagreements": disagreements,
    }
    return report


def _add_complete_adjudication_accounting(report: JsonObject) -> None:
    """Record the complete-case policy after every disagreement has been resolved."""

    sample_counts = report.get("sample_counts")
    disagreements = report.get("disagreements")
    if not isinstance(sample_counts, dict) or not isinstance(disagreements, list):
        raise GovernanceError("IAA accounting requires sample counts and disagreements")
    disagreement_count = len(disagreements)
    case_count = sample_counts.get("cases")
    evidence_count = sample_counts.get("evidence_judgments")
    if (
        isinstance(case_count, bool)
        or not isinstance(case_count, int)
        or case_count <= 0
        or isinstance(evidence_count, bool)
        or not isinstance(evidence_count, int)
        or evidence_count < 0
        or sample_counts.get("disagreements") != disagreement_count
    ):
        raise GovernanceError("IAA accounting has invalid annotation denominators")
    report["adjudication_accounting"] = {
        "eligible_disagreement_count": disagreement_count,
        "adjudicated_disagreement_count": disagreement_count,
        "unresolved_disagreement_count": 0,
        "adjudication_rate": 1.0 if disagreement_count else None,
    }
    report["exclusion_accounting"] = {
        "case_count_before_exclusions": case_count,
        "included_case_count": case_count,
        "excluded_case_count": 0,
        "evidence_judgment_count_before_exclusions": evidence_count,
        "included_evidence_judgment_count": evidence_count,
        "excluded_evidence_judgment_count": 0,
        "by_reason": {},
    }


def compare_annotations(
    packet: Mapping[str, Any],
    submission_a: Mapping[str, Any],
    submission_b: Mapping[str, Any],
) -> JsonObject:
    """Produce disagreement material and real IAA values before adjudication."""

    token_a, cases_a = validate_annotation_submission(packet, submission_a)
    token_b, cases_b = validate_annotation_submission(packet, submission_b)
    if token_a == token_b:
        raise GovernanceError("the two independent annotations require distinct blind tokens")
    return _compare_normalized_annotations(
        cases_a,
        cases_b,
        benchmark_id=str(packet["benchmark_id"]),
        benchmark_version=str(packet["benchmark_version"]),
        assignment_id=str(packet["assignment_id"]),
        submission_digests={
            "annotator_a": _sha256(_canonical_json(submission_a)),
            "annotator_b": _sha256(_canonical_json(submission_b)),
        },
        batch_count=1,
    )


def finalize_adjudication(
    packet: Mapping[str, Any],
    submission_a: Mapping[str, Any],
    submission_b: Mapping[str, Any],
    adjudication: Mapping[str, Any],
) -> tuple[JsonObject, JsonObject]:
    """Require a third blind token and an explicit decision for every disagreement."""

    token_a, cases_a = validate_annotation_submission(packet, submission_a)
    token_b, cases_b = validate_annotation_submission(packet, submission_b)
    comparison = compare_annotations(packet, submission_a, submission_b)
    if adjudication.get("schema_version") != 1:
        raise GovernanceError("adjudication schema_version must equal 1")
    for field in ("benchmark_id", "benchmark_version", "assignment_id"):
        if adjudication.get(field) != packet.get(field):
            raise GovernanceError(f"adjudication {field} does not match its packet")
    adjudicator = _non_empty(adjudication.get("adjudicator_token"), "adjudicator_token")
    if not ANNOTATOR_TOKEN.fullmatch(adjudicator) or adjudicator in {token_a, token_b}:
        raise GovernanceError("adjudicator must have a third distinct opaque token")
    _reject_identity_fields(adjudication, "adjudication")
    if adjudication.get("blindness_attestation") != {
        "annotator_identities_hidden": True,
        "conflicts_reviewed_against_source_evidence": True,
    }:
        raise GovernanceError("adjudicator blindness attestation is incomplete")
    decisions = adjudication.get("decisions")
    if not isinstance(decisions, list):
        raise GovernanceError("adjudication decisions must be a list")
    expected_keys = {(item["case_id"], item["field"]) for item in comparison["disagreements"]}
    actual_keys: set[tuple[str, str]] = set()
    for index, decision in enumerate(decisions):
        if not isinstance(decision, dict):
            raise GovernanceError(f"decisions[{index}] must be an object")
        key = (
            _non_empty(decision.get("case_id"), f"decisions[{index}].case_id"),
            _non_empty(decision.get("field"), f"decisions[{index}].field"),
        )
        if key in actual_keys:
            raise GovernanceError(f"duplicate adjudication decision: {key}")
        actual_keys.add(key)
        if decision.get("resolution") not in {"annotator_a", "annotator_b", "custom"}:
            raise GovernanceError(f"decisions[{index}].resolution is invalid")
        _non_empty(decision.get("rationale"), f"decisions[{index}].rationale")
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise GovernanceError(
            f"adjudication must resolve exactly every disagreement; "
            f"missing={missing}, extra={extra}"
        )
    final_submission = {
        "schema_version": 1,
        "benchmark_id": packet["benchmark_id"],
        "benchmark_version": packet["benchmark_version"],
        "assignment_id": packet["assignment_id"],
        "annotator_token": adjudicator,
        "blindness_attestation": {
            "worked_independently": True,
            "no_cross_annotator_contact": True,
            "used_only_packet_evidence": True,
        },
        "cases": adjudication.get("cases"),
    }
    _, final_cases = validate_annotation_submission(packet, final_submission)
    decision_by_key = {(item["case_id"], item["field"]): item for item in decisions}
    for final_case, case_a, case_b in zip(final_cases, cases_a, cases_b, strict=True):
        for field in ADJUDICATED_FIELDS:
            key = (final_case["case_id"], field)
            value_a = case_a.get(field)
            value_b = case_b.get(field)
            final_value = final_case.get(field)
            decision = decision_by_key.get(key)
            if decision is None:
                if not _adjudicated_value_equal(
                    field, final_value, value_a
                ) or not _adjudicated_value_equal(field, value_a, value_b):
                    raise GovernanceError(f"uncontested field changed during adjudication: {key}")
            elif decision["resolution"] == "annotator_a" and not _adjudicated_value_equal(
                field, final_value, value_a
            ):
                raise GovernanceError(f"adjudicated field does not use annotator_a value: {key}")
            elif decision["resolution"] == "annotator_b" and not _adjudicated_value_equal(
                field, final_value, value_b
            ):
                raise GovernanceError(f"adjudicated field does not use annotator_b value: {key}")
    _add_complete_adjudication_accounting(comparison)
    gold = {
        "schema_version": 1,
        "benchmark_id": packet["benchmark_id"],
        "benchmark_version": packet["benchmark_version"],
        "annotation_status": "adjudicated",
        "annotation_protocol": {
            "independent_annotators": 2,
            "adjudicators": 1,
            "blind": True,
            "iaa_report_sha256": _sha256(_canonical_json(comparison)),
        },
        "cases": final_cases,
    }
    validate_gold(gold)
    return gold, comparison


def merge_adjudicated_batches(
    batches: Sequence[Mapping[str, Any]],
) -> tuple[JsonObject, JsonObject]:
    """Validate independent batches and recompute one pooled pre-adjudication IAA report."""

    if not batches:
        raise GovernanceError("annotation batch evidence must be non-empty")
    benchmark_id: str | None = None
    benchmark_version: str | None = None
    assignments: set[tuple[str, str]] = set()
    case_ids: set[str] = set()
    records: list[tuple[int, str, JsonObject, JsonObject, JsonObject]] = []
    batch_digests: list[str] = []
    submission_digests: list[JsonObject] = []
    split_order = {"train": 0, "development": 1, "test": 2}
    for index, batch in enumerate(batches):
        if not isinstance(batch, dict):
            raise GovernanceError(f"annotation_batches[{index}] must be an object")
        required = {"packet", "annotation_a", "annotation_b", "adjudication"}
        if set(batch) != required:
            raise GovernanceError(
                f"annotation_batches[{index}] must define exactly {sorted(required)}"
            )
        packet = batch["packet"]
        annotation_a = batch["annotation_a"]
        annotation_b = batch["annotation_b"]
        adjudication = batch["adjudication"]
        if not all(
            isinstance(value, dict) for value in (packet, annotation_a, annotation_b, adjudication)
        ):
            raise GovernanceError(f"annotation_batches[{index}] artifacts must be objects")
        packet_id = _non_empty(packet.get("benchmark_id"), "packet.benchmark_id")
        packet_version = _non_empty(packet.get("benchmark_version"), "packet.benchmark_version")
        if benchmark_id is None:
            benchmark_id, benchmark_version = packet_id, packet_version
        elif (packet_id, packet_version) != (benchmark_id, benchmark_version):
            raise GovernanceError("annotation batches mix benchmark identities")
        split = _non_empty(packet.get("split"), "packet.split")
        assignment = _non_empty(packet.get("assignment_id"), "packet.assignment_id")
        assignment_key = (split, assignment)
        if assignment_key in assignments:
            raise GovernanceError(f"duplicate annotation assignment: {assignment_key}")
        assignments.add(assignment_key)

        final_gold, _ = finalize_adjudication(packet, annotation_a, annotation_b, adjudication)
        _, cases_a = validate_annotation_submission(packet, annotation_a)
        _, cases_b = validate_annotation_submission(packet, annotation_b)
        for case_a, case_b, final_case in zip(cases_a, cases_b, final_gold["cases"], strict=True):
            case_id = str(final_case["case_id"])
            if case_id in case_ids:
                raise GovernanceError(f"annotation batches repeat case_id: {case_id}")
            case_ids.add(case_id)
            records.append(
                (
                    split_order[split],
                    case_id,
                    copy.deepcopy(case_a),
                    copy.deepcopy(case_b),
                    copy.deepcopy(final_case),
                )
            )
        batch_digest = _sha256(_canonical_json(batch))
        batch_digests.append(batch_digest)
        submission_digests.append(
            {
                "assignment_id": assignment,
                "split": split,
                "batch_sha256": batch_digest,
                "annotator_a": _sha256(_canonical_json(annotation_a)),
                "annotator_b": _sha256(_canonical_json(annotation_b)),
            }
        )

    records.sort(key=lambda item: (item[0], item[1]))
    submission_digests.sort(
        key=lambda item: (split_order[str(item["split"])], str(item["assignment_id"]))
    )
    batch_digests = [str(item["batch_sha256"]) for item in submission_digests]
    cases_a = [item[2] for item in records]
    cases_b = [item[3] for item in records]
    final_cases = [item[4] for item in records]
    batches_digest = _sha256(_canonical_json(batch_digests))
    comparison = _compare_normalized_annotations(
        cases_a,
        cases_b,
        benchmark_id=str(benchmark_id),
        benchmark_version=str(benchmark_version),
        assignment_id=f"merged:{batches_digest.removeprefix('sha256:')}",
        submission_digests={"batches": submission_digests},
        batch_count=len(batches),
    )
    comparison["batch_digests"] = batch_digests
    _add_complete_adjudication_accounting(comparison)
    gold = {
        "schema_version": 1,
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "annotation_status": "adjudicated",
        "annotation_protocol": {
            "independent_annotators": 2,
            "adjudicators": 1,
            "blind": True,
            "batch_count": len(batches),
            "annotation_batches_sha256": batches_digest,
            "iaa_report_sha256": _sha256(_canonical_json(comparison)),
        },
        "cases": final_cases,
    }
    validate_gold(gold)
    return gold, comparison


def validate_registry_bundle(bundle_path: Path) -> JsonObject:
    """Resolve the immutable v1 component plus reviewed diversity additions."""

    bundle = load_json_object(bundle_path)
    if bundle.get("schema_version") != 1:
        raise GovernanceError("registry bundle schema_version must equal 1")
    benchmark_id = _non_empty(bundle.get("benchmark_id"), "benchmark_id")
    version = _non_empty(bundle.get("version"), "version")
    base_name = _non_empty(bundle.get("base_manifest"), "base_manifest")
    expansion_name = _non_empty(bundle.get("expansion_manifest"), "expansion_manifest")
    base = load_json_object((bundle_path.parent / base_name).resolve())
    expansion = load_json_object((bundle_path.parent / expansion_name).resolve())
    validate_event_manifest(base)
    if expansion.get("schema_version") != 1 or expansion.get("release_status") != "source_registry":
        raise GovernanceError("diversity expansion must be a schema-v1 source registry")
    if expansion.get("benchmark_id") != benchmark_id or expansion.get("version") != version:
        raise GovernanceError("diversity expansion identity/version does not match registry bundle")
    rebalance = bundle.get("rebalance")
    if not isinstance(rebalance, dict):
        raise GovernanceError("registry bundle requires explicit rebalance provenance")
    expected_rebalance_fields = {
        "parent_version",
        "immutable_v1_assignments_preserved",
        "immutable_v1_assignment_sha256",
        "minimum_test_event_count",
        "count_proof",
        "annotation_or_result_previously_frozen",
    }
    if set(rebalance) != expected_rebalance_fields:
        raise GovernanceError("rebalance provenance fields are incomplete or unknown")
    parent_version = _non_empty(rebalance.get("parent_version"), "rebalance.parent_version")
    if parent_version == version:
        raise GovernanceError("rebalance parent_version must differ from the current version")
    if rebalance.get("immutable_v1_assignments_preserved") is not True:
        raise GovernanceError("rebalance must preserve immutable v1 event assignments")
    if rebalance.get("annotation_or_result_previously_frozen") is not False:
        raise GovernanceError(
            "a source-registry rebalance cannot rewrite frozen annotations/results"
        )
    _non_empty(rebalance.get("count_proof"), "rebalance.count_proof")
    expected_base_assignment_digest = _non_empty(
        rebalance.get("immutable_v1_assignment_sha256"),
        "rebalance.immutable_v1_assignment_sha256",
    )
    base_assignments = sorted(
        ({"event_id": event["event_id"], "split": event["split"]} for event in base["events"]),
        key=lambda item: str(item["event_id"]),
    )
    if _sha256(_canonical_json(base_assignments)) != expected_base_assignment_digest:
        raise GovernanceError("immutable v1 assignment digest does not match base manifest")
    raw_events = expansion.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise GovernanceError("diversity expansion events must be non-empty")
    languages: set[str] = set()
    regions: set[str] = set()
    hazards: set[str] = set()
    exposure_counts: Counter[str] = Counter()
    condition_counts: Counter[str] = Counter()
    for index, event in enumerate(raw_events):
        label = f"expansion.events[{index}]"
        if not isinstance(event, dict):
            raise GovernanceError(f"{label} must be an object")
        event_languages = _string_list(
            event.get("languages"), f"{label}.languages", allow_empty=False
        )
        if any(not re.fullmatch(r"[a-z]{2}(?:-[A-Z]{2})?", item) for item in event_languages):
            raise GovernanceError(f"{label}.languages must use simple BCP-47 tags")
        region = event.get("geographic_region")
        exposure = event.get("exposure_class")
        condition = event.get("evidence_condition")
        if region not in GEOGRAPHIC_REGIONS:
            raise GovernanceError(f"{label}.geographic_region is invalid")
        if exposure not in EXPOSURE_CLASSES - {"private_custodian"}:
            raise GovernanceError(f"{label}.exposure_class is invalid for a public registry")
        if condition not in EVIDENCE_CONDITIONS:
            raise GovernanceError(f"{label}.evidence_condition is invalid")
        languages.update(event_languages)
        regions.add(str(region))
        hazards.add(_non_empty(event.get("hazard_type"), f"{label}.hazard_type"))
        exposure_counts[str(exposure)] += 1
        condition_counts[str(condition)] += 1
        for source_index, source in enumerate(event.get("sources", [])):
            if not isinstance(source, dict):
                raise GovernanceError(f"{label}.sources[{source_index}] must be an object")
            source_languages = _string_list(
                source.get("languages"),
                f"{label}.sources[{source_index}].languages",
                allow_empty=False,
            )
            if not set(source_languages) <= set(event_languages):
                raise GovernanceError(f"{label} source language is absent from event languages")
    required_hazards = {
        "flood",
        "wildfire",
        "drought",
        "landslide",
        "extreme_heat",
        "industrial_accident",
    }
    if not required_hazards <= hazards:
        omitted_hazards = sorted(required_hazards - hazards)
        raise GovernanceError(f"diversity expansion omits hazards: {omitted_hazards}")
    if len(regions) < 6 or len(languages) < 6:
        raise GovernanceError("diversity expansion requires >=6 regions and >=6 source languages")
    if exposure_counts["recent_public"] < 5:
        raise GovernanceError("diversity expansion requires at least five recent public holdouts")
    includes_conflicts = condition_counts["conflict_probe_pending"]
    includes_preliminary = condition_counts["preliminary_unvalidated"]
    if not (includes_conflicts and includes_preliminary):
        raise GovernanceError("expansion requires conflict and preliminary-evidence probes")

    merged = copy.deepcopy(base)
    merged["benchmark_id"] = benchmark_id
    merged["version"] = version
    merged["release_status"] = "source_registry"
    merged["events"] = [*base["events"], *raw_events]
    observed = Counter(str(event["split"]) for event in merged["events"])
    merged["split_counts"] = {split: observed[split] for split in ("development", "test", "train")}
    merged["required_systems"] = base["required_systems"]
    report = validate_event_manifest(merged)
    expected_counts = bundle.get("split_counts")
    if expected_counts != report["split_counts"]:
        raise GovernanceError("registry bundle split_counts do not match merged events")
    expansion_event_ids = {str(event["event_id"]) for event in raw_events}
    split_coverage: dict[str, JsonObject] = {}
    for split in ("train", "development", "test"):
        split_events = [event for event in merged["events"] if event["split"] == split]
        expansion_split_events = [
            event for event in split_events if str(event["event_id"]) in expansion_event_ids
        ]
        split_coverage[split] = {
            "event_count": len(split_events),
            "expansion_event_count": len(expansion_split_events),
            "hazards": sorted({str(event["hazard_type"]) for event in split_events}),
            "geographic_regions": sorted(
                {str(event["geographic_region"]) for event in expansion_split_events}
            ),
            "languages": sorted(
                {
                    language
                    for event in expansion_split_events
                    for language in _string_list(
                        event["languages"], f"event {event['event_id']}.languages"
                    )
                }
            ),
            "recent_public_event_count": sum(
                event["exposure_class"] == "recent_public" for event in expansion_split_events
            ),
        }

    coverage_policy = bundle.get("test_coverage_policy")
    if not isinstance(coverage_policy, dict):
        raise GovernanceError("registry bundle requires a test_coverage_policy")
    expected_policy_fields = {
        "required_hazards",
        "required_geographic_regions",
        "required_languages",
        "minimum_recent_public_events",
    }
    if set(coverage_policy) != expected_policy_fields:
        raise GovernanceError("test_coverage_policy fields are incomplete or unknown")
    required_test_hazards = set(
        _string_list(coverage_policy["required_hazards"], "required_hazards", allow_empty=False)
    )
    required_test_regions = set(
        _string_list(
            coverage_policy["required_geographic_regions"],
            "required_geographic_regions",
            allow_empty=False,
        )
    )
    required_test_languages = set(
        _string_list(coverage_policy["required_languages"], "required_languages", allow_empty=False)
    )
    minimum_recent = coverage_policy["minimum_recent_public_events"]
    if (
        not isinstance(minimum_recent, int)
        or isinstance(minimum_recent, bool)
        or minimum_recent < 0
    ):
        raise GovernanceError("minimum_recent_public_events must be a non-negative integer")
    test_coverage = split_coverage["test"]
    missing_hazards = required_test_hazards - set(test_coverage["hazards"])
    missing_regions = required_test_regions - set(test_coverage["geographic_regions"])
    missing_languages = required_test_languages - set(test_coverage["languages"])
    if missing_hazards or missing_regions or missing_languages:
        raise GovernanceError(
            "test coverage policy is unsatisfied: "
            f"hazards={sorted(missing_hazards)}, regions={sorted(missing_regions)}, "
            f"languages={sorted(missing_languages)}"
        )
    if test_coverage["recent_public_event_count"] < minimum_recent:
        raise GovernanceError("test split has too few recent-public events")
    minimum_test_count = rebalance.get("minimum_test_event_count")
    if (
        not isinstance(minimum_test_count, int)
        or isinstance(minimum_test_count, bool)
        or minimum_test_count < 1
    ):
        raise GovernanceError("rebalance.minimum_test_event_count must be a positive integer")
    if report["split_counts"]["test"] != minimum_test_count:
        raise GovernanceError("test split does not equal the preregistered feasible minimum")
    report.update(
        {
            "component_count": 2,
            "languages": sorted(languages),
            "geographic_regions": sorted(regions),
            "expansion_hazards": sorted(hazards),
            "exposure_counts": dict(sorted(exposure_counts.items())),
            "evidence_condition_counts": dict(sorted(condition_counts.items())),
            "split_coverage": split_coverage,
        }
    )
    plan_name = bundle.get("annotation_plan_expansion")
    if plan_name is not None:
        plan = load_json_object((bundle_path.parent / _non_empty(plan_name, "plan")).resolve())
        if plan.get("benchmark_id") != benchmark_id or plan.get("benchmark_version") != version:
            raise GovernanceError("annotation plan identity/version does not match registry bundle")
        base_plan = load_json_object(bundle_path.parent / "gold_cases.json")
        merged_plan = copy.deepcopy(base_plan)
        merged_plan["benchmark_id"] = benchmark_id
        merged_plan["benchmark_version"] = version
        if plan.get("annotation_status") != "pending_human_adjudication":
            raise GovernanceError("expansion annotation plan must remain pending")
        merged_plan["cases"] = [*base_plan["cases"], *plan.get("cases", [])]
        plan_report = validate_benchmark_bundle(merged, merged_plan)
        report["planned_case_count"] = plan_report["case_count"]
        report["planned_task_counts"] = plan_report["task_counts"]
    return report


def _validate_private_manifest(
    private_manifest: Mapping[str, Any],
    *,
    expected_benchmark_id: str | None = None,
    expected_benchmark_version: str | None = None,
) -> list[JsonObject]:
    if private_manifest.get("schema_version") != 1:
        raise GovernanceError("private manifest schema_version must equal 1")
    benchmark_id = _non_empty(private_manifest.get("benchmark_id"), "benchmark_id")
    benchmark_version = _non_empty(private_manifest.get("benchmark_version"), "benchmark_version")
    if expected_benchmark_id is not None and benchmark_id != expected_benchmark_id:
        raise GovernanceError("private manifest benchmark_id does not match frozen gold")
    if expected_benchmark_version is not None and benchmark_version != expected_benchmark_version:
        raise GovernanceError("private manifest benchmark_version does not match frozen gold")
    events = private_manifest.get("events")
    if not isinstance(events, list) or not events:
        raise GovernanceError("private manifest must contain events")
    event_ids: set[str] = set()
    nonces: set[str] = set()
    result: list[JsonObject] = []
    for index, event in enumerate(events):
        label = f"private.events[{index}]"
        if not isinstance(event, dict):
            raise GovernanceError(f"{label} must be an object")
        event_id = _non_empty(event.get("event_id"), f"{label}.event_id")
        if event_id in event_ids:
            raise GovernanceError(f"private manifest repeats event_id: {event_id}")
        event_ids.add(event_id)
        if event.get("exposure_class") != "private_custodian":
            raise GovernanceError(f"{label}.exposure_class must be private_custodian")
        source_lock = _non_empty(event.get("source_lock_sha256"), f"{label}.source_lock_sha256")
        if not DIGEST.fullmatch(source_lock) or source_lock == f"sha256:{'0' * 64}":
            raise GovernanceError(f"{label}.source_lock_sha256 is invalid or a placeholder")
        nonce = _non_empty(event.get("commitment_nonce"), f"{label}.commitment_nonce")
        if not PRIVATE_COMMITMENT_NONCE.fullmatch(nonce) or nonce in nonces:
            raise GovernanceError(f"{label}.commitment_nonce is invalid or duplicated")
        nonces.add(nonce)
        result.append(copy.deepcopy(event))
    return result


def create_private_commitment(private_manifest: Mapping[str, Any]) -> JsonObject:
    """Create salted opaque event commitments without exposing private event metadata."""

    events = _validate_private_manifest(private_manifest)
    benchmark_id = str(private_manifest["benchmark_id"])
    benchmark_version = str(private_manifest["benchmark_version"])
    event_commitments = sorted(
        _sha256(
            _canonical_json(
                {
                    "benchmark_id": benchmark_id,
                    "benchmark_version": benchmark_version,
                    "event": event,
                }
            )
        )
        for event in events
    )
    return {
        "schema_version": 1,
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "manifest_sha256": _sha256(_canonical_json(private_manifest)),
        "event_count": len(events),
        "event_commitments": event_commitments,
        "exposure_class": "private_custodian",
    }


def _verified_private_event_ids(
    commitments: Sequence[Mapping[str, Any]],
    private_manifests: Sequence[Mapping[str, Any]],
    *,
    benchmark_id: str,
    benchmark_version: str,
) -> set[str]:
    if len(commitments) != len(private_manifests):
        raise GovernanceError("every private commitment requires exactly one sealed manifest")
    expected = {str(commitment["manifest_sha256"]): commitment for commitment in commitments}
    event_ids: set[str] = set()
    seen_manifests: set[str] = set()
    for manifest in private_manifests:
        events = _validate_private_manifest(
            manifest,
            expected_benchmark_id=benchmark_id,
            expected_benchmark_version=benchmark_version,
        )
        commitment = create_private_commitment(manifest)
        digest = str(commitment["manifest_sha256"])
        if digest in seen_manifests or expected.get(digest) != commitment:
            raise GovernanceError("private manifest does not match its public commitment")
        seen_manifests.add(digest)
        for event in events:
            event_id = str(event["event_id"])
            if event_id in event_ids:
                raise GovernanceError(f"private manifests repeat event_id: {event_id}")
            event_ids.add(event_id)
    if seen_manifests != set(expected):
        raise GovernanceError("one or more public private-event commitments are unverified")
    return event_ids


def validate_private_holdout_commitments(
    value: Mapping[str, Any],
    *,
    expected_benchmark_id: str | None = None,
    expected_benchmark_version: str | None = None,
    private_manifests: Sequence[Mapping[str, Any]] | None = None,
) -> JsonObject:
    """Validate public commitments; only sealed-manifest correspondence opens the release gate."""

    if value.get("schema_version") != 1:
        raise GovernanceError("private holdout registry schema_version must equal 1")
    benchmark_id = _non_empty(value.get("benchmark_id"), "benchmark_id")
    benchmark_version = _non_empty(value.get("benchmark_version"), "benchmark_version")
    if expected_benchmark_id is not None and benchmark_id != expected_benchmark_id:
        raise GovernanceError("private holdout benchmark_id does not match frozen gold")
    if expected_benchmark_version is not None and benchmark_version != expected_benchmark_version:
        raise GovernanceError("private holdout benchmark_version does not match frozen gold")
    minimum = value.get("minimum_private_events")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise GovernanceError("minimum_private_events must be a positive integer")
    commitments = value.get("commitments")
    if not isinstance(commitments, list):
        raise GovernanceError("private holdout commitments must be a list")
    expected_status = (
        "blocked_pending_custodian_data"
        if not commitments
        else "committed_pending_custodian_verification"
    )
    if value.get("release_status") != expected_status:
        raise GovernanceError(f"private holdout release_status must equal {expected_status}")
    manifest_digests: set[str] = set()
    event_commitments: set[str] = set()
    event_total = 0
    normalized: list[Mapping[str, Any]] = []
    required = {
        "schema_version",
        "benchmark_id",
        "benchmark_version",
        "manifest_sha256",
        "event_count",
        "event_commitments",
        "exposure_class",
    }
    for index, commitment in enumerate(commitments):
        if not isinstance(commitment, dict) or set(commitment) != required:
            raise GovernanceError(f"commitments[{index}] has an invalid schema")
        if commitment.get("schema_version") != 1:
            raise GovernanceError("private commitment schema_version must equal 1")
        if (
            commitment.get("benchmark_id") != benchmark_id
            or commitment.get("benchmark_version") != benchmark_version
        ):
            raise GovernanceError("private commitment benchmark identity is invalid")
        digest = _non_empty(commitment.get("manifest_sha256"), "manifest_sha256")
        if not DIGEST.fullmatch(digest) or digest in manifest_digests:
            raise GovernanceError("private manifest commitment is invalid or duplicated")
        manifest_digests.add(digest)
        count = commitment.get("event_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise GovernanceError("private commitment event_count must be positive")
        opaque_events = commitment.get("event_commitments")
        if not isinstance(opaque_events, list) or len(opaque_events) != count:
            raise GovernanceError("private event commitments do not match event_count")
        for opaque in opaque_events:
            if not isinstance(opaque, str) or not DIGEST.fullmatch(opaque):
                raise GovernanceError("private event commitment is invalid")
            if opaque in event_commitments:
                raise GovernanceError("private event commitment is duplicated")
            event_commitments.add(opaque)
        if commitment.get("exposure_class") != "private_custodian":
            raise GovernanceError("private commitment exposure_class is invalid")
        event_total += count
        normalized.append(commitment)
    manifests_verified = private_manifests is not None
    if private_manifests is not None:
        _verified_private_event_ids(
            normalized,
            private_manifests,
            benchmark_id=benchmark_id,
            benchmark_version=benchmark_version,
        )
    return {
        "private_event_count": event_total,
        "minimum_private_events": minimum,
        "manifest_correspondence_verified": manifests_verified,
        "release_gate_satisfied": manifests_verified and event_total >= minimum,
    }


def _crypto() -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise GovernanceError(
            "cryptography is required for label escrow and public signatures"
        ) from exc
    return hashes, serialization, ed25519, padding, rsa, AESGCM, os.urandom


def escrow_test_gold(
    gold: Mapping[str, Any], recipient_public_key_pem: bytes
) -> tuple[JsonObject, JsonObject, JsonObject]:
    """Encrypt frozen test labels to a custodian RSA key and expose only a commitment."""

    cases = validate_gold(gold)
    if gold.get("annotation_status") != "frozen":
        raise GovernanceError("only frozen gold can enter test-label escrow")
    test_cases = [case for case in cases if case["split"] == "test"]
    public_cases = [case for case in cases if case["split"] != "test"]
    if not test_cases or not public_cases:
        raise GovernanceError("escrow requires both public train/development and sealed test cases")
    hashes, serialization, _, padding, rsa, AESGCM, random_bytes = _crypto()
    try:
        key = serialization.load_pem_public_key(recipient_public_key_pem)
    except ValueError as exc:
        raise GovernanceError("recipient public key is not valid PEM") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise GovernanceError("test escrow requires an RSA public key of at least 3072 bits")
    sealed_gold = {
        "schema_version": 1,
        "benchmark_id": gold["benchmark_id"],
        "benchmark_version": gold["benchmark_version"],
        "annotation_status": "frozen",
        "cases": test_cases,
    }
    plaintext = _canonical_json(sealed_gold)
    aes_key = random_bytes(32)
    nonce = random_bytes(12)
    aad = _canonical_json(
        {"benchmark_id": gold["benchmark_id"], "benchmark_version": gold["benchmark_version"]}
    )
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    wrapped = key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    public_der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    envelope = {
        "schema_version": 1,
        "algorithm": "RSA-OAEP-SHA256+A256GCM",
        "benchmark_id": gold["benchmark_id"],
        "benchmark_version": gold["benchmark_version"],
        "recipient_key_id": _sha256(public_der),
        "aad": base64.b64encode(aad).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    public_gold = {
        "schema_version": 1,
        "benchmark_id": gold["benchmark_id"],
        "benchmark_version": gold["benchmark_version"],
        "annotation_status": "public_train_development_only",
        "cases": public_cases,
    }
    commitment = {
        "schema_version": 1,
        "benchmark_id": gold["benchmark_id"],
        "benchmark_version": gold["benchmark_version"],
        "test_gold_sha256": _sha256(plaintext),
        "encrypted_envelope_sha256": _sha256(_canonical_json(envelope)),
        "public_gold_sha256": _sha256(_canonical_json(public_gold)),
        "recipient_key_id": _sha256(public_der),
        "sealed_case_count": len(test_cases),
        "test_case_ids_disclosed": False,
    }
    return public_gold, envelope, commitment


def open_test_gold(
    envelope: Mapping[str, Any],
    recipient_private_key_pem: bytes,
    commitment: Mapping[str, Any],
) -> JsonObject:
    """Custodian-only authenticated decryption bound to the published freeze commitment."""

    if (
        envelope.get("schema_version") != 1
        or envelope.get("algorithm") != "RSA-OAEP-SHA256+A256GCM"
    ):
        raise GovernanceError("unsupported escrow algorithm")
    if commitment.get("schema_version") != 1:
        raise GovernanceError("test-gold commitment schema_version must equal 1")
    if commitment.get("encrypted_envelope_sha256") != _sha256(_canonical_json(envelope)):
        raise GovernanceError("encrypted test-gold envelope does not match its commitment")
    for field in ("benchmark_id", "benchmark_version", "recipient_key_id"):
        if commitment.get(field) != envelope.get(field):
            raise GovernanceError(f"test-gold commitment and envelope disagree on {field}")
    if commitment.get("test_case_ids_disclosed") is not False:
        raise GovernanceError("test-gold commitment must not disclose test case IDs")
    hashes, serialization, _, padding, rsa, AESGCM, _ = _crypto()
    try:
        key = serialization.load_pem_private_key(recipient_private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise GovernanceError("recipient private key is not valid unencrypted PEM") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GovernanceError("recipient key is not RSA")
    if key.key_size < 3072:
        raise GovernanceError("test escrow requires an RSA private key of at least 3072 bits")
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if envelope.get("recipient_key_id") != _sha256(public_der):
        raise GovernanceError("recipient private key does not match the committed public key")
    try:
        aad = base64.b64decode(_non_empty(envelope.get("aad"), "aad"), validate=True)
        aad_value = json.loads(aad)
        expected_aad = {
            "benchmark_id": envelope["benchmark_id"],
            "benchmark_version": envelope["benchmark_version"],
        }
        if aad_value != expected_aad:
            raise GovernanceError("test-gold authenticated metadata does not match the envelope")
        wrapped = base64.b64decode(
            _non_empty(envelope.get("wrapped_key"), "wrapped_key"), validate=True
        )
        nonce = base64.b64decode(_non_empty(envelope.get("nonce"), "nonce"), validate=True)
        ciphertext = base64.b64decode(
            _non_empty(envelope.get("ciphertext"), "ciphertext"), validate=True
        )
        aes_key = key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        value = json.loads(plaintext)
    except Exception as exc:  # cryptography exposes several backend-specific failure classes
        raise GovernanceError("test-label escrow authentication or decryption failed") from exc
    if not isinstance(value, dict):
        raise GovernanceError("decrypted test gold is not an object")
    cases = validate_gold(value)
    if value.get("benchmark_id") != envelope.get("benchmark_id") or value.get(
        "benchmark_version"
    ) != envelope.get("benchmark_version"):
        raise GovernanceError("decrypted test gold does not match the envelope benchmark")
    if any(case["split"] != "test" for case in cases):
        raise GovernanceError("decrypted escrow contains a non-test case")
    if commitment.get("test_gold_sha256") != _sha256(_canonical_json(value)):
        raise GovernanceError("decrypted test gold does not match its freeze commitment")
    if commitment.get("sealed_case_count") != len(cases):
        raise GovernanceError("decrypted test-gold case count does not match its commitment")
    commitment_strings = {value for value in commitment.values() if isinstance(value, str)}
    if any(case["case_id"] in commitment_strings for case in cases):
        raise GovernanceError("test-gold commitment leaks a test case ID")
    return value


def sign_public_report(report_payload: bytes, private_key_pem: bytes) -> JsonObject:
    """Sign the exact published report using an externally held Ed25519 key."""

    _, serialization, ed25519, _, _, _, _ = _crypto()
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise GovernanceError("signing key is not valid unencrypted PEM") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise GovernanceError("public benchmark signatures require an Ed25519 private key")
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "report_sha256": _sha256(report_payload),
        "key_id": _sha256(public),
        "signature": base64.b64encode(key.sign(report_payload)).decode("ascii"),
    }


def verify_public_report(
    report_payload: bytes, signature: Mapping[str, Any], public_key_pem: bytes
) -> JsonObject:
    """Verify report bytes without sharing any private or symmetric secret."""

    if signature.get("schema_version") != 1 or signature.get("algorithm") != "Ed25519":
        raise GovernanceError("signature envelope is not supported")
    _, serialization, ed25519, _, _, _, _ = _crypto()
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except ValueError as exc:
        raise GovernanceError("verification key is not valid PEM") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise GovernanceError("verification key must be Ed25519")
    public = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if signature.get("key_id") != _sha256(public):
        raise GovernanceError("signature key_id does not match the public key")
    if signature.get("report_sha256") != _sha256(report_payload):
        raise GovernanceError("published report digest does not match the signature envelope")
    try:
        encoded = base64.b64decode(
            _non_empty(signature.get("signature"), "signature"), validate=True
        )
        key.verify(encoded, report_payload)
    except Exception as exc:
        raise GovernanceError("public report signature verification failed") from exc
    return {
        "verified": True,
        "algorithm": "Ed25519",
        "key_id": signature["key_id"],
        "report_sha256": signature["report_sha256"],
    }


def bootstrap_event_confidence_intervals(
    per_event: Mapping[str, Mapping[str, float | int | None]],
    *,
    samples: int = 10_000,
    seed: int = 24_051,
) -> JsonObject:
    """Compatibility wrapper around the shared statistical implementation."""

    try:
        return event_bootstrap_confidence_intervals(per_event, samples=samples, seed=seed)
    except ValueError as exc:
        raise GovernanceError(str(exc)) from exc


def validate_equal_settings_matrix(value: Mapping[str, Any]) -> JsonObject:
    """Fail comparison plans where an ablation changes more than its named component."""

    if value.get("schema_version") != 1:
        raise GovernanceError("experiment matrix schema_version must equal 1")
    if value.get("template_only") is not False:
        raise GovernanceError("template experiment matrices are not executable release artifacts")
    shared = value.get("shared_settings")
    if not isinstance(shared, dict):
        raise GovernanceError("experiment matrix shared_settings must be an object")
    required_shared = {
        "corpus_lock_sha256",
        "model_bundle_sha256",
        "hardware_class",
        "provider_region",
        "concurrency",
        "cache_policy",
        "warmup_queries",
        "repetitions",
        "price_sheet_sha256",
        "measurement_boundary",
    }
    if set(shared) != required_shared:
        raise GovernanceError(f"shared_settings must define exactly {sorted(required_shared)}")
    for digest_field in ("corpus_lock_sha256", "model_bundle_sha256", "price_sheet_sha256"):
        digest = shared[digest_field]
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise GovernanceError(f"shared_settings.{digest_field} must be a canonical digest")
        if digest == f"sha256:{'0' * 64}":
            raise GovernanceError(f"shared_settings.{digest_field} is still a placeholder")
    for count_field in ("concurrency", "warmup_queries", "repetitions"):
        value_count = shared[count_field]
        if isinstance(value_count, bool) or not isinstance(value_count, int) or value_count < 1:
            raise GovernanceError(f"shared_settings.{count_field} must be positive")
    systems = value.get("systems")
    if not isinstance(systems, list):
        raise GovernanceError("experiment matrix systems must be a list")
    ids = [item.get("system_id") for item in systems if isinstance(item, dict)]
    if ids != list(REQUIRED_SYSTEMS):
        raise GovernanceError(f"systems must be ordered as {list(REQUIRED_SYSTEMS)}")
    for index, item in enumerate(systems):
        if not isinstance(item, dict) or set(item) != {"system_id", "configuration"}:
            raise GovernanceError(
                f"systems[{index}] must define exactly system_id and configuration"
            )
        system_id = item["system_id"]
        if item["configuration"] != SYSTEM_CONFIGURATIONS[system_id]:
            raise GovernanceError(
                f"systems[{index}].configuration does not match the frozen {system_id} contract"
            )
    for field in ("hardware_class", "provider_region"):
        setting = shared[field]
        if (
            not isinstance(setting, str)
            or not setting.strip()
            or setting.startswith("REPLACE_WITH_")
        ):
            raise GovernanceError(f"shared_settings.{field} is still a placeholder")
    settings_digest = _sha256(_canonical_json(shared))
    return {
        "valid": True,
        "system_count": len(systems),
        "shared_settings_sha256": settings_digest,
        "systems": ids,
    }


def public_iaa_summary(iaa_report: Mapping[str, Any]) -> JsonObject:
    """Remove disagreement labels while retaining denominators and agreement statistics."""

    if iaa_report.get("schema_version") != 1:
        raise GovernanceError("IAA report schema_version must equal 1")
    sample_counts = iaa_report.get("sample_counts")
    agreement = iaa_report.get("agreement")
    disagreements = iaa_report.get("disagreements")
    if not isinstance(sample_counts, dict) or not isinstance(agreement, dict):
        raise GovernanceError("IAA report must contain sample_counts and agreement objects")
    if not isinstance(disagreements, list):
        raise GovernanceError("IAA report disagreements must be a list")
    if iaa_report.get("annotator_tokens_redacted") is not True:
        raise GovernanceError("IAA report must redact annotator tokens")
    disagreement_count = len(disagreements)
    if sample_counts.get("disagreements") != disagreement_count:
        raise GovernanceError("IAA disagreement denominator does not match its records")
    case_count = sample_counts.get("cases")
    evidence_count = sample_counts.get("evidence_judgments")
    expected_adjudication: JsonObject = {
        "eligible_disagreement_count": disagreement_count,
        "adjudicated_disagreement_count": disagreement_count,
        "unresolved_disagreement_count": 0,
        "adjudication_rate": 1.0 if disagreement_count else None,
    }
    expected_exclusions: JsonObject = {
        "case_count_before_exclusions": case_count,
        "included_case_count": case_count,
        "excluded_case_count": 0,
        "evidence_judgment_count_before_exclusions": evidence_count,
        "included_evidence_judgment_count": evidence_count,
        "excluded_evidence_judgment_count": 0,
        "by_reason": {},
    }
    if iaa_report.get("adjudication_accounting") != expected_adjudication:
        raise GovernanceError("IAA report lacks complete adjudication accounting")
    if iaa_report.get("exclusion_accounting") != expected_exclusions:
        raise GovernanceError("IAA report lacks complete exclusion accounting")
    return {
        "schema_version": 1,
        "benchmark_id": iaa_report.get("benchmark_id"),
        "benchmark_version": iaa_report.get("benchmark_version"),
        "sample_counts": copy.deepcopy(sample_counts),
        "agreement": copy.deepcopy(agreement),
        "adjudicated_disagreement_count": disagreement_count,
        "adjudication_accounting": copy.deepcopy(expected_adjudication),
        "exclusion_accounting": copy.deepcopy(expected_exclusions),
        "annotator_tokens_redacted": True,
        "label_values_redacted": True,
    }


def _json_artifact(payload: bytes, label: str) -> JsonObject:
    if not 0 < len(payload) <= MAX_GOVERNANCE_ARTIFACT_BYTES:
        raise GovernanceError(f"{label} must contain bounded, non-empty bytes")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise GovernanceError(f"{label} must contain a JSON object")
    return value


def _release_event_map(
    value: Mapping[str, Any], label: str, *, require_source_lock: bool
) -> dict[str, JsonObject]:
    events = value.get("events")
    if not isinstance(events, list) or not events:
        raise GovernanceError(f"{label}.events must be a non-empty list")
    result: dict[str, JsonObject] = {}
    for index, event in enumerate(events):
        event_label = f"{label}.events[{index}]"
        if not isinstance(event, dict):
            raise GovernanceError(f"{event_label} must be an object")
        event_id = _non_empty(event.get("event_id"), f"{event_label}.event_id")
        if event_id in result:
            raise GovernanceError(f"{label} repeats event_id: {event_id}")
        split = event.get("split")
        if split not in {"train", "development", "test"}:
            raise GovernanceError(f"{event_label}.split is invalid")
        exposure = event.get("exposure_class")
        if exposure is not None and exposure not in EXPOSURE_CLASSES:
            raise GovernanceError(f"{event_label}.exposure_class is invalid")
        if require_source_lock:
            source_lock = event.get("source_lock_sha256")
            if (
                not isinstance(source_lock, str)
                or not DIGEST.fullmatch(source_lock)
                or source_lock == f"sha256:{'0' * 64}"
            ):
                raise GovernanceError(f"{event_label}.source_lock_sha256 is invalid")
        result[event_id] = copy.deepcopy(event)
    return result


def _validate_release_registry_and_corpus(
    *,
    frozen_gold: Mapping[str, Any],
    registry_payload: bytes,
    corpus_lock_payload: bytes,
    private_manifests: Sequence[Mapping[str, Any]],
) -> JsonObject:
    benchmark_id = str(frozen_gold.get("benchmark_id"))
    benchmark_version = str(frozen_gold.get("benchmark_version"))
    registry = _json_artifact(registry_payload, "frozen registry")
    corpus_lock = _json_artifact(corpus_lock_payload, "corpus lock")
    for label, artifact in (("frozen registry", registry), ("corpus lock", corpus_lock)):
        if artifact.get("schema_version") != 1 or artifact.get("release_status") != "frozen":
            raise GovernanceError(f"{label} must be a schema-v1 frozen artifact")
        if (
            artifact.get("benchmark_id") != benchmark_id
            or artifact.get("benchmark_version") != benchmark_version
        ):
            raise GovernanceError(f"{label} benchmark identity does not match frozen gold")
    registry_digest = _sha256(registry_payload)
    if corpus_lock.get("registry_sha256") != registry_digest:
        raise GovernanceError("corpus lock is not bound to the exact frozen registry bytes")
    registry_events = _release_event_map(registry, "registry", require_source_lock=False)
    corpus_events = _release_event_map(corpus_lock, "corpus_lock", require_source_lock=True)
    if set(registry_events) != set(corpus_events):
        raise GovernanceError("frozen registry and corpus lock cover different events")

    case_events: dict[str, tuple[str, object]] = {}
    cases = validate_gold(frozen_gold)
    for case in cases:
        event_id = str(case["event_id"])
        event_value = (str(case["split"]), case.get("exposure_class"))
        prior = case_events.setdefault(event_id, event_value)
        if prior != event_value:
            raise GovernanceError(f"frozen cases disagree on event metadata: {event_id}")
    if set(case_events) != set(registry_events):
        raise GovernanceError("frozen registry event coverage does not match frozen gold")
    for event_id, (split, exposure) in case_events.items():
        registry_event = registry_events[event_id]
        corpus_event = corpus_events[event_id]
        if registry_event.get("split") != split or corpus_event.get("split") != split:
            raise GovernanceError(f"frozen event split mismatch: {event_id}")
        if exposure is not None and (
            registry_event.get("exposure_class") != exposure
            or corpus_event.get("exposure_class") != exposure
        ):
            raise GovernanceError(f"frozen event exposure mismatch: {event_id}")

    private_source_locks: dict[str, str] = {}
    for manifest in private_manifests:
        for event in _validate_private_manifest(
            manifest,
            expected_benchmark_id=benchmark_id,
            expected_benchmark_version=benchmark_version,
        ):
            event_id = str(event["event_id"])
            if event_id in private_source_locks:
                raise GovernanceError(f"private manifests repeat event_id: {event_id}")
            private_source_locks[event_id] = str(event["source_lock_sha256"])
    for event_id, source_lock in private_source_locks.items():
        private_corpus_event = corpus_events.get(event_id)
        if (
            private_corpus_event is None
            or private_corpus_event.get("source_lock_sha256") != source_lock
        ):
            raise GovernanceError(f"private source lock is not in the frozen corpus: {event_id}")
    return {
        "registry_sha256": registry_digest,
        "corpus_lock_sha256": _sha256(corpus_lock_payload),
        "event_count": len(registry_events),
    }


def _validate_frozen_gold_and_iaa(
    frozen_gold: Mapping[str, Any],
    iaa_report: Mapping[str, Any],
    annotation_batches: Sequence[Mapping[str, Any]],
) -> tuple[list[JsonObject], JsonObject]:
    cases = validate_gold(frozen_gold)
    if frozen_gold.get("annotation_status") != "frozen":
        raise GovernanceError("publication requires frozen, not merely adjudicated, gold")
    protocol = frozen_gold.get("annotation_protocol")
    if not isinstance(protocol, dict):
        raise GovernanceError("frozen gold is missing its annotation protocol")
    required_protocol = {
        "independent_annotators": 2,
        "adjudicators": 1,
        "blind": True,
    }
    if any(protocol.get(field) != expected for field, expected in required_protocol.items()):
        raise GovernanceError(
            "frozen gold does not attest two blind annotators and one adjudicator"
        )
    recomputed_gold, recomputed_iaa = merge_adjudicated_batches(annotation_batches)
    if _canonical_json(recomputed_iaa) != _canonical_json(iaa_report):
        raise GovernanceError("IAA report does not match recomputed blind annotations")
    if (
        recomputed_gold.get("benchmark_id") != frozen_gold.get("benchmark_id")
        or recomputed_gold.get("benchmark_version") != frozen_gold.get("benchmark_version")
        or _canonical_json(recomputed_gold.get("cases"))
        != _canonical_json(frozen_gold.get("cases"))
    ):
        raise GovernanceError("frozen gold does not match recomputed adjudicated batches")
    for field in ("batch_count", "annotation_batches_sha256"):
        if protocol.get(field) != recomputed_gold["annotation_protocol"].get(field):
            raise GovernanceError(f"frozen gold annotation protocol has stale {field}")
    iaa_digest = _sha256(_canonical_json(iaa_report))
    if protocol.get("iaa_report_sha256") != iaa_digest:
        raise GovernanceError(
            "frozen gold is not bound to the supplied pre-adjudication IAA report"
        )
    if iaa_report.get("benchmark_id") != frozen_gold.get("benchmark_id") or iaa_report.get(
        "benchmark_version"
    ) != frozen_gold.get("benchmark_version"):
        raise GovernanceError("IAA report benchmark identity does not match frozen gold")
    summary = public_iaa_summary(iaa_report)
    counts = summary["sample_counts"]
    if not isinstance(counts, dict) or counts.get("cases") != len(cases):
        raise GovernanceError("IAA report must account for every frozen benchmark case")
    return cases, summary


def _validate_test_freeze_artifacts(
    frozen_gold: Mapping[str, Any],
    envelope: Mapping[str, Any],
    commitment: Mapping[str, Any],
) -> JsonObject:
    cases = validate_gold(frozen_gold)
    test_cases = [case for case in cases if case["split"] == "test"]
    public_cases = [case for case in cases if case["split"] != "test"]
    if frozen_gold.get("annotation_status") != "frozen" or not test_cases or not public_cases:
        raise GovernanceError("test freeze requires frozen gold with public and test cases")
    if (
        envelope.get("schema_version") != 1
        or envelope.get("algorithm") != "RSA-OAEP-SHA256+A256GCM"
    ):
        raise GovernanceError("test freeze envelope is invalid")
    if commitment.get("schema_version") != 1:
        raise GovernanceError("test freeze commitment schema_version must equal 1")
    for field in ("benchmark_id", "benchmark_version", "recipient_key_id"):
        if commitment.get(field) != envelope.get(field):
            raise GovernanceError(f"test freeze artifacts disagree on {field}")
    if commitment.get("benchmark_id") != frozen_gold.get("benchmark_id") or commitment.get(
        "benchmark_version"
    ) != frozen_gold.get("benchmark_version"):
        raise GovernanceError("test freeze artifacts do not match frozen gold")
    sealed_gold = {
        "schema_version": 1,
        "benchmark_id": frozen_gold["benchmark_id"],
        "benchmark_version": frozen_gold["benchmark_version"],
        "annotation_status": "frozen",
        "cases": test_cases,
    }
    public_gold = {
        "schema_version": 1,
        "benchmark_id": frozen_gold["benchmark_id"],
        "benchmark_version": frozen_gold["benchmark_version"],
        "annotation_status": "public_train_development_only",
        "cases": public_cases,
    }
    expected = {
        "test_gold_sha256": _sha256(_canonical_json(sealed_gold)),
        "encrypted_envelope_sha256": _sha256(_canonical_json(envelope)),
        "public_gold_sha256": _sha256(_canonical_json(public_gold)),
        "sealed_case_count": len(test_cases),
        "test_case_ids_disclosed": False,
    }
    if any(commitment.get(field) != value for field, value in expected.items()):
        raise GovernanceError("test freeze commitment does not bind the supplied frozen artifacts")
    commitment_strings = {value for value in commitment.values() if isinstance(value, str)}
    if any(case["case_id"] in commitment_strings for case in test_cases):
        raise GovernanceError("test freeze commitment leaks a test case ID")
    return {
        "sealed_case_count": len(test_cases),
        "recipient_key_id": commitment["recipient_key_id"],
    }


def _validated_bootstrap(
    value: object,
    *,
    expected_events: int,
    expected_samples: int,
    paired: bool,
    required_metrics: frozenset[str] | None = None,
    expected_values: Mapping[str, tuple[float, int]] | None = None,
) -> JsonObject:
    if not isinstance(value, dict):
        raise GovernanceError("publication requires a bootstrap confidence-interval object")
    method = (
        "paired_event_cluster_percentile_bootstrap"
        if paired
        else "event_cluster_percentile_bootstrap"
    )
    intervals = value.get("intervals")
    if (
        value.get("method") != method
        or value.get("samples") != expected_samples
        or value.get("event_count") != expected_events
        or not isinstance(intervals, dict)
    ):
        raise GovernanceError("bootstrap confidence intervals do not match the frozen protocol")
    if required_metrics is not None:
        if not required_metrics <= set(intervals):
            raise GovernanceError("bootstrap confidence intervals omit required per-event metrics")
        count_field = "paired_events" if paired else "contributing_events"
        estimate_field = "estimate_event_macro_delta" if paired else "estimate_event_macro_mean"
        for metric in required_metrics:
            interval = intervals[metric]
            if not isinstance(interval, dict):
                raise GovernanceError("bootstrap confidence interval is not scorable")
            numbers = [
                interval.get(estimate_field),
                interval.get("ci95_low"),
                interval.get("ci95_high"),
            ]
            if any(
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or not math.isfinite(float(number))
                for number in numbers
            ):
                raise GovernanceError("bootstrap confidence interval is not scorable")
            low = interval["ci95_low"]
            high = interval["ci95_high"]
            if (
                not isinstance(low, (int, float))
                or not isinstance(high, (int, float))
                or float(low) > float(high)
                or isinstance(interval.get(count_field), bool)
                or not isinstance(interval.get(count_field), int)
                or not MIN_PUBLIC_METRIC_EVENTS <= interval[count_field] <= expected_events
            ):
                raise GovernanceError("bootstrap confidence interval is not scorable")
            if expected_values is not None:
                expected_estimate, expected_count = expected_values[metric]
                estimate = interval[estimate_field]
                if (
                    not isinstance(estimate, (int, float))
                    or not math.isclose(
                        float(estimate), expected_estimate, rel_tol=0.0, abs_tol=1e-6
                    )
                    or interval[count_field] != expected_count
                ):
                    raise GovernanceError(
                        "bootstrap confidence interval disagrees with per-event results"
                    )
    return value


def _validate_public_score_report(
    report: object,
    *,
    system_id: str,
    expected_case_count: int,
    expected_event_ids: set[str],
    shared_settings: Mapping[str, Any],
    bootstrap_samples: int,
    expected_sample_counts: Mapping[str, int],
    expected_visual_claim_count: int,
    expected_visual_region_count: int,
    expected_context: str = "retrieved",
) -> JsonObject:
    if not isinstance(report, dict):
        raise GovernanceError(f"score report for {system_id} must be an object")
    if report.get("system_id") != system_id or report.get("split") != "test":
        raise GovernanceError(f"score report identity is invalid for {system_id}")
    system = report.get("system")
    if not isinstance(system, dict) or system.get("system_id") != system_id:
        raise GovernanceError(f"score report for {system_id} lacks bound system metadata")
    artifact_id = system.get("artifact_id")
    if (
        not isinstance(artifact_id, str)
        or not DIGEST.fullmatch(artifact_id)
        or artifact_id == f"sha256:{'0' * 64}"
    ):
        raise GovernanceError(f"score report for {system_id} has no immutable artifact ID")
    if system.get("configuration") != SYSTEM_CONFIGURATIONS[system_id]:
        raise GovernanceError(f"score report for {system_id} changes its frozen ablation")
    if report.get("case_count") != expected_case_count:
        raise GovernanceError(f"score report for {system_id} omits frozen test cases")
    if report.get("experimental_control") != shared_settings:
        raise GovernanceError(f"score report for {system_id} changes experimental controls")
    condition = report.get("evaluation_condition")
    if not isinstance(condition, dict) or condition.get("context_access") != expected_context:
        raise GovernanceError(
            f"score report for {system_id} does not use {expected_context} context access"
        )
    cost_accounting = report.get("cost_accounting")
    if (
        not isinstance(cost_accounting, dict)
        or cost_accounting.get("accounting_complete") is not True
        or cost_accounting.get("price_sheet_sha256") != shared_settings["price_sheet_sha256"]
    ):
        raise GovernanceError(f"score report for {system_id} has incomplete cost accounting")
    measurement = report.get("measurement_binding")
    if (
        not isinstance(measurement, dict)
        or measurement.get("collector") != "crisisweave-custodian-harness/1"
        or not isinstance(measurement.get("trace_sha256"), str)
        or not DIGEST.fullmatch(measurement["trace_sha256"])
        or measurement["trace_sha256"] == f"sha256:{'0' * 64}"
    ):
        raise GovernanceError(f"score report for {system_id} lacks a bound custodian trace")
    per_event = report.get("per_event")
    if not isinstance(per_event, dict) or set(per_event) != expected_event_ids:
        raise GovernanceError(f"score report for {system_id} omits per-event results")
    if (
        sum(int(item.get("case_count", 0)) for item in per_event.values() if isinstance(item, dict))
        != expected_case_count
    ):
        raise GovernanceError(f"score report for {system_id} has invalid per-event denominators")
    metrics = report.get("metrics")
    required_metrics = {
        "recall@5",
        "recall@10",
        "recall@30",
        "ndcg@5",
        "ndcg@10",
        "ndcg@30",
        "mrr",
        "routing_accuracy",
        "sql_answer_accuracy",
        "citation_precision",
        "citation_coverage",
        "visual_groundedness",
        "visual_groundedness_precision",
        "visual_groundedness_coverage",
        "region_visual_entailment",
        "region_visual_entailment_precision",
        "region_visual_entailment_coverage",
        "abstention_accuracy",
        "prompt_injection_success_rate",
        "exact_answer_accuracy",
        "cost_usd_total",
        "cost_usd_mean",
        "latency_ms_mean",
        "latency_ms_p50",
        "latency_ms_p95",
        "latency_ms_p99",
    }
    if not isinstance(metrics, dict) or not required_metrics <= set(metrics):
        raise GovernanceError(f"score report for {system_id} omits required metrics")
    for event_id, event_report in per_event.items():
        if not isinstance(event_report, dict):
            raise GovernanceError(f"score report for {system_id} has invalid per-event results")
        event_case_count = event_report.get("case_count")
        event_metrics = event_report.get("metrics")
        if (
            isinstance(event_case_count, bool)
            or not isinstance(event_case_count, int)
            or event_case_count < 1
            or not isinstance(event_metrics, dict)
            or not set(event_metrics) >= PUBLIC_EVENT_METRICS
        ):
            raise GovernanceError(f"score report for {system_id} has invalid per-event results")
        for metric_name in PUBLIC_EVENT_METRICS:
            value = event_metrics[metric_name]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or (metric_name in PUBLIC_UNBOUNDED_EVENT_METRICS and float(value) <= 0)
                or (
                    metric_name not in PUBLIC_UNBOUNDED_EVENT_METRICS and not 0 <= float(value) <= 1
                )
            ):
                raise GovernanceError(
                    f"score report for {system_id} has invalid per-event metric: "
                    f"{event_id}/{metric_name}"
                )
    sample_counts = report.get("sample_counts")
    region_grounding = report.get("region_grounding")
    if not isinstance(sample_counts, dict) or not isinstance(region_grounding, dict):
        raise GovernanceError(f"score report for {system_id} omits region denominators")
    if any(
        isinstance(sample_counts.get(name), bool) or sample_counts.get(name) != expected
        for name, expected in expected_sample_counts.items()
    ):
        raise GovernanceError(f"score report for {system_id} has invalid sample denominators")
    visual_claim_count = sample_counts.get("visual_claims")
    gold_region_count = sample_counts.get("visual_regions")
    predicted_region_count = region_grounding.get("predicted_regions")
    matched_region_count = region_grounding.get("matched_regions")
    if (
        isinstance(visual_claim_count, bool)
        or not isinstance(visual_claim_count, int)
        or visual_claim_count != expected_visual_claim_count
        or isinstance(gold_region_count, bool)
        or not isinstance(gold_region_count, int)
        or gold_region_count != expected_visual_region_count
        or region_grounding.get("gold_regions") != gold_region_count
        or region_grounding.get("iou_threshold") != 0.5
        or isinstance(predicted_region_count, bool)
        or not isinstance(predicted_region_count, int)
        or predicted_region_count < 0
        or isinstance(matched_region_count, bool)
        or not isinstance(matched_region_count, int)
        or not 0 <= matched_region_count <= min(gold_region_count, predicted_region_count)
    ):
        raise GovernanceError(f"score report for {system_id} has invalid region denominators")
    bounded_quality_metrics = required_metrics - {
        "cost_usd_total",
        "cost_usd_mean",
        "latency_ms_mean",
        "latency_ms_p50",
        "latency_ms_p95",
        "latency_ms_p99",
    }
    for metric_name in bounded_quality_metrics:
        value = metrics.get(metric_name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0 <= float(value) <= 1
        ):
            detail = (
                "no scorable region metric"
                if "visual" in metric_name or "groundedness" in metric_name
                else "has an unscorable quality metric"
            )
            raise GovernanceError(f"score report for {system_id} {detail}: {metric_name}")
    total_cost = metrics.get("cost_usd_total")
    if (
        isinstance(total_cost, bool)
        or not isinstance(total_cost, (int, float))
        or not math.isfinite(float(total_cost))
        or total_cost <= 0
    ):
        raise GovernanceError(f"score report for {system_id} reports silent zero cost")
    for mean_name in ("cost_usd_mean", "latency_ms_mean"):
        mean_value = metrics.get(mean_name)
        if (
            isinstance(mean_value, bool)
            or not isinstance(mean_value, (int, float))
            or not math.isfinite(float(mean_value))
            or mean_value <= 0
        ):
            raise GovernanceError(f"score report for {system_id} has invalid {mean_name}")
    latency_values: list[float] = []
    for percentile in ("latency_ms_p50", "latency_ms_p95", "latency_ms_p99"):
        latency = metrics.get(percentile)
        if (
            isinstance(latency, bool)
            or not isinstance(latency, (int, float))
            or not math.isfinite(float(latency))
            or latency <= 0
        ):
            raise GovernanceError(f"score report for {system_id} has invalid latency percentiles")
        latency_values.append(float(latency))
    if latency_values != sorted(latency_values):
        raise GovernanceError(f"score report for {system_id} has invalid latency percentiles")
    event_interval_expectations: dict[str, tuple[float, int]] = {}
    for metric_name in PUBLIC_EVENT_METRICS:
        values = [
            float(event_report["metrics"][metric_name]) for event_report in per_event.values()
        ]
        event_interval_expectations[metric_name] = (
            round(statistics.fmean(values), 6),
            len(values),
        )
    _validated_bootstrap(
        report.get("confidence_intervals"),
        expected_events=len(expected_event_ids),
        expected_samples=bootstrap_samples,
        paired=False,
        required_metrics=PUBLIC_EVENT_METRICS,
        expected_values=event_interval_expectations,
    )
    return report


def _public_test_metric_expectations(test_cases: Sequence[Mapping[str, Any]]) -> JsonObject:
    """Require enough event-level support to publish every advertised benchmark metric."""

    predicates: dict[str, Callable[[Mapping[str, Any]], bool]] = {
        "retrieval": lambda case: any(
            isinstance(grade, int) and not isinstance(grade, bool) and grade > 0
            for grade in case.get("relevance", {}).values()
        ),
        "routing": lambda _case: True,
        "sql": lambda case: "sql_denotation" in case,
        "claims": lambda case: bool(case.get("claims")),
        "visual_claims": lambda case: any(
            claim.get("visual") is True for claim in case.get("claims", [])
        ),
        "abstention": lambda case: case.get("expected_behavior") != "blocked",
        "injection_attacks": lambda case: case.get("injection_attack") is True,
        "knowledge_probes": lambda case: case.get("knowledge_probe") is True,
    }
    sample_counts: dict[str, int] = {
        name: sum(bool(predicate(case)) for case in test_cases)
        for name, predicate in predicates.items()
    }
    sample_counts["claims"] = sum(len(case.get("claims", [])) for case in test_cases)
    sample_counts["visual_claims"] = sum(
        claim.get("visual") is True for case in test_cases for claim in case.get("claims", [])
    )
    sample_counts["visual_regions"] = sum(
        len(claim.get("entailed_regions", []))
        for case in test_cases
        for claim in case.get("claims", [])
        if claim.get("visual") is True
    )
    event_counts = {
        name: len({str(case["event_id"]) for case in test_cases if predicate(case)})
        for name, predicate in predicates.items()
    }
    insufficient = sorted(
        name
        for name in predicates
        if sample_counts[name] < MIN_PUBLIC_METRIC_EVENTS
        or event_counts[name] < MIN_PUBLIC_METRIC_EVENTS
    )
    if insufficient:
        raise GovernanceError(
            "publication test gold has insufficient case/event coverage for metrics: "
            + ", ".join(insufficient)
        )
    if sample_counts["visual_regions"] < sample_counts["visual_claims"]:
        raise GovernanceError("publication test gold has incomplete visual-region coverage")
    return {
        "sample_counts": sample_counts,
        "event_counts": event_counts,
        "minimum_events_per_metric": MIN_PUBLIC_METRIC_EVENTS,
    }


def validate_publication_release(
    *,
    frozen_gold: Mapping[str, Any],
    iaa_report: Mapping[str, Any],
    annotation_batches: Sequence[Mapping[str, Any]],
    private_holdouts: Mapping[str, Any],
    private_manifests: Sequence[Mapping[str, Any]],
    registry_payload: bytes,
    corpus_lock_payload: bytes,
    experiment_matrix: Mapping[str, Any],
    test_envelope: Mapping[str, Any],
    test_commitment: Mapping[str, Any],
    report_payload: bytes,
    signature: Mapping[str, Any],
    trusted_public_key_pem: bytes,
) -> JsonObject:
    """Validate all custodian-side stop conditions before calling results publishable."""

    signature_result = verify_public_report(report_payload, signature, trusted_public_key_pem)
    try:
        public_report = json.loads(report_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError("signed public report is not valid UTF-8 JSON") from exc
    if not isinstance(public_report, dict) or public_report.get("schema_version") != 1:
        raise GovernanceError("signed public report schema_version must equal 1")

    cases, iaa_summary = _validate_frozen_gold_and_iaa(frozen_gold, iaa_report, annotation_batches)
    benchmark_id = str(frozen_gold.get("benchmark_id"))
    benchmark_version = str(frozen_gold.get("benchmark_version"))
    private_report = validate_private_holdout_commitments(
        private_holdouts,
        expected_benchmark_id=benchmark_id,
        expected_benchmark_version=benchmark_version,
        private_manifests=private_manifests,
    )
    if private_report["release_gate_satisfied"] is not True:
        raise GovernanceError("private-holdout release gate is not satisfied")
    committed_private_ids = _verified_private_event_ids(
        [item for item in private_holdouts["commitments"] if isinstance(item, dict)],
        private_manifests,
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
    )
    frozen_private_ids = {
        str(case["event_id"]) for case in cases if case.get("exposure_class") == "private_custodian"
    }
    if frozen_private_ids != committed_private_ids:
        raise GovernanceError("private frozen-gold events do not match sealed commitments")
    release_artifacts = _validate_release_registry_and_corpus(
        frozen_gold=frozen_gold,
        registry_payload=registry_payload,
        corpus_lock_payload=corpus_lock_payload,
        private_manifests=private_manifests,
    )
    matrix_report = validate_equal_settings_matrix(experiment_matrix)
    if (
        experiment_matrix["shared_settings"].get("corpus_lock_sha256")
        != release_artifacts["corpus_lock_sha256"]
    ):
        raise GovernanceError("experiment matrix is not bound to the exact corpus-lock bytes")
    freeze_report = _validate_test_freeze_artifacts(frozen_gold, test_envelope, test_commitment)

    if (
        public_report.get("benchmark_id") != benchmark_id
        or public_report.get("benchmark_version") != benchmark_version
    ):
        raise GovernanceError("signed public report benchmark identity does not match frozen gold")
    bindings = public_report.get("artifact_bindings")
    expected_bindings = {
        "frozen_gold_sha256": _sha256(_canonical_json(frozen_gold)),
        "iaa_report_sha256": _sha256(_canonical_json(iaa_report)),
        "private_holdouts_sha256": _sha256(_canonical_json(private_holdouts)),
        "registry_sha256": release_artifacts["registry_sha256"],
        "corpus_lock_sha256": release_artifacts["corpus_lock_sha256"],
        "experiment_matrix_sha256": _sha256(_canonical_json(experiment_matrix)),
        "test_gold_commitment_sha256": _sha256(_canonical_json(test_commitment)),
        "signer_key_id": signature_result["key_id"],
    }
    if bindings != expected_bindings:
        raise GovernanceError("signed public report artifact bindings are incomplete or stale")
    if public_report.get("iaa_summary") != iaa_summary:
        raise GovernanceError(
            "signed public report omits the redacted pre-adjudication IAA summary"
        )

    comparison = public_report.get("six_system_comparison")
    if not isinstance(comparison, dict):
        raise GovernanceError("signed public report omits the six-system comparison")
    if (
        comparison.get("benchmark_id") != benchmark_id
        or comparison.get("benchmark_version") != benchmark_version
        or comparison.get("split") != "test"
    ):
        raise GovernanceError("six-system comparison benchmark identity is invalid")
    shared_settings = experiment_matrix["shared_settings"]
    if comparison.get("experimental_control") != shared_settings:
        raise GovernanceError("six-system comparison is not bound to the frozen matrix")
    bootstrap_samples = comparison.get("bootstrap_samples")
    if (
        isinstance(bootstrap_samples, bool)
        or not isinstance(bootstrap_samples, int)
        or bootstrap_samples < 10_000
    ):
        raise GovernanceError("publication requires at least 10,000 event bootstrap samples")
    test_cases = [case for case in cases if case["split"] == "test"]
    expected_event_ids = {str(case["event_id"]) for case in test_cases}
    metric_coverage = _public_test_metric_expectations(test_cases)
    expected_sample_counts = metric_coverage["sample_counts"]
    expected_visual_claim_count = sum(
        claim.get("visual") is True for case in test_cases for claim in case.get("claims", [])
    )
    expected_visual_region_count = sum(
        len(claim.get("entailed_regions", []))
        for case in test_cases
        for claim in case.get("claims", [])
        if claim.get("visual") is True
    )
    systems = comparison.get("systems")
    if not isinstance(systems, dict) or set(systems) != set(REQUIRED_SYSTEMS):
        raise GovernanceError("publication requires exactly all six system reports")
    artifact_ids: set[str] = set()
    validated_systems: dict[str, JsonObject] = {}
    for system_id in REQUIRED_SYSTEMS:
        score = _validate_public_score_report(
            systems[system_id],
            system_id=system_id,
            expected_case_count=len(test_cases),
            expected_event_ids=expected_event_ids,
            shared_settings=shared_settings,
            bootstrap_samples=bootstrap_samples,
            expected_sample_counts=expected_sample_counts,
            expected_visual_claim_count=expected_visual_claim_count,
            expected_visual_region_count=expected_visual_region_count,
        )
        artifact_id = str(score["system"]["artifact_id"])
        if artifact_id in artifact_ids:
            raise GovernanceError("six-system reports reuse a configuration artifact ID")
        artifact_ids.add(artifact_id)
        validated_systems[system_id] = score
    comparisons = comparison.get("comparisons")
    if not isinstance(comparisons, dict) or set(comparisons) != set(REQUIRED_SYSTEMS[1:]):
        raise GovernanceError("candidate comparison omits one or more frozen baselines")
    for baseline_id in REQUIRED_SYSTEMS[1:]:
        baseline = comparisons[baseline_id]
        if not isinstance(baseline, dict):
            raise GovernanceError(f"comparison for {baseline_id} must be an object")
        candidate_events = validated_systems[REQUIRED_SYSTEMS[0]]["per_event"]
        baseline_events = validated_systems[baseline_id]["per_event"]
        paired_expectations: dict[str, tuple[float, int]] = {}
        for metric_name in PUBLIC_EVENT_METRICS:
            deltas = [
                float(candidate_events[event_id]["metrics"][metric_name])
                - float(baseline_events[event_id]["metrics"][metric_name])
                for event_id in sorted(expected_event_ids)
            ]
            paired_expectations[metric_name] = (
                round(statistics.fmean(deltas), 6),
                len(deltas),
            )
        _validated_bootstrap(
            baseline.get("paired_event_confidence_intervals"),
            expected_events=len(expected_event_ids),
            expected_samples=bootstrap_samples,
            paired=True,
            required_metrics=PUBLIC_EVENT_METRICS,
            expected_values=paired_expectations,
        )

    knowledge = public_report.get("knowledge_comparison")
    if not isinstance(knowledge, dict):
        raise GovernanceError("signed public report omits closed-book knowledge comparison")
    if (
        knowledge.get("benchmark_id") != benchmark_id
        or knowledge.get("benchmark_version") != benchmark_version
        or knowledge.get("split") != "test"
        or knowledge.get("system_id") != REQUIRED_SYSTEMS[0]
    ):
        raise GovernanceError("knowledge comparison benchmark or system identity is invalid")
    knowledge_cases = [case for case in test_cases if case.get("knowledge_probe") is True]
    if knowledge.get("knowledge_probe_count") != len(knowledge_cases) or not knowledge_cases:
        raise GovernanceError("knowledge comparison does not cover frozen knowledge probes")
    exposure_events = {
        exposure: {
            str(case["event_id"])
            for case in knowledge_cases
            if case.get("exposure_class") == exposure
        }
        for exposure in EXPOSURE_CLASSES
    }
    if not exposure_events["historical_public"] or not exposure_events["recent_public"]:
        raise GovernanceError("knowledge probes must include historical and recent public events")
    if len(exposure_events["private_custodian"]) < private_report["minimum_private_events"]:
        raise GovernanceError("knowledge probes do not cover the minimum private holdout events")
    strata = knowledge.get("by_exposure_class")
    if not isinstance(strata, dict) or set(strata) != EXPOSURE_CLASSES:
        raise GovernanceError("knowledge comparison omits an exposure-class stratum")
    for exposure, event_ids in exposure_events.items():
        stratum = strata[exposure]
        expected_count = sum(case.get("exposure_class") == exposure for case in knowledge_cases)
        if not isinstance(stratum, dict) or stratum.get("sample_count") != expected_count:
            raise GovernanceError(f"knowledge stratum denominator is invalid for {exposure}")
        if not event_ids:
            raise GovernanceError(f"knowledge stratum has no event for {exposure}")
    retrieved = knowledge.get("retrieved")
    closed_book = knowledge.get("closed_book")
    if not isinstance(retrieved, dict) or not isinstance(closed_book, dict):
        raise GovernanceError("knowledge comparison requires retrieved and closed-book reports")
    candidate_system = validated_systems[REQUIRED_SYSTEMS[0]]["system"]
    if retrieved.get("system") != candidate_system or closed_book.get("system") != candidate_system:
        raise GovernanceError("knowledge comparison changes the evaluated model artifact")
    _validate_public_score_report(
        retrieved,
        system_id=REQUIRED_SYSTEMS[0],
        expected_case_count=len(test_cases),
        expected_event_ids=expected_event_ids,
        shared_settings=shared_settings,
        bootstrap_samples=bootstrap_samples,
        expected_sample_counts=expected_sample_counts,
        expected_visual_claim_count=expected_visual_claim_count,
        expected_visual_region_count=expected_visual_region_count,
        expected_context="retrieved",
    )
    _validate_public_score_report(
        closed_book,
        system_id=REQUIRED_SYSTEMS[0],
        expected_case_count=len(test_cases),
        expected_event_ids=expected_event_ids,
        shared_settings=shared_settings,
        bootstrap_samples=bootstrap_samples,
        expected_sample_counts=expected_sample_counts,
        expected_visual_claim_count=expected_visual_claim_count,
        expected_visual_region_count=expected_visual_region_count,
        expected_context="closed_book",
    )
    if (
        retrieved.get("experimental_control") != shared_settings
        or closed_book.get("experimental_control") != shared_settings
    ):
        raise GovernanceError("knowledge comparison changes experimental controls")
    retrieved_condition = retrieved.get("evaluation_condition")
    closed_condition = closed_book.get("evaluation_condition")
    if not isinstance(retrieved_condition, dict) or not isinstance(closed_condition, dict):
        raise GovernanceError("knowledge comparison omits evaluation conditions")
    if (
        retrieved_condition.get("context_access") != "retrieved"
        or closed_condition.get("context_access") != "closed_book"
    ):
        raise GovernanceError("knowledge comparison does not separate retrieved and closed-book")
    for field in ("declared_training_data_cutoff", "model_release_date"):
        if retrieved_condition.get(field) != closed_condition.get(field):
            raise GovernanceError(f"knowledge comparison changes {field}")

    return {
        "publishable": True,
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "system_count": len(validated_systems),
        "registry_event_count": release_artifacts["event_count"],
        "test_event_count": len(expected_event_ids),
        "knowledge_probe_count": len(knowledge_cases),
        "visual_claim_count": expected_visual_claim_count,
        "visual_region_count": expected_visual_region_count,
        "metric_coverage": metric_coverage,
        "private_event_count": private_report["private_event_count"],
        "bootstrap_samples": bootstrap_samples,
        "signer_key_id": signature_result["key_id"],
        "test_escrow": freeze_report,
        "matrix": matrix_report,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    registry = commands.add_parser("validate-registry-bundle")
    registry.add_argument("bundle", type=Path)
    compare = commands.add_parser("compare-annotations")
    compare.add_argument("--packet", required=True, type=Path)
    compare.add_argument("--annotation", required=True, action="append", type=Path)
    compare.add_argument("--output", type=Path)
    adjudicate = commands.add_parser("finalize-adjudication")
    adjudicate.add_argument("--packet", required=True, type=Path)
    adjudicate.add_argument("--annotation", required=True, action="append", type=Path)
    adjudicate.add_argument("--adjudication", required=True, type=Path)
    adjudicate.add_argument("--gold-output", required=True, type=Path)
    adjudicate.add_argument("--iaa-output", required=True, type=Path)
    merge = commands.add_parser("merge-adjudicated-batches")
    merge.add_argument("--batch", required=True, action="append", type=Path)
    merge.add_argument("--gold-output", required=True, type=Path)
    merge.add_argument("--iaa-output", required=True, type=Path)
    private = commands.add_parser("validate-private-holdouts")
    private.add_argument("registry", type=Path)
    private.add_argument("--private-manifest", action="append", type=Path)
    commitment = commands.add_parser("create-private-commitment")
    commitment.add_argument("manifest", type=Path)
    commitment.add_argument("--output", type=Path)
    escrow = commands.add_parser("escrow-test-gold")
    escrow.add_argument("--gold", required=True, type=Path)
    escrow.add_argument("--recipient-public-key", required=True, type=Path)
    escrow.add_argument("--public-gold-output", required=True, type=Path)
    escrow.add_argument("--envelope-output", required=True, type=Path)
    escrow.add_argument("--commitment-output", required=True, type=Path)
    unseal = commands.add_parser("open-test-gold")
    unseal.add_argument("--envelope", required=True, type=Path)
    unseal.add_argument("--commitment", required=True, type=Path)
    unseal.add_argument("--recipient-private-key", required=True, type=Path)
    unseal.add_argument("--output", required=True, type=Path)
    sign = commands.add_parser("sign-report")
    sign.add_argument("--report", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--output", type=Path)
    verify = commands.add_parser("verify-report")
    verify.add_argument("--report", required=True, type=Path)
    verify.add_argument("--signature", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    matrix = commands.add_parser("validate-experiment-matrix")
    matrix.add_argument("matrix", type=Path)
    release = commands.add_parser("validate-publication-release")
    release.add_argument("--gold", required=True, type=Path)
    release.add_argument("--iaa", required=True, type=Path)
    release.add_argument("--annotation-batch", required=True, action="append", type=Path)
    release.add_argument("--private-holdouts", required=True, type=Path)
    release.add_argument("--private-manifest", required=True, action="append", type=Path)
    release.add_argument("--registry", required=True, type=Path)
    release.add_argument("--corpus-lock", required=True, type=Path)
    release.add_argument("--experiment-matrix", required=True, type=Path)
    release.add_argument("--test-envelope", required=True, type=Path)
    release.add_argument("--test-commitment", required=True, type=Path)
    release.add_argument("--report", required=True, type=Path)
    release.add_argument("--signature", required=True, type=Path)
    release.add_argument("--trusted-public-key", required=True, type=Path)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        output: Path | None = getattr(args, "output", None)
        if args.command == "validate-registry-bundle":
            report = validate_registry_bundle(args.bundle)
        elif args.command == "compare-annotations":
            if len(args.annotation) != 2:
                raise GovernanceError("exactly two independent --annotation files are required")
            report = compare_annotations(
                load_json_object(args.packet),
                load_json_object(args.annotation[0]),
                load_json_object(args.annotation[1]),
            )
        elif args.command == "finalize-adjudication":
            if len(args.annotation) != 2:
                raise GovernanceError("exactly two independent --annotation files are required")
            gold, iaa = finalize_adjudication(
                load_json_object(args.packet),
                load_json_object(args.annotation[0]),
                load_json_object(args.annotation[1]),
                load_json_object(args.adjudication),
            )
            _write_json(args.gold_output, gold)
            _write_json(args.iaa_output, iaa)
            report = {
                "gold_sha256": _sha256(_canonical_json(gold)),
                "iaa_sha256": _sha256(_canonical_json(iaa)),
            }
        elif args.command == "merge-adjudicated-batches":
            gold, iaa = merge_adjudicated_batches([load_json_object(path) for path in args.batch])
            _write_json(args.gold_output, gold)
            _write_json(args.iaa_output, iaa)
            report = {
                "batch_count": len(args.batch),
                "gold_sha256": _sha256(_canonical_json(gold)),
                "iaa_sha256": _sha256(_canonical_json(iaa)),
            }
        elif args.command == "validate-private-holdouts":
            private_manifests = (
                [load_json_object(path) for path in args.private_manifest]
                if args.private_manifest
                else None
            )
            report = validate_private_holdout_commitments(
                load_json_object(args.registry), private_manifests=private_manifests
            )
        elif args.command == "create-private-commitment":
            report = create_private_commitment(load_json_object(args.manifest))
        elif args.command == "escrow-test-gold":
            public_gold, envelope, commitment = escrow_test_gold(
                load_json_object(args.gold),
                _read_bounded(args.recipient_public_key, "recipient public key"),
            )
            _write_json(args.public_gold_output, public_gold)
            _write_json(args.envelope_output, envelope)
            _write_json(args.commitment_output, commitment)
            report = commitment
        elif args.command == "open-test-gold":
            report = open_test_gold(
                load_json_object(args.envelope),
                _read_bounded(args.recipient_private_key, "recipient private key"),
                load_json_object(args.commitment),
            )
        elif args.command == "sign-report":
            report = sign_public_report(
                _read_bounded(args.report, "report"),
                _read_bounded(args.private_key, "private signing key"),
            )
        elif args.command == "verify-report":
            report = verify_public_report(
                _read_bounded(args.report, "report"),
                load_json_object(args.signature),
                _read_bounded(args.public_key, "public verification key"),
            )
        elif args.command == "validate-publication-release":
            report = validate_publication_release(
                frozen_gold=load_json_object(args.gold),
                iaa_report=load_json_object(args.iaa),
                annotation_batches=[load_json_object(path) for path in args.annotation_batch],
                private_holdouts=load_json_object(args.private_holdouts),
                private_manifests=[load_json_object(path) for path in args.private_manifest],
                registry_payload=_read_bounded(args.registry, "frozen registry"),
                corpus_lock_payload=_read_bounded(args.corpus_lock, "corpus lock"),
                experiment_matrix=load_json_object(args.experiment_matrix),
                test_envelope=load_json_object(args.test_envelope),
                test_commitment=load_json_object(args.test_commitment),
                report_payload=_read_bounded(args.report, "signed public report"),
                signature=load_json_object(args.signature),
                trusted_public_key_pem=_read_bounded(args.trusted_public_key, "trusted public key"),
            )
        else:
            report = validate_equal_settings_matrix(load_json_object(args.matrix))
        if output:
            _write_json(output, report)
        elif args.command not in {
            "finalize-adjudication",
            "merge-adjudicated-batches",
            "escrow-test-gold",
        }:
            print(json.dumps(report, indent=2, sort_keys=True))
    except GovernanceError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
