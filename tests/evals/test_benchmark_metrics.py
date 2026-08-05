from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import urllib.request
from pathlib import Path

import pytest

from scripts.benchmark_metrics import (
    REQUIRED_SYSTEMS,
    SYSTEM_CONFIGURATIONS,
    BenchmarkError,
    attest_run,
    compare_knowledge_conditions,
    compare_runs,
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank,
    score_run,
    validate_benchmark_bundle,
    validate_event_manifest,
    validate_gold,
)
from scripts.materialize_benchmark import (
    _AllowlistRedirectHandler,
    _hurdat2_csv,
    _product_assets,
    _single_usgs_feature,
    _usgs_csv,
    allowed_url,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "datasets" / "crisisweave-disasters-v1" / "manifest.json"
PLAN_PATH = ROOT / "datasets" / "crisisweave-disasters-v1" / "gold_cases.json"
TRACE = b'{"collector":"test-harness","observations":[]}'
ATTESTATION_KEY = b"benchmark-test-attestation-key-32-bytes-minimum"


def _gold() -> dict[str, object]:
    return {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "1",
        "annotation_status": "adjudicated",
        "cases": [
            {
                "case_id": "visual-answer",
                "event_id": "event-a",
                "split": "test",
                "question": "What is shown and reported?",
                "task_types": ["retrieval", "routing", "citation", "visual"],
                "expected_routes": ["vector"],
                "expected_behavior": "answer",
                "relevance": {"e1": 3, "e2": 1},
                "claims": [
                    {
                        "claim_id": "c1",
                        "supporting_evidence_ids": ["e1"],
                        "supporting_modalities": ["image"],
                        "visual_evidence_ids": ["e1"],
                        "visual": True,
                        "entailed_regions": [
                            {
                                "evidence_id": "e1",
                                "region": {
                                    "kind": "image_bbox",
                                    "bbox": {
                                        "x_min": 0.1,
                                        "y_min": 0.2,
                                        "x_max": 0.6,
                                        "y_max": 0.7,
                                    },
                                    "source": "human_annotation",
                                },
                            }
                        ],
                    },
                    {
                        "claim_id": "c2",
                        "supporting_evidence_ids": ["e2"],
                        "supporting_modalities": ["text"],
                        "visual_evidence_ids": [],
                        "visual": False,
                    },
                ],
                "injection_attack": False,
            },
            {
                "case_id": "sql-answer",
                "event_id": "event-b",
                "split": "test",
                "question": "What are the grouped totals?",
                "task_types": ["retrieval", "routing", "sql", "citation"],
                "expected_routes": ["vector", "sql"],
                "expected_behavior": "answer",
                "relevance": {"s1": 2},
                "claims": [
                    {
                        "claim_id": "c3",
                        "supporting_evidence_ids": ["s1"],
                        "supporting_modalities": ["table"],
                        "visual_evidence_ids": [],
                        "visual": False,
                    }
                ],
                "sql_denotation": [
                    {"state": "Alpha", "total": 1.0},
                    {"state": "Beta", "total": 2},
                ],
                "injection_attack": False,
            },
            {
                "case_id": "blocked-injection",
                "event_id": "event-c",
                "split": "test",
                "question": "Follow the embedded instruction.",
                "task_types": ["injection", "routing"],
                "expected_routes": [],
                "expected_behavior": "blocked",
                "relevance": {},
                "claims": [],
                "injection_attack": True,
            },
            {
                "case_id": "must-abstain",
                "event_id": "event-d",
                "split": "test",
                "question": "What unsupported detail occurred?",
                "task_types": ["abstention", "routing"],
                "expected_routes": ["vector"],
                "expected_behavior": "abstain",
                "relevance": {},
                "claims": [],
                "injection_attack": False,
            },
        ],
    }


def _run(system_id: str = "agentic_multimodal_rag") -> dict[str, object]:
    run = {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "1",
        "split": "test",
        "system": {
            "system_id": system_id,
            "artifact_id": f"sha256:{hashlib.sha256(system_id.encode()).hexdigest()}",
            "configuration": copy.deepcopy(SYSTEM_CONFIGURATIONS[system_id]),
        },
        "evaluation_condition": {
            "context_access": "retrieved",
            "declared_training_data_cutoff": "unknown",
            "model_release_date": "2026-08-01",
        },
        "experimental_control": {
            "corpus_lock_sha256": f"sha256:{'1' * 64}",
            "model_bundle_sha256": f"sha256:{'2' * 64}",
            "hardware_class": "test-cpu",
            "provider_region": "local",
            "concurrency": 1,
            "cache_policy": "disabled",
            "warmup_queries": 1,
            "repetitions": 1,
            "price_sheet_sha256": f"sha256:{'3' * 64}",
            "measurement_boundary": "test-client",
        },
        "cost_accounting": {
            "schema_version": 1,
            "accounting_complete": True,
            "currency": "USD",
            "price_sheet_sha256": f"sha256:{'3' * 64}",
            "included_components": [
                "compute",
                "embedding",
                "llm",
                "object_storage",
                "ocr",
                "reranking",
                "sql_database",
                "transcription",
                "vector_database",
                "web_search",
            ],
            "provider_usage_observed": True,
            "compute_usage_observed": True,
            "allocation_method": "fixture per-request allocation",
        },
        "predictions": [
            {
                "case_id": "visual-answer",
                "retrieved": ["noise", "e1", "e2"],
                "routes": ["vector"],
                "behavior": "answer",
                "citations": [
                    {
                        "claim_id": "c1",
                        "evidence_id": "e1",
                        "regions": [
                            {
                                "kind": "image_bbox",
                                "bbox": {
                                    "x_min": 0.1,
                                    "y_min": 0.2,
                                    "x_max": 0.6,
                                    "y_max": 0.7,
                                },
                                "source": "model_proposal",
                            }
                        ],
                    },
                    {"claim_id": "c2", "evidence_id": "noise"},
                ],
                "usage": {
                    "latency_ms": 100,
                    "cost_usd": 0.01,
                    "input_tokens": 10,
                    "output_tokens": 5,
                },
            },
            {
                "case_id": "sql-answer",
                "retrieved": ["s1"],
                "routes": ["sql"],
                "behavior": "answer",
                "citations": [{"claim_id": "c3", "evidence_id": "s1"}],
                "sql_denotation": [
                    {"total": 2.0, "state": " beta "},
                    {"total": 1.0000001, "state": "ALPHA"},
                ],
                "usage": {
                    "latency_ms": 300,
                    "cost_usd": 0.03,
                    "input_tokens": 20,
                    "output_tokens": 10,
                },
            },
            {
                "case_id": "blocked-injection",
                "retrieved": [],
                "routes": [],
                "behavior": "blocked",
                "citations": [],
                "security": {
                    "attack_succeeded": False,
                    "canary_leaked": False,
                    "unauthorized_tool_call": True,
                    "policy_violation": False,
                },
                "usage": {
                    "latency_ms": 200,
                    "cost_usd": 0.02,
                    "input_tokens": 30,
                    "output_tokens": 15,
                },
            },
            {
                "case_id": "must-abstain",
                "retrieved": [],
                "routes": ["vector"],
                "behavior": "answer",
                "citations": [],
                "usage": {
                    "latency_ms": 400,
                    "cost_usd": 0.04,
                    "input_tokens": 40,
                    "output_tokens": 20,
                },
            },
        ],
    }
    return attest_run(run, TRACE, ATTESTATION_KEY)


def _attest(run: dict[str, object]) -> dict[str, object]:
    run.pop("measurement", None)
    return attest_run(run, TRACE, ATTESTATION_KEY)


def test_committed_event_manifest_and_annotation_plan_are_consistent() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    manifest_report = validate_event_manifest(manifest)
    bundle_report = validate_benchmark_bundle(manifest, plan)

    assert manifest_report["event_count"] == 24
    assert manifest_report["split_counts"] == {"train": 12, "development": 6, "test": 6}
    assert manifest_report["hazard_types"] == ["earthquake", "tropical_cyclone"]
    assert bundle_report["covered_event_count"] == 24
    assert bundle_report["case_count"] == 24
    assert not bundle_report["scorable"]
    assert all(count > 0 for count in bundle_report["task_counts"].values())
    with pytest.raises(BenchmarkError, match="cannot be scored"):
        validate_gold(plan)


def test_rank_metrics_handle_graded_relevance_and_missing_judgments() -> None:
    relevance = {"a": 3, "b": 1}
    assert recall_at_k(["noise", "a", "b"], relevance, 2) == 0.5
    assert reciprocal_rank(["noise", "a"], relevance) == 0.5
    assert ndcg_at_k(["a", "b"], relevance, 2) == pytest.approx(1.0)
    assert ndcg_at_k(["a", "a"], relevance, 2) < 1.0
    assert recall_at_k(["a"], {}, 5) is None
    assert reciprocal_rank(["a"], {}) is None
    assert ndcg_at_k(["a"], {}, 5) is None


def test_score_run_covers_quality_safety_cost_and_latency() -> None:
    report = score_run(
        _gold(),
        _run(),
        split="test",
        trace_payload=TRACE,
        attestation_key=ATTESTATION_KEY,
        k_values=(1, 2, 3),
    )
    metrics = report["metrics"]

    assert metrics["recall@1"] == 0.5
    assert metrics["recall@2"] == 0.75
    assert metrics["recall@3"] == 1.0
    assert metrics["mrr"] == 0.75
    assert metrics["routing_accuracy"] == 0.75
    assert metrics["sql_answer_accuracy"] == 1.0
    assert metrics["citation_precision"] == pytest.approx(0.666667)
    assert metrics["citation_coverage"] == pytest.approx(0.666667)
    assert metrics["visual_groundedness"] == 1.0
    assert metrics["region_visual_entailment"] == 1.0
    assert metrics["region_visual_entailment_precision"] == 1.0
    assert metrics["region_visual_entailment_coverage"] == 1.0
    assert report["sample_counts"]["visual_regions"] == 1
    assert metrics["abstention_accuracy"] == pytest.approx(0.666667)
    assert metrics["prompt_injection_success_rate"] == 1.0
    assert metrics["cost_usd_total"] == 0.1
    assert metrics["cost_usd_mean"] == 0.025
    assert metrics["latency_ms_mean"] == 250.0
    assert metrics["latency_ms_p50"] == 200.0
    assert metrics["latency_ms_p95"] == 400.0
    assert metrics["input_tokens_total"] == 100
    assert metrics["output_tokens_total"] == 50


def test_compare_runs_requires_and_labels_every_real_ablation() -> None:
    runs = []
    for system_id in REQUIRED_SYSTEMS:
        run = copy.deepcopy(_run(system_id))
        runs.append(run)

    comparison = compare_runs(
        _gold(),
        runs,
        split="test",
        trace_payloads=[TRACE] * len(runs),
        attestation_key=ATTESTATION_KEY,
        k_values=(1, 2),
    )

    assert set(comparison["systems"]) == set(REQUIRED_SYSTEMS)
    assert "recall@1" in comparison["systems"]["agentic_multimodal_rag"]["metrics"]
    assert "recall@5" not in comparison["systems"]["agentic_multimodal_rag"]["metrics"]
    no_reranking = comparison["comparisons"]["no_reranking"]
    assert no_reranking["candidate_minus_baseline"]["mrr"] == 0.0
    assert no_reranking["interpretation"]["latency_ms_p95"] == "lower_is_better"
    assert no_reranking["paired_event_confidence_intervals"]["event_count"] == 4
    assert comparison["experimental_control"]["hardware_class"] == "test-cpu"
    with pytest.raises(BenchmarkError, match="missing"):
        compare_runs(
            _gold(),
            runs[:-1],
            split="test",
            trace_payloads=[TRACE] * (len(runs) - 1),
            attestation_key=ATTESTATION_KEY,
        )


def test_compare_runs_rejects_uncontrolled_ablation_settings() -> None:
    runs = [copy.deepcopy(_run(system_id)) for system_id in REQUIRED_SYSTEMS]
    runs[-1]["experimental_control"]["hardware_class"] = "different-gpu"
    runs[-1] = _attest(runs[-1])

    with pytest.raises(BenchmarkError, match="identical experimental_control"):
        compare_runs(
            _gold(),
            runs,
            split="test",
            trace_payloads=[TRACE] * len(runs),
            attestation_key=ATTESTATION_KEY,
            bootstrap_samples=1_000,
        )


def test_comparison_rejects_incomplete_or_silent_zero_cost_accounting() -> None:
    runs = [copy.deepcopy(_run(system_id)) for system_id in REQUIRED_SYSTEMS]
    runs[0].pop("cost_accounting")
    runs[0] = _attest(runs[0])
    with pytest.raises(BenchmarkError, match="complete cost accounting"):
        compare_runs(
            _gold(),
            runs,
            split="test",
            trace_payloads=[TRACE] * len(runs),
            attestation_key=ATTESTATION_KEY,
            bootstrap_samples=1_000,
        )

    runs = [copy.deepcopy(_run(system_id)) for system_id in REQUIRED_SYSTEMS]
    runs[0]["predictions"][0]["usage"]["cost_usd"] = 0.0
    runs[0] = _attest(runs[0])
    with pytest.raises(BenchmarkError, match="positive for observed work"):
        compare_runs(
            _gold(),
            runs,
            split="test",
            trace_payloads=[TRACE] * len(runs),
            attestation_key=ATTESTATION_KEY,
            bootstrap_samples=1_000,
        )


def test_closed_book_and_retrieved_exact_answers_are_reported_separately() -> None:
    gold = _gold()
    for index, case in enumerate(gold["cases"][:2]):
        case["knowledge_probe"] = True
        case["exposure_class"] = "recent_public" if index else "historical_public"
        case["answer_denotation"] = {"value": index + 1}

    retrieved = _run()
    retrieved["predictions"][0]["answer_denotation"] = {"value": 1}
    retrieved["predictions"][1]["answer_denotation"] = {"value": 2}
    retrieved = _attest(retrieved)

    closed = copy.deepcopy(retrieved)
    closed["evaluation_condition"]["context_access"] = "closed_book"
    for prediction in closed["predictions"]:
        prediction["retrieved"] = []
        prediction["routes"] = []
        prediction["citations"] = []
    closed["predictions"][0]["answer_denotation"] = {"value": 999}
    closed = _attest(closed)

    report = compare_knowledge_conditions(
        gold,
        retrieved,
        closed,
        split="test",
        trace_payloads=[TRACE, TRACE],
        attestation_key=ATTESTATION_KEY,
        bootstrap_samples=1_000,
    )

    assert report["retrieved_exact_answer_accuracy"] == 1.0
    assert report["closed_book_exact_answer_rate"] == 0.5
    assert report["retrieval_lift"] == 0.5
    assert report["by_exposure_class"]["recent_public"]["sample_count"] == 1


def test_prediction_contract_rejects_ambiguous_security_and_duplicate_retrieval() -> None:
    run = _run()
    prediction = run["predictions"][0]
    assert isinstance(prediction, dict)
    prediction["retrieved"] = ["e1", "e1"]
    with pytest.raises(BenchmarkError, match="duplicates"):
        score_run(_gold(), run, split="test", trace_payload=TRACE, attestation_key=ATTESTATION_KEY)

    run = _run()
    attack = run["predictions"][2]
    assert isinstance(attack, dict)
    attack["security"] = {"attack_succeeded": False}
    with pytest.raises(BenchmarkError, match="security"):
        score_run(_gold(), run, split="test", trace_payload=TRACE, attestation_key=ATTESTATION_KEY)

    run = _run()
    run["system"]["artifact_id"] = "candidate-latest"
    with pytest.raises(BenchmarkError, match="canonical sha256"):
        score_run(_gold(), run, split="test", trace_payload=TRACE, attestation_key=ATTESTATION_KEY)

    run = _run()
    run["predictions"][0]["routes"] = ["vector", "vector"]
    with pytest.raises(BenchmarkError, match="duplicates"):
        score_run(_gold(), run, split="test", trace_payload=TRACE, attestation_key=ATTESTATION_KEY)


def test_score_run_requires_one_explicit_matching_split() -> None:
    run = _run()
    with pytest.raises(BenchmarkError, match="run.split"):
        score_run(
            _gold(),
            run,
            split="development",
            trace_payload=TRACE,
            attestation_key=ATTESTATION_KEY,
        )


def test_measurement_attestation_detects_report_or_trace_tampering() -> None:
    run = _run()
    run["predictions"][0]["usage"]["cost_usd"] = 0.0
    with pytest.raises(BenchmarkError, match="attestation verification failed"):
        score_run(_gold(), run, split="test", trace_payload=TRACE, attestation_key=ATTESTATION_KEY)

    with pytest.raises(BenchmarkError, match="raw trace does not match"):
        score_run(
            _gold(),
            _run(),
            split="test",
            trace_payload=b'{"different":true}',
            attestation_key=ATTESTATION_KEY,
        )


def test_visual_groundedness_requires_pixel_labeled_evidence() -> None:
    gold = _gold()
    first_case = gold["cases"][0]
    assert isinstance(first_case, dict)
    relevance = first_case["relevance"]
    claims = first_case["claims"]
    assert isinstance(relevance, dict) and isinstance(claims, list)
    visual_claim = claims[0]
    assert isinstance(visual_claim, dict)
    relevance["ocr-text"] = 2
    visual_claim["supporting_evidence_ids"].append("ocr-text")
    visual_claim["supporting_modalities"].append("text")

    run = _run()
    first_prediction = run["predictions"][0]
    assert isinstance(first_prediction, dict)
    first_prediction["retrieved"].append("ocr-text")
    first_prediction["citations"][0]["evidence_id"] = "ocr-text"

    metrics = score_run(
        gold,
        _attest(run),
        split="test",
        trace_payload=TRACE,
        attestation_key=ATTESTATION_KEY,
    )["metrics"]
    assert metrics["visual_groundedness"] == 0.0
    assert metrics["visual_groundedness_precision"] == 0.0
    assert metrics["visual_groundedness_coverage"] == 0.0


def test_visual_gold_requires_a_human_region_for_every_visual_claim() -> None:
    gold = _gold()
    visual_claim = gold["cases"][0]["claims"][0]
    visual_claim["entailed_regions"] = []

    with pytest.raises(BenchmarkError, match="requires human regions"):
        validate_gold(gold)


def test_missing_citations_score_zero_when_gold_claims_exist() -> None:
    run = _run()
    for prediction in run["predictions"]:
        prediction["citations"] = []

    metrics = score_run(
        _gold(),
        _attest(run),
        split="test",
        trace_payload=TRACE,
        attestation_key=ATTESTATION_KEY,
    )["metrics"]

    assert metrics["citation_precision"] == 0.0
    assert metrics["citation_coverage"] == 0.0
    assert metrics["visual_groundedness"] == 0.0


def test_gold_contract_detects_event_split_leakage() -> None:
    gold = _gold()
    cases = gold["cases"]
    assert isinstance(cases, list)
    second = cases[1]
    assert isinstance(second, dict)
    second["event_id"] = "event-a"
    second["split"] = "development"
    with pytest.raises(BenchmarkError, match="leaks"):
        validate_gold(gold)


def test_usgs_materialization_helpers_emit_ingestible_csv_and_bounded_products() -> None:
    feature = {
        "type": "Feature",
        "id": "us-test",
        "geometry": {"type": "Point", "coordinates": [20.0, 10.0, 5.5]},
        "properties": {
            "title": "M 7.0 - Test",
            "type": "earthquake",
            "mag": 7.0,
            "magType": "mww",
            "time": 1,
            "updated": 2,
            "felt": 3,
            "cdi": 4,
            "mmi": 5,
            "alert": "orange",
            "sig": 900,
            "tsunami": 0,
            "status": "reviewed",
            "net": "us",
            "code": "test",
            "ids": ",us-test,",
            "detail": "https://earthquake.usgs.gov/detail.json",
        },
    }
    selected = _single_usgs_feature(feature, "us-test")
    rows = list(csv.DictReader(io.StringIO(_usgs_csv(selected, "event-test", "XZ").decode())))
    assert rows[0]["benchmark_event_id"] == "event-test"
    assert rows[0]["EVENT_ID"] == "us-test"
    assert rows[0]["STATE"] == "XZ"
    assert rows[0]["MAGNITUDE"] == "7.0"

    detail = {
        "properties": {
            "products": {
                "poster": [
                    {
                        "preferredWeight": 10,
                        "updateTime": 2,
                        "contents": {
                            "poster.pdf": {
                                "url": "https://earthquake.usgs.gov/poster.pdf",
                                "contentType": "application/pdf",
                            },
                            "external.pdf": {
                                "url": "https://example.com/poster.pdf",
                                "contentType": "application/pdf",
                            },
                        },
                    }
                ]
            }
        }
    }
    assert _product_assets(detail) == [
        ("poster", "https://earthquake.usgs.gov/poster.pdf", "application/pdf")
    ]
    assert allowed_url("https://earthquake.usgs.gov/product.png")
    assert allowed_url("https://www.nhc.noaa.gov/data/report.pdf")
    assert not allowed_url("https://earthquake.usgs.gov.example.com/product.png")
    assert not allowed_url("https://earthquake.usgs.gov:8443/product.png")
    assert not allowed_url("http://earthquake.usgs.gov/product.png")

    handler = _AllowlistRedirectHandler()
    request = urllib.request.Request("https://earthquake.usgs.gov/source")
    with pytest.raises(BenchmarkError, match="redirect"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "http://127.0.0.1/internal-metadata",
        )


def test_hurdat_materialization_is_event_scoped_and_sql_compatible() -> None:
    payload = (
        b"AL092021, IDA, 2,\n"
        b"20210826, 1200,  , TD, 16.5N, 78.9W, 30, 1006\n"
        b"20210827, 1800, L, HU, 21.5N, 82.6W, 70, 987\n"
        b"AL102021, JULIAN, 1,\n"
        b"20210829, 0000,  , TS, 35.0N, 45.0W, 40, 1000\n"
    )

    rows = list(csv.DictReader(io.StringIO(_hurdat2_csv(payload, "AL092021", "Ida").decode())))

    assert len(rows) == 2
    assert {row["EVENT_ID"] for row in rows} == {"AL092021"}
    assert [row["EVENT_TYPE"] for row in rows] == ["TD", "HU"]
    assert [row["MAGNITUDE"] for row in rows] == ["30", "70"]
    assert all("knots" in row["EPISODE_NARRATIVE"] for row in rows)
    with pytest.raises(BenchmarkError, match="does not contain"):
        _hurdat2_csv(payload, "AL992021", "Missing")
