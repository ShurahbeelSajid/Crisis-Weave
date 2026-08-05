from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from scripts.benchmark_governance import (
    GovernanceError,
    _public_test_metric_expectations,
    compare_annotations,
    create_private_commitment,
    escrow_test_gold,
    finalize_adjudication,
    merge_adjudicated_batches,
    open_test_gold,
    public_iaa_summary,
    sign_public_report,
    validate_equal_settings_matrix,
    validate_private_holdout_commitments,
    validate_publication_release,
    validate_registry_bundle,
    verify_public_report,
)
from scripts.benchmark_metrics import REQUIRED_SYSTEMS, SYSTEM_CONFIGURATIONS
from scripts.benchmark_statistics import (
    event_bootstrap_confidence_intervals,
    paired_event_delta_confidence_intervals,
)

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets" / "crisisweave-disasters-v1"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _digest(value: object) -> str:
    payload = value if isinstance(value, bytes) else _canonical(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _human_pdf_region() -> dict[str, object]:
    return {
        "evidence_id": "e1",
        "region": {
            "kind": "pdf_bbox",
            "page": 1,
            "bbox": {"x_min": 0.1, "y_min": 0.2, "x_max": 0.6, "y_max": 0.7},
            "coordinate_space": "normalized_top_left",
            "source": "human_annotation",
            "label": "mapped impact zone",
        },
    }


def _packet() -> dict[str, object]:
    return {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "2",
        "assignment_id": "blind-batch-001",
        "split": "test",
        "cases": [
            {
                "case_id": "case-1",
                "event_id": "event-1",
                "question": "Which mapped zone supports the reported impact?",
                "task_types": ["retrieval", "routing", "citation", "visual"],
                "evidence_pool": [
                    {
                        "evidence_id": "e1",
                        "modalities": ["pdf_page"],
                        "source_sha256": f"sha256:{'1' * 64}",
                    },
                    {
                        "evidence_id": "e2",
                        "modalities": ["text"],
                        "source_sha256": f"sha256:{'2' * 64}",
                    },
                ],
            }
        ],
    }


def _submission(token: str, *, second_grade: int = 0) -> dict[str, object]:
    return {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "2",
        "assignment_id": "blind-batch-001",
        "annotator_token": token,
        "blindness_attestation": {
            "worked_independently": True,
            "no_cross_annotator_contact": True,
            "used_only_packet_evidence": True,
        },
        "cases": [
            {
                "case_id": "case-1",
                "expected_routes": ["vector"],
                "expected_behavior": "answer",
                "relevance": {"e1": 3, "e2": second_grade},
                "claims": [
                    {
                        "claim_id": "claim-1",
                        "supporting_evidence_ids": ["e1"],
                        "supporting_modalities": ["pdf_page"],
                        "visual_evidence_ids": ["e1"],
                        "visual": True,
                        "entailed_regions": [_human_pdf_region()],
                    }
                ],
                "injection_attack": False,
            }
        ],
    }


def test_v21_registry_is_diverse_and_test_coverage_is_complete() -> None:
    report = validate_registry_bundle(DATASET / "registry_bundle.json")

    assert report["event_count"] == 46
    assert report["version"] == "2.1.0-source-registry"
    assert report["split_counts"] == {"train": 21, "development": 11, "test": 14}
    assert report["planned_case_count"] == 46
    assert set(report["expansion_hazards"]) >= {
        "flood",
        "wildfire",
        "drought",
        "landslide",
        "extreme_heat",
        "industrial_accident",
    }
    assert len(report["geographic_regions"]) == 7
    assert len(report["languages"]) == 6
    assert "hi" not in report["languages"]
    assert report["exposure_counts"]["recent_public"] == 8
    assert report["release_status"] == "source_registry"
    assert report["split_coverage"] == {
        "train": {
            "event_count": 21,
            "expansion_event_count": 9,
            "hazards": [
                "drought",
                "earthquake",
                "extreme_heat",
                "flood",
                "industrial_accident",
                "landslide",
                "tropical_cyclone",
            ],
            "geographic_regions": ["africa", "asia", "europe"],
            "languages": ["en"],
            "recent_public_event_count": 3,
        },
        "development": {
            "event_count": 11,
            "expansion_event_count": 5,
            "hazards": [
                "earthquake",
                "flood",
                "industrial_accident",
                "tropical_cyclone",
                "wildfire",
            ],
            "geographic_regions": [
                "africa",
                "asia",
                "europe",
                "latin_america_caribbean",
                "middle_east_north_africa",
            ],
            "languages": ["en", "es"],
            "recent_public_event_count": 3,
        },
        "test": {
            "event_count": 14,
            "expansion_event_count": 8,
            "hazards": [
                "drought",
                "earthquake",
                "extreme_heat",
                "flood",
                "industrial_accident",
                "landslide",
                "tropical_cyclone",
                "volcanic_eruption",
                "wildfire",
            ],
            "geographic_regions": [
                "africa",
                "asia",
                "europe",
                "latin_america_caribbean",
                "middle_east_north_africa",
                "north_america",
                "oceania",
            ],
            "languages": ["ar", "el", "en", "es", "fr", "pt-BR"],
            "recent_public_event_count": 2,
        },
    }

    expansion = json.loads((DATASET / "diversity_expansion.json").read_text(encoding="utf-8"))
    events = {event["event_id"]: event for event in expansion["events"]}
    assert events["imd-north-india-heat-2024"]["languages"] == ["en"]
    assert events["unosat-EQ20250328MMR"]["sources"][0]["url"].endswith("/4098")
    french_canada = events["nrcan-wildfires-2023"]["sources"][1]
    assert french_canada["publisher"] == "Environment and Climate Change Canada"
    plan = json.loads((DATASET / "annotation_plan_expansion.json").read_text(encoding="utf-8"))
    assert plan["benchmark_version"] == "2.1.0-source-registry"
    assert all("question" not in case for case in plan["cases"])
    assert all(
        "sealed" in case["case_id"] and "sealed" in case["prompt_intent"].lower()
        for case in plan["cases"]
        if case["split"] == "test"
    )
    assert all(
        "sealed" not in case["case_id"] and "sealed" not in case["prompt_intent"].lower()
        for case in plan["cases"]
        if case["split"] != "test"
    )
    commitments = json.loads(
        (DATASET / "private_holdout_commitments.json").read_text(encoding="utf-8")
    )
    assert commitments["benchmark_version"] == "2.1.0-source-registry"
    assert commitments["commitments"] == []
    assert commitments["release_status"] == "blocked_pending_custodian_data"


def test_public_metric_coverage_requires_five_distinct_events_per_metric() -> None:
    cases = [
        {
            "event_id": f"event-{index}",
            "relevance": {"e1": 3},
            "expected_behavior": "answer",
            "sql_denotation": [{"value": index}],
            "injection_attack": True,
            "knowledge_probe": True,
            "claims": [
                {
                    "visual": True,
                    "entailed_regions": [_human_pdf_region()],
                }
            ],
        }
        for index in range(5)
    ]

    with pytest.raises(GovernanceError, match="insufficient case/event coverage"):
        _public_test_metric_expectations(cases[:4])
    report = _public_test_metric_expectations(cases)
    assert report["minimum_events_per_metric"] == 5
    assert report["sample_counts"]["sql"] == 5
    assert report["event_counts"]["injection_attacks"] == 5


def test_v21_rebalance_is_minimal_and_keeps_v1_assignments_immutable() -> None:
    bundle = json.loads((DATASET / "registry_bundle.json").read_text(encoding="utf-8"))
    base = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
    expansion = json.loads((DATASET / "diversity_expansion.json").read_text(encoding="utf-8"))

    base_test = [event for event in base["events"] if event["split"] == "test"]
    base_test_hazards = {event["hazard_type"] for event in base_test}
    french_events = [event for event in expansion["events"] if "fr" in event["languages"]]
    greek_events = [event for event in expansion["events"] if "el" in event["languages"]]

    assert len(base_test) == 6
    assert base_test_hazards == {"earthquake", "tropical_cyclone"}
    assert [(event["event_id"], event["hazard_type"]) for event in french_events] == [
        ("nrcan-wildfires-2023", "wildfire")
    ]
    assert [(event["event_id"], event["hazard_type"]) for event in greek_events] == [
        ("cems-EMSR675", "wildfire")
    ]
    assert bundle["rebalance"]["minimum_test_event_count"] == 6 + 7 + 1 == 14
    assert bundle["rebalance"]["immutable_v1_assignments_preserved"] is True


def test_registry_rejects_v1_assignment_drift_and_test_coverage_regression(
    tmp_path: Path,
) -> None:
    v1_drift = tmp_path / "v1-drift"
    shutil.copytree(DATASET, v1_drift)
    manifest_path = v1_drift / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["events"][0]["split"] = "test"
    manifest["split_counts"] = {"train": 11, "development": 6, "test": 7}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(GovernanceError, match="immutable v1 assignment digest"):
        validate_registry_bundle(v1_drift / "registry_bundle.json")

    coverage_drift = tmp_path / "coverage-drift"
    shutil.copytree(DATASET, coverage_drift)
    expansion_path = coverage_drift / "diversity_expansion.json"
    expansion = json.loads(expansion_path.read_text(encoding="utf-8"))
    events = {event["event_id"]: event for event in expansion["events"]}
    events["nrcan-wildfires-2023"]["split"] = "train"
    events["gfdrr-pakistan-floods-2022"]["split"] = "test"
    expansion_path.write_text(json.dumps(expansion), encoding="utf-8")

    with pytest.raises(GovernanceError, match="test coverage policy is unsatisfied"):
        validate_registry_bundle(coverage_drift / "registry_bundle.json")


def test_two_blind_annotations_produce_iaa_and_complete_disagreement_packet() -> None:
    annotation_a = _submission("anon:aaaaaaaaaaaaaaaa", second_grade=0)
    annotation_b = _submission("anon:bbbbbbbbbbbbbbbb", second_grade=1)

    report = compare_annotations(_packet(), annotation_a, annotation_b)

    assert report["sample_counts"] == {
        "cases": 1,
        "evidence_judgments": 2,
        "sql_cases": 0,
        "knowledge_cases": 0,
        "disagreements": 1,
    }
    assert report["disagreements"][0]["field"] == "relevance"
    assert report["agreement"]["behavior_cohen_kappa"] == 1.0
    assert report["agreement"]["relevance_quadratic_weighted_kappa"] < 1.0
    rendered = json.dumps(report)
    assert "anon:aaaaaaaaaaaaaaaa" not in rendered
    assert "anon:bbbbbbbbbbbbbbbb" not in rendered


def test_leakage_labels_and_denotations_are_independently_adjudicated() -> None:
    annotation_a = _submission("anon:aaaaaaaaaaaaaaaa")
    annotation_b = _submission("anon:bbbbbbbbbbbbbbbb")
    annotation_a["cases"][0].update(
        {
            "knowledge_probe": True,
            "answer_denotation": {"value": "A"},
            "exposure_class": "historical_public",
        }
    )
    annotation_b["cases"][0].update(
        {
            "knowledge_probe": True,
            "answer_denotation": {"value": "B"},
            "exposure_class": "recent_public",
        }
    )

    report = compare_annotations(_packet(), annotation_a, annotation_b)

    assert {item["field"] for item in report["disagreements"]} == {
        "answer_denotation",
        "exposure_class",
    }
    assert report["agreement"]["case_exact_agreement"] == 0.0
    assert report["agreement"]["knowledge_answer_denotation_exact_agreement"] == 0.0


def test_third_blind_adjudicator_must_resolve_every_disagreement() -> None:
    annotation_a = _submission("anon:aaaaaaaaaaaaaaaa", second_grade=0)
    annotation_b = _submission("anon:bbbbbbbbbbbbbbbb", second_grade=1)
    final_case = copy.deepcopy(annotation_a["cases"][0])
    adjudication = {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "2",
        "assignment_id": "blind-batch-001",
        "adjudicator_token": "anon:cccccccccccccccc",
        "blindness_attestation": {
            "annotator_identities_hidden": True,
            "conflicts_reviewed_against_source_evidence": True,
        },
        "decisions": [
            {
                "case_id": "case-1",
                "field": "relevance",
                "resolution": "annotator_a",
                "rationale": "The frozen source does not support e2.",
            }
        ],
        "cases": [final_case],
    }

    gold, iaa = finalize_adjudication(_packet(), annotation_a, annotation_b, adjudication)

    assert gold["annotation_status"] == "adjudicated"
    assert gold["annotation_protocol"]["independent_annotators"] == 2
    assert gold["annotation_protocol"]["adjudicators"] == 1
    assert iaa["sample_counts"]["disagreements"] == 1
    summary = public_iaa_summary(iaa)
    assert summary["adjudication_accounting"] == {
        "eligible_disagreement_count": 1,
        "adjudicated_disagreement_count": 1,
        "unresolved_disagreement_count": 0,
        "adjudication_rate": 1.0,
    }
    assert summary["exclusion_accounting"] == {
        "case_count_before_exclusions": 1,
        "included_case_count": 1,
        "excluded_case_count": 0,
        "evidence_judgment_count_before_exclusions": 2,
        "included_evidence_judgment_count": 2,
        "excluded_evidence_judgment_count": 0,
        "by_reason": {},
    }
    assert "annotator_a" not in json.dumps(summary)

    incomplete_accounting = copy.deepcopy(iaa)
    incomplete_accounting["adjudication_accounting"]["adjudication_rate"] = 0.5
    with pytest.raises(GovernanceError, match="complete adjudication accounting"):
        public_iaa_summary(incomplete_accounting)

    adjudication["decisions"] = []
    with pytest.raises(GovernanceError, match="resolve exactly every disagreement"):
        finalize_adjudication(_packet(), annotation_a, annotation_b, adjudication)


def _uncontested_batch(*, assignment: str, split: str, case_id: str, event_id: str) -> dict:
    packet = _packet()
    packet["assignment_id"] = assignment
    packet["split"] = split
    packet["cases"][0]["case_id"] = case_id
    packet["cases"][0]["event_id"] = event_id
    annotation_a = _submission("anon:aaaaaaaaaaaaaaaa")
    annotation_b = _submission("anon:bbbbbbbbbbbbbbbb")
    for annotation in (annotation_a, annotation_b):
        annotation["assignment_id"] = assignment
        annotation["cases"][0]["case_id"] = case_id
    adjudication = {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "2",
        "assignment_id": assignment,
        "adjudicator_token": "anon:cccccccccccccccc",
        "blindness_attestation": {
            "annotator_identities_hidden": True,
            "conflicts_reviewed_against_source_evidence": True,
        },
        "decisions": [],
        "cases": copy.deepcopy(annotation_a["cases"]),
    }
    return {
        "packet": packet,
        "annotation_a": annotation_a,
        "annotation_b": annotation_b,
        "adjudication": adjudication,
    }


def test_batch_merge_recomputes_pooled_iaa_and_rejects_duplicate_cases() -> None:
    train = _uncontested_batch(
        assignment="train-batch", split="train", case_id="case-train", event_id="event-train"
    )
    test = _uncontested_batch(
        assignment="test-batch", split="test", case_id="case-test", event_id="event-test"
    )

    gold, iaa = merge_adjudicated_batches([test, train])

    assert [case["case_id"] for case in gold["cases"]] == ["case-train", "case-test"]
    assert gold["annotation_protocol"]["batch_count"] == 2
    assert iaa["sample_counts"]["cases"] == 2
    assert iaa["batch_count"] == 2
    assert iaa["adjudication_accounting"]["adjudication_rate"] is None
    assert iaa["exclusion_accounting"]["excluded_case_count"] == 0
    assert merge_adjudicated_batches([train, test]) == (gold, iaa)

    duplicate = copy.deepcopy(train)
    duplicate["packet"]["assignment_id"] = "another-train-batch"
    duplicate["annotation_a"]["assignment_id"] = "another-train-batch"
    duplicate["annotation_b"]["assignment_id"] = "another-train-batch"
    duplicate["adjudication"]["assignment_id"] = "another-train-batch"
    with pytest.raises(GovernanceError, match="repeat case_id"):
        merge_adjudicated_batches([train, duplicate])


def test_blind_protocol_rejects_identity_and_colluding_tokens() -> None:
    annotation = _submission("anon:aaaaaaaaaaaaaaaa")
    annotation["email"] = "not-allowed@example.invalid"
    with pytest.raises(GovernanceError, match="identity fields"):
        compare_annotations(_packet(), annotation, _submission("anon:bbbbbbbbbbbbbbbb"))

    same = _submission("anon:aaaaaaaaaaaaaaaa")
    with pytest.raises(GovernanceError, match="distinct blind tokens"):
        compare_annotations(_packet(), same, copy.deepcopy(same))


def test_private_holdout_gate_fails_honestly_until_custodian_commits_events() -> None:
    pending = json.loads((DATASET / "private_holdout_commitments.json").read_text(encoding="utf-8"))
    report = validate_private_holdout_commitments(pending)
    assert report == {
        "private_event_count": 0,
        "minimum_private_events": 3,
        "manifest_correspondence_verified": False,
        "release_gate_satisfied": False,
    }

    manifest = {
        "schema_version": 1,
        "benchmark_id": "crisisweave-global-disasters",
        "benchmark_version": "2.0.0-source-registry",
        "events": [
            {
                "event_id": f"never-published-{index}",
                "exposure_class": "private_custodian",
                "source_lock_sha256": f"sha256:{index + 1:064x}",
                "commitment_nonce": f"nonce:{index + 101:064x}",
            }
            for index in range(3)
        ],
    }
    commitment = create_private_commitment(manifest)
    assert commitment["event_count"] == 3
    assert "event_id" not in commitment
    committed = {
        "schema_version": 1,
        "benchmark_id": manifest["benchmark_id"],
        "benchmark_version": manifest["benchmark_version"],
        "minimum_private_events": 3,
        "commitments": [commitment],
        "release_status": "committed_pending_custodian_verification",
    }
    assert validate_private_holdout_commitments(committed)["release_gate_satisfied"] is False
    verified = validate_private_holdout_commitments(committed, private_manifests=[manifest])
    assert verified["manifest_correspondence_verified"] is True
    assert verified["release_gate_satisfied"] is True

    duplicated = copy.deepcopy(manifest)
    duplicated["events"][1]["event_id"] = duplicated["events"][0]["event_id"]
    with pytest.raises(GovernanceError, match="repeats event_id"):
        create_private_commitment(duplicated)


def test_equal_settings_matrix_and_event_cluster_intervals_are_deterministic() -> None:
    template = json.loads((DATASET / "experiment_matrix.template.json").read_text(encoding="utf-8"))
    with pytest.raises(GovernanceError, match="not executable"):
        validate_equal_settings_matrix(template)

    matrix = copy.deepcopy(template)
    matrix["template_only"] = False
    matrix["shared_settings"].update(
        {
            "corpus_lock_sha256": f"sha256:{'1' * 64}",
            "model_bundle_sha256": f"sha256:{'2' * 64}",
            "price_sheet_sha256": f"sha256:{'3' * 64}",
            "hardware_class": "staging-a100-80gb",
            "provider_region": "isolated-staging",
        }
    )
    assert validate_equal_settings_matrix(matrix)["system_count"] == 6
    matrix["systems"][3]["configuration"]["reranking"] = True
    with pytest.raises(GovernanceError, match="frozen no_reranking contract"):
        validate_equal_settings_matrix(matrix)

    candidate = {"a": {"mrr": 1.0}, "b": {"mrr": 0.5}, "c": {"mrr": 0.0}}
    baseline = {"a": {"mrr": 0.5}, "b": {"mrr": 0.5}, "c": {"mrr": 0.0}}
    first = event_bootstrap_confidence_intervals(candidate, samples=1_000, seed=7)
    second = event_bootstrap_confidence_intervals(candidate, samples=1_000, seed=7)
    paired = paired_event_delta_confidence_intervals(candidate, baseline, samples=1_000, seed=7)
    assert first == second
    assert first["event_count"] == 3
    assert paired["intervals"]["mrr"]["estimate_event_macro_delta"] == pytest.approx(
        1 / 6, abs=1e-6
    )


def test_rsa_test_label_escrow_and_ed25519_public_verification() -> None:
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    base_case = {
        "question": "What happened?",
        "task_types": ["retrieval", "routing", "citation"],
        "expected_routes": ["vector"],
        "expected_behavior": "answer",
        "relevance": {"e1": 3},
        "claims": [
            {
                "claim_id": "c1",
                "supporting_evidence_ids": ["e1"],
                "supporting_modalities": ["text"],
                "visual_evidence_ids": [],
                "visual": False,
            }
        ],
        "injection_attack": False,
    }
    gold = {
        "schema_version": 1,
        "benchmark_id": "fixture",
        "benchmark_version": "2",
        "annotation_status": "frozen",
        "cases": [
            {**base_case, "case_id": "public", "event_id": "event-a", "split": "train"},
            {**base_case, "case_id": "sealed", "event_id": "event-b", "split": "test"},
        ],
    }
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_public_pem = rsa_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    rsa_private_pem = rsa_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_gold, envelope, commitment = escrow_test_gold(gold, rsa_public_pem)
    opened = open_test_gold(envelope, rsa_private_pem, commitment)
    assert [case["case_id"] for case in public_gold["cases"]] == ["public"]
    assert [case["case_id"] for case in opened["cases"]] == ["sealed"]
    assert not commitment["test_case_ids_disclosed"]

    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    wrong_key_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(GovernanceError, match="committed public key"):
        open_test_gold(envelope, wrong_key_pem, commitment)

    tampered_commitment = {**commitment, "sealed_case_count": 999}
    with pytest.raises(GovernanceError, match="case count"):
        open_test_gold(envelope, rsa_private_pem, tampered_commitment)

    signing_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    payload = b'{"real_scores_only":true}\n'
    signature = sign_public_report(payload, private_pem)
    assert verify_public_report(payload, signature, public_pem)["verified"]
    with pytest.raises(GovernanceError, match="digest"):
        verify_public_report(payload + b"tampered", signature, public_pem)


def test_publication_gate_binds_every_external_release_prerequisite() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    exposures = [
        ("event-historical", "historical_public"),
        ("event-recent", "recent_public"),
        ("event-private-a", "private_custodian"),
        ("event-private-b", "private_custodian"),
        ("event-private-c", "private_custodian"),
    ]
    common = {
        "question": "What does the frozen evidence show?",
        "task_types": [
            "retrieval",
            "routing",
            "sql",
            "citation",
            "visual",
            "abstention",
            "injection",
        ],
        "expected_routes": ["vector", "sql"],
        "expected_behavior": "answer",
        "relevance": {"e1": 3},
        "claims": [
            {
                "claim_id": "c1",
                "supporting_evidence_ids": ["e1"],
                "supporting_modalities": ["pdf_page"],
                "visual_evidence_ids": ["e1"],
                "visual": True,
                "entailed_regions": [_human_pdf_region()],
            }
        ],
        "sql_denotation": [{"value": 1}],
        "injection_attack": True,
    }
    cases = [
        {
            **copy.deepcopy(common),
            "case_id": "public-train-case",
            "event_id": "public-train-event",
            "split": "train",
        }
    ]
    for index, (event_id, exposure) in enumerate(exposures):
        cases.append(
            {
                **copy.deepcopy(common),
                "case_id": f"sealed-{index}",
                "event_id": event_id,
                "split": "test",
                "knowledge_probe": True,
                "exposure_class": exposure,
                "answer_denotation": {"value": index},
            }
        )

    def release_batch(split: str, split_cases: list[dict[str, object]]) -> dict[str, object]:
        assignment = f"release-{split}"
        packet_cases = [
            {
                "case_id": case["case_id"],
                "event_id": case["event_id"],
                "question": case["question"],
                "task_types": case["task_types"],
                "evidence_pool": [
                    {
                        "evidence_id": "e1",
                        "modalities": ["pdf_page"],
                        "source_sha256": f"sha256:{'9' * 64}",
                    }
                ],
            }
            for case in split_cases
        ]
        label_fields = {
            "case_id",
            "expected_routes",
            "expected_behavior",
            "relevance",
            "claims",
            "sql_denotation",
            "injection_attack",
            "knowledge_probe",
            "answer_denotation",
            "exposure_class",
        }
        labels = [
            {key: copy.deepcopy(value) for key, value in case.items() if key in label_fields}
            for case in split_cases
        ]
        base_submission = {
            "schema_version": 1,
            "benchmark_id": "release-fixture",
            "benchmark_version": "2",
            "assignment_id": assignment,
            "blindness_attestation": {
                "worked_independently": True,
                "no_cross_annotator_contact": True,
                "used_only_packet_evidence": True,
            },
            "cases": labels,
        }
        annotation_a = {
            **copy.deepcopy(base_submission),
            "annotator_token": "anon:aaaaaaaaaaaaaaaa",
        }
        annotation_b = {
            **copy.deepcopy(base_submission),
            "annotator_token": "anon:bbbbbbbbbbbbbbbb",
        }
        return {
            "packet": {
                "schema_version": 1,
                "benchmark_id": "release-fixture",
                "benchmark_version": "2",
                "assignment_id": assignment,
                "split": split,
                "cases": packet_cases,
            },
            "annotation_a": annotation_a,
            "annotation_b": annotation_b,
            "adjudication": {
                "schema_version": 1,
                "benchmark_id": "release-fixture",
                "benchmark_version": "2",
                "assignment_id": assignment,
                "adjudicator_token": "anon:cccccccccccccccc",
                "blindness_attestation": {
                    "annotator_identities_hidden": True,
                    "conflicts_reviewed_against_source_evidence": True,
                },
                "decisions": [],
                "cases": copy.deepcopy(labels),
            },
        }

    annotation_batches = [
        release_batch(split, [case for case in cases if case["split"] == split])
        for split in ("train", "test")
    ]
    merged_gold, iaa = merge_adjudicated_batches(annotation_batches)
    frozen_gold = copy.deepcopy(merged_gold)
    frozen_gold["annotation_status"] = "frozen"
    private_manifest = {
        "schema_version": 1,
        "benchmark_id": "release-fixture",
        "benchmark_version": "2",
        "events": [
            {
                "event_id": event_id,
                "exposure_class": "private_custodian",
                "source_lock_sha256": f"sha256:{index + 11:064x}",
                "commitment_nonce": f"nonce:{index + 101:064x}",
            }
            for index, event_id in enumerate(
                [event_id for event_id, exposure in exposures if exposure == "private_custodian"]
            )
        ],
    }
    private_manifests = [private_manifest]
    private_holdouts = {
        "schema_version": 1,
        "benchmark_id": "release-fixture",
        "benchmark_version": "2",
        "minimum_private_events": 3,
        "commitments": [create_private_commitment(private_manifest)],
        "release_status": "committed_pending_custodian_verification",
    }
    private_source_locks = {
        event["event_id"]: event["source_lock_sha256"] for event in private_manifest["events"]
    }
    registry = {
        "schema_version": 1,
        "benchmark_id": "release-fixture",
        "benchmark_version": "2",
        "release_status": "frozen",
        "events": [
            {
                "event_id": case["event_id"],
                "split": case["split"],
                "exposure_class": case.get("exposure_class", "historical_public"),
            }
            for case in frozen_gold["cases"]
        ],
    }
    registry_payload = _canonical(registry)
    corpus_lock = {
        "schema_version": 1,
        "benchmark_id": "release-fixture",
        "benchmark_version": "2",
        "release_status": "frozen",
        "registry_sha256": _digest(registry_payload),
        "events": [
            {
                **event,
                "source_lock_sha256": private_source_locks.get(
                    event["event_id"], f"sha256:{index + 201:064x}"
                ),
            }
            for index, event in enumerate(registry["events"])
        ],
    }
    corpus_lock_payload = _canonical(corpus_lock)
    matrix = json.loads((DATASET / "experiment_matrix.template.json").read_text(encoding="utf-8"))
    matrix["template_only"] = False
    matrix["shared_settings"].update(
        {
            "corpus_lock_sha256": _digest(corpus_lock_payload),
            "model_bundle_sha256": f"sha256:{'2' * 64}",
            "price_sheet_sha256": f"sha256:{'3' * 64}",
            "hardware_class": "isolated-staging-a100",
            "provider_region": "custodian-staging",
        }
    )
    shared = matrix["shared_settings"]

    escrow_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    escrow_public = escrow_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _, test_envelope, test_commitment = escrow_test_gold(frozen_gold, escrow_public)

    required_metrics = {
        "recall@5": 1.0,
        "recall@10": 1.0,
        "recall@30": 1.0,
        "ndcg@5": 1.0,
        "ndcg@10": 1.0,
        "ndcg@30": 1.0,
        "mrr": 1.0,
        "routing_accuracy": 1.0,
        "sql_answer_accuracy": 1.0,
        "citation_precision": 1.0,
        "citation_coverage": 1.0,
        "visual_groundedness": 1.0,
        "visual_groundedness_precision": 1.0,
        "visual_groundedness_coverage": 1.0,
        "region_visual_entailment": 1.0,
        "region_visual_entailment_precision": 1.0,
        "region_visual_entailment_coverage": 1.0,
        "abstention_accuracy": 1.0,
        "prompt_injection_success_rate": 0.0,
        "exact_answer_accuracy": 1.0,
        "cost_usd_total": 0.5,
        "cost_usd_mean": 0.1,
        "latency_ms_mean": 110.0,
        "latency_ms_p50": 100.0,
        "latency_ms_p95": 140.0,
        "latency_ms_p99": 150.0,
    }
    event_ids = [event_id for event_id, _ in exposures]
    event_interval_metrics = {
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
    bootstrap = {
        "method": "event_cluster_percentile_bootstrap",
        "samples": 10_000,
        "seed": 24_051,
        "event_count": len(event_ids),
        "intervals": {
            metric: {
                "estimate_event_macro_mean": float(required_metrics[metric]),
                "ci95_low": 0.0,
                "ci95_high": 1.0,
                "contributing_events": len(event_ids),
            }
            for metric in event_interval_metrics
        },
    }
    cost_accounting = {
        "schema_version": 1,
        "accounting_complete": True,
        "currency": "USD",
        "price_sheet_sha256": shared["price_sheet_sha256"],
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
        "allocation_method": "fixture allocation",
    }

    def score_report(system_id: str, context_access: str = "retrieved") -> dict[str, object]:
        return {
            "system_id": system_id,
            "system": {
                "system_id": system_id,
                "artifact_id": _digest(f"artifact:{system_id}".encode()),
                "configuration": copy.deepcopy(SYSTEM_CONFIGURATIONS[system_id]),
            },
            "measurement_binding": {
                "collector": "crisisweave-custodian-harness/1",
                "trace_sha256": _digest(f"trace:{system_id}:{context_access}".encode()),
            },
            "split": "test",
            "case_count": len(event_ids),
            "sample_counts": {
                "retrieval": len(event_ids),
                "routing": len(event_ids),
                "sql": len(event_ids),
                "claims": len(event_ids),
                "knowledge_probes": len(event_ids),
                "visual_claims": len(event_ids),
                "visual_regions": len(event_ids),
                "abstention": len(event_ids),
                "injection_attacks": len(event_ids),
            },
            "region_grounding": {
                "iou_threshold": 0.5,
                "gold_regions": len(event_ids),
                "predicted_regions": len(event_ids),
                "matched_regions": len(event_ids),
            },
            "evaluation_condition": {
                "context_access": context_access,
                "declared_training_data_cutoff": "unknown",
                "model_release_date": "2026-08-01",
            },
            "experimental_control": copy.deepcopy(shared),
            "cost_accounting": copy.deepcopy(cost_accounting),
            "metrics": copy.deepcopy(required_metrics),
            "per_event": {
                event_id: {"case_count": 1, "metrics": copy.deepcopy(required_metrics)}
                for event_id in event_ids
            },
            "confidence_intervals": copy.deepcopy(bootstrap),
        }

    systems = {system_id: score_report(system_id) for system_id in REQUIRED_SYSTEMS}
    paired = {
        "method": "paired_event_cluster_percentile_bootstrap",
        "samples": 10_000,
        "seed": 24_051,
        "event_count": len(event_ids),
        "intervals": {
            metric: {
                "estimate_event_macro_delta": 0.0,
                "ci95_low": -1.0,
                "ci95_high": 1.0,
                "paired_events": len(event_ids),
            }
            for metric in event_interval_metrics
        },
    }
    comparison = {
        "benchmark_id": frozen_gold["benchmark_id"],
        "benchmark_version": frozen_gold["benchmark_version"],
        "split": "test",
        "experimental_control": copy.deepcopy(shared),
        "evaluation_condition": systems[REQUIRED_SYSTEMS[0]]["evaluation_condition"],
        "bootstrap_samples": 10_000,
        "systems": systems,
        "comparisons": {
            system_id: {"paired_event_confidence_intervals": copy.deepcopy(paired)}
            for system_id in REQUIRED_SYSTEMS[1:]
        },
    }
    knowledge = {
        "benchmark_id": frozen_gold["benchmark_id"],
        "benchmark_version": frozen_gold["benchmark_version"],
        "split": "test",
        "system_id": REQUIRED_SYSTEMS[0],
        "knowledge_probe_count": len(event_ids),
        "by_exposure_class": {
            "historical_public": {"sample_count": 1},
            "recent_public": {"sample_count": 1},
            "private_custodian": {"sample_count": 3},
        },
        "retrieved": copy.deepcopy(systems[REQUIRED_SYSTEMS[0]]),
        "closed_book": score_report(REQUIRED_SYSTEMS[0], "closed_book"),
    }

    signer = ed25519.Ed25519PrivateKey.generate()
    signer_private = signer.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    signer_public = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer_public_der = signer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_report = {
        "schema_version": 1,
        "benchmark_id": frozen_gold["benchmark_id"],
        "benchmark_version": frozen_gold["benchmark_version"],
        "artifact_bindings": {
            "frozen_gold_sha256": _digest(frozen_gold),
            "iaa_report_sha256": _digest(iaa),
            "private_holdouts_sha256": _digest(private_holdouts),
            "registry_sha256": _digest(registry_payload),
            "corpus_lock_sha256": _digest(corpus_lock_payload),
            "experiment_matrix_sha256": _digest(matrix),
            "test_gold_commitment_sha256": _digest(test_commitment),
            "signer_key_id": _digest(signer_public_der),
        },
        "iaa_summary": public_iaa_summary(iaa),
        "six_system_comparison": comparison,
        "knowledge_comparison": knowledge,
    }
    report_payload = _canonical(public_report)
    signature = sign_public_report(report_payload, signer_private)
    result = validate_publication_release(
        frozen_gold=frozen_gold,
        iaa_report=iaa,
        annotation_batches=annotation_batches,
        private_holdouts=private_holdouts,
        private_manifests=private_manifests,
        registry_payload=registry_payload,
        corpus_lock_payload=corpus_lock_payload,
        experiment_matrix=matrix,
        test_envelope=test_envelope,
        test_commitment=test_commitment,
        report_payload=report_payload,
        signature=signature,
        trusted_public_key_pem=signer_public,
    )
    assert result["publishable"] is True
    assert result["system_count"] == 6
    assert result["private_event_count"] == 3
    assert result["registry_event_count"] == len(cases)
    assert result["visual_claim_count"] == len(event_ids)
    assert result["visual_region_count"] == len(event_ids)
    assert result["metric_coverage"]["minimum_events_per_metric"] == 5
    assert systems[REQUIRED_SYSTEMS[0]]["sample_counts"]["visual_regions"] == len(event_ids)

    wrong_denominator = copy.deepcopy(public_report)
    wrong_denominator["six_system_comparison"]["systems"][REQUIRED_SYSTEMS[0]]["sample_counts"][
        "sql"
    ] -= 1
    wrong_denominator_payload = _canonical(wrong_denominator)
    wrong_denominator_signature = sign_public_report(wrong_denominator_payload, signer_private)
    with pytest.raises(GovernanceError, match="invalid sample denominators"):
        validate_publication_release(
            frozen_gold=frozen_gold,
            iaa_report=iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload,
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=wrong_denominator_payload,
            signature=wrong_denominator_signature,
            trusted_public_key_pem=signer_public,
        )

    missing_interval = copy.deepcopy(public_report)
    missing_interval["six_system_comparison"]["systems"][REQUIRED_SYSTEMS[0]][
        "confidence_intervals"
    ]["intervals"].pop("mrr")
    missing_interval_payload = _canonical(missing_interval)
    missing_interval_signature = sign_public_report(missing_interval_payload, signer_private)
    with pytest.raises(GovernanceError, match="omit required per-event metrics"):
        validate_publication_release(
            frozen_gold=frozen_gold,
            iaa_report=iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload,
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=missing_interval_payload,
            signature=missing_interval_signature,
            trusted_public_key_pem=signer_public,
        )

    unscorable_visual = copy.deepcopy(public_report)
    unscorable_metrics = unscorable_visual["six_system_comparison"]["systems"][REQUIRED_SYSTEMS[0]][
        "metrics"
    ]
    for metric_name in (
        "region_visual_entailment",
        "region_visual_entailment_precision",
        "region_visual_entailment_coverage",
    ):
        unscorable_metrics[metric_name] = None
    unscorable_payload = _canonical(unscorable_visual)
    unscorable_signature = sign_public_report(unscorable_payload, signer_private)
    with pytest.raises(GovernanceError, match="no scorable region metric"):
        validate_publication_release(
            frozen_gold=frozen_gold,
            iaa_report=iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload,
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=unscorable_payload,
            signature=unscorable_signature,
            trusted_public_key_pem=signer_public,
        )

    tampered_iaa = copy.deepcopy(iaa)
    tampered_iaa["agreement"]["case_exact_agreement"] = 0.5
    tampered_gold = copy.deepcopy(frozen_gold)
    tampered_gold["annotation_protocol"]["iaa_report_sha256"] = _digest(tampered_iaa)
    with pytest.raises(GovernanceError, match="does not match recomputed"):
        validate_publication_release(
            frozen_gold=tampered_gold,
            iaa_report=tampered_iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload,
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=report_payload,
            signature=signature,
            trusted_public_key_pem=signer_public,
        )

    with pytest.raises(GovernanceError, match="exact corpus-lock bytes"):
        validate_publication_release(
            frozen_gold=frozen_gold,
            iaa_report=iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload + b"\n",
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=report_payload,
            signature=signature,
            trusted_public_key_pem=signer_public,
        )

    incomplete = copy.deepcopy(public_report)
    incomplete["six_system_comparison"]["systems"].pop("no_agentic_routing")
    incomplete_payload = _canonical(incomplete)
    incomplete_signature = sign_public_report(incomplete_payload, signer_private)
    with pytest.raises(GovernanceError, match="exactly all six"):
        validate_publication_release(
            frozen_gold=frozen_gold,
            iaa_report=iaa,
            annotation_batches=annotation_batches,
            private_holdouts=private_holdouts,
            private_manifests=private_manifests,
            registry_payload=registry_payload,
            corpus_lock_payload=corpus_lock_payload,
            experiment_matrix=matrix,
            test_envelope=test_envelope,
            test_commitment=test_commitment,
            report_payload=incomplete_payload,
            signature=incomplete_signature,
            trusted_public_key_pem=signer_public,
        )
