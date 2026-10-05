from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from scripts.validate_release_evidence import (
    BundleVerification,
    ReleaseEvidence,
    _verify_performance_report,
    validate_release,
    verify_release_bundle,
)

ARTIFACT_BYTES = b"independently-produced-release-artifact\n"
DIGEST = "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest()
CLAIM_NAMES = {
    "assessor.report",
    "artifact_images.api",
    "artifact_images.ui",
    "artifact_images.gateway",
    "artifact_images.malware",
    "configuration",
    "model_bundle",
    "postgresql.failover.report",
    "postgresql.restore.report",
    "object_storage.restore.report",
    "qdrant.latest_snapshot",
    "qdrant.restore.report",
    "security.dast_report",
    "security.malformed_media_report",
    "security.dependency_report",
    "identity.report",
    "platform.report",
    "load.report",
    "load.price_sheet",
    "load.hardware_profile",
    "analyst_pilot.report",
}


def _evidence(now: datetime) -> ReleaseEvidence:
    drill = {
        "executed_at": now - timedelta(days=1),
        "passed": True,
        "report_digest": DIGEST,
        "rpo_seconds": 10.0,
        "rto_seconds": 60.0,
    }
    payload = {
        "schema_version": 2,
        "environment_id": "staging-a",
        "generated_at": now,
        "assessor": "Independent Security Team",
        "assessor_report_url": "https://audit.example.test/report/1",
        "assessor_report_digest": DIGEST,
        "artifact_images": {
            "api": DIGEST,
            "ui": DIGEST,
            "gateway": DIGEST,
            "malware": DIGEST,
        },
        "configuration_digest": DIGEST,
        "model_bundle_digest": DIGEST,
        "postgresql": {
            "service": "managed-postgresql",
            "zones": ["zone-a", "zone-b"],
            "ready_replicas": 2,
            "tls_verify_full": True,
            "runtime_ddl_denied": True,
            "cross_tenant_rls_denied": True,
            "failover": drill,
            "restore": drill,
        },
        "object_storage": {
            "service": "managed-object-store",
            "source_region": "region-a",
            "replica_region": "region-b",
            "versioning_enabled": True,
            "replication_enabled": True,
            "encryption_enabled": True,
            "exact_version_delete_tested": True,
            "latest_replication_lag_seconds": 5.0,
            "restore": drill,
        },
        "qdrant": {
            "service": "managed-qdrant",
            "zones": ["zone-a", "zone-b"],
            "replication_factor": 2,
            "latest_snapshot_at": now,
            "latest_snapshot_digest": DIGEST,
            "snapshot_encrypted": True,
            "backup_replication_enabled": True,
            "restore": drill,
        },
        "security": {
            "executed_at": now,
            "dast_report_digest": DIGEST,
            "malformed_media_report_digest": DIGEST,
            "dependency_report_digest": DIGEST,
            "open_critical": 0,
            "open_high": 0,
            "parser_escape_succeeded": False,
            "prompt_injection_success_rate": 0.0,
        },
        "identity": {
            "executed_at": now,
            "report_digest": DIGEST,
            "oidc_login_passed": True,
            "invalid_issuer_denied": True,
            "expired_token_denied": True,
            "user_rbac_denied": True,
            "service_identity_rbac_denied": True,
            "cross_tenant_denied": True,
            "key_rotation_passed": True,
            "revoked_key_denied": True,
            "audit_chain_verified": True,
            "audit_retention_days": 365,
        },
        "load": {
            "executed_at": now,
            "measurement_started_at": now - timedelta(hours=2),
            "measurement_ended_at": now - timedelta(hours=1),
            "report_schema_version": 2,
            "profile_id": "gpu-a10-v1",
            "run_id": "run-00000001",
            "report_digest": DIGEST,
            "price_sheet_digest": DIGEST,
            "price_sheet_effective_at": now - timedelta(days=2),
            "hardware_profile_digest": DIGEST,
            "model_revisions": {
                "generator": "provider/model@immutable-revision",
                "reranker": "bge-reranker@immutable-revision",
            },
            "cost_bases": ["blended"],
            "currency": "USD",
            "accounting_complete": True,
            "zero_cost_operations": 0,
            "stage_latency": {
                stage: {
                    "samples": 1000,
                    "measurement_scope": (
                        "end_to_end" if stage in {"query", "ingestion"} else "core_operation"
                    ),
                    "p50_seconds": 1.0,
                    "p95_seconds": 8.0 if stage == "query" else 500.0,
                    "p99_seconds": 12.0 if stage == "query" else 700.0,
                }
                for stage in (
                    "ingestion",
                    "ocr",
                    "transcription",
                    "retrieval",
                    "reranking",
                    "llm_generation",
                    "query",
                )
            },
            "operation_cost": {
                "query": {
                    "operations": 1000,
                    "total_usd": 20.0,
                    "p50_usd": 0.01,
                    "p95_usd": 0.02,
                    "p99_usd": 0.03,
                },
                "document": {
                    "operations": 1000,
                    "total_usd": 30.0,
                    "p50_usd": 0.02,
                    "p95_usd": 0.03,
                    "p99_usd": 0.04,
                },
            },
            "operation_error_rate": 0.005,
            "peak_multiplier": 2.0,
        },
        "platform": {
            "executed_at": now,
            "report_digest": DIGEST,
            "orchestrator": "managed-kubernetes",
            "zones": ["zone-a", "zone-b"],
            "autoscaling_passed": True,
            "network_policy_enforced": True,
            "destination_egress_denied": True,
            "strict_mtls_passed": True,
            "plaintext_service_denied": True,
            "external_secret_sync_passed": True,
            "secret_rotation_rollout_passed": True,
            "otel_trace_delivery_passed": True,
            "prometheus_slo_series_passed": True,
            "alert_delivery_passed": True,
        },
        "analyst_pilot": {
            "executed_at": now,
            "completed": True,
            "report_digest": DIGEST,
            "analysts": 3,
            "tasks": 30,
            "median_time_change_percent": -25.0,
            "unsupported_claim_rate": 0.0,
            "severe_incidents": 0,
        },
        "artifact_bindings": {
            name: {
                "relative_path": f"artifacts/{name.replace('.', '/')}.bin",
                "digest": DIGEST,
                "size_bytes": len(ARTIFACT_BYTES),
            }
            for name in sorted(CLAIM_NAMES)
        },
    }
    return ReleaseEvidence.model_validate(payload)


def _performance_report(evidence: ReleaseEvidence) -> dict[str, Any]:
    stage_reports: dict[str, Any] = {}
    for stage, latency in evidence.load.stage_latency.items():
        p50 = latency.p50_seconds * 1000
        p95 = latency.p95_seconds * 1000
        p99 = latency.p99_seconds * 1000
        stage_reports[stage] = {
            "measurement_scope": latency.measurement_scope,
            "samples": latency.samples,
            "errors": 0,
            "error_rate": 0.0,
            "duration_ms": {
                "mean": p50,
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "min": p50,
                "max": p99,
            },
            "cost_usd_total": (
                evidence.load.operation_cost["query"].total_usd
                if stage == "query"
                else evidence.load.operation_cost["document"].total_usd
                if stage == "ingestion"
                else 0.0
            ),
            "input_tokens_total": 0,
            "output_tokens_total": 0,
            "input_bytes_total": 0,
        }
    cost_reports: dict[str, Any] = {}
    for operation, cost in evidence.load.operation_cost.items():
        cost_reports[operation] = {
            "operations": cost.operations,
            "total_usd": cost.total_usd,
            "per_operation_usd": {
                "mean": cost.p50_usd,
                "p50": cost.p50_usd,
                "p95": cost.p95_usd,
                "p99": cost.p99_usd,
                "min": cost.p50_usd,
                "max": cost.p99_usd,
            },
        }
    root_operations = sum(item.operations for item in evidence.load.operation_cost.values())
    operation_errors = round(evidence.load.operation_error_rate * root_operations)
    return {
        "schema_version": 2,
        "profile_id": evidence.load.profile_id,
        "run_id": evidence.load.run_id,
        "warmup_samples_excluded": 0,
        "measured_samples": sum(item.samples for item in evidence.load.stage_latency.values()),
        "measurement_started_at": evidence.load.measurement_started_at.isoformat(),
        "measurement_ended_at": evidence.load.measurement_ended_at.isoformat(),
        "operation_errors": operation_errors,
        "operation_error_rate": round(operation_errors / root_operations, 6),
        "stage_observation_errors": 0,
        "stage_observation_error_rate": 0.0,
        "accounting": {
            "status": "complete",
            "price_sheet_digest": evidence.load.price_sheet_digest,
            "price_sheet_effective_at": evidence.load.price_sheet_effective_at.isoformat(),
            "cost_bases": evidence.load.cost_bases,
            "zero_cost_operations": 0,
        },
        "measurement_contract": {
            "child_scope": "core_operation",
            "latency_population": "all_terminal_statuses",
            "minimum_tail_samples_per_stage": 1000,
            "percentile_method": "linear_interpolation",
            "root_scope": "end_to_end",
        },
        "stages": stage_reports,
        "cost": cost_reports,
    }


def _write_bound_artifacts(evidence: ReleaseEvidence, artifact_root: Path) -> None:
    performance_payload = json.dumps(
        _performance_report(evidence), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    performance_digest = "sha256:" + hashlib.sha256(performance_payload).hexdigest()
    evidence.load.report_digest = performance_digest
    performance_binding = evidence.artifact_bindings["load.report"]
    performance_binding.digest = performance_digest
    performance_binding.size_bytes = len(performance_payload)
    for name, binding in evidence.artifact_bindings.items():
        path = artifact_root.joinpath(*binding.relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(performance_payload if name == "load.report" else ARTIFACT_BYTES)


def _validate(evidence: ReleaseEvidence, now: datetime) -> list[str]:
    verification = BundleVerification(
        verified=True,
        algorithm="Ed25519",
        report_sha256=DIGEST,
        key_id=DIGEST,
        artifacts_verified=len(evidence.artifact_bindings),
    )
    return validate_release(
        evidence,
        bundle_verification=verification,
        now=now,
        max_evidence_age_days=30,
        max_drill_age_days=180,
        max_snapshot_age_hours=24,
        query_p95_limit_seconds=10.0,
        ingestion_p95_limit_seconds=600.0,
        error_rate_limit=0.01,
        injection_rate_limit=0.0,
    )


def test_complete_fresh_release_evidence_passes() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    assert _validate(_evidence(now), now) == []


def test_analyst_pilot_requires_a_real_predeclared_time_reduction() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.analyst_pilot.median_time_change_percent = 0.0

    assert _validate(evidence, now) == ["analyst_pilot.median_time_change_percent"]
    verification = BundleVerification(
        verified=True,
        algorithm="Ed25519",
        report_sha256=DIGEST,
        key_id=DIGEST,
        artifacts_verified=len(evidence.artifact_bindings),
    )
    with pytest.raises(ValueError, match="strictly positive time reduction"):
        validate_release(
            evidence,
            bundle_verification=verification,
            now=now,
            max_evidence_age_days=30,
            max_drill_age_days=180,
            max_snapshot_age_hours=24,
            query_p95_limit_seconds=10.0,
            ingestion_p95_limit_seconds=600.0,
            error_rate_limit=0.01,
            injection_rate_limit=0.0,
            pilot_time_change_limit_percent=0.0,
        )


def test_release_evidence_collects_independent_failures() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.generated_at = now - timedelta(days=31)
    evidence.security.open_high = 1
    evidence.security.prompt_injection_success_rate = 0.1
    evidence.postgresql.cross_tenant_rls_denied = False
    evidence.load.stage_latency["query"].p95_seconds = 11.0
    evidence.analyst_pilot.severe_incidents = 1
    assert _validate(evidence, now) == [
        "analyst_pilot.severe_incidents",
        "load.query_p95_seconds",
        "postgres.cross_tenant_rls_denied",
        "release_evidence.freshness",
        "security.open_high",
        "security.prompt_injection_success_rate",
    ]


def test_future_and_stale_drills_and_snapshots_fail() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.postgresql.failover.executed_at = now - timedelta(days=181)
    evidence.object_storage.restore.executed_at = now + timedelta(hours=1)
    evidence.qdrant.latest_snapshot_at = now - timedelta(hours=25)
    failures = _validate(evidence, now)
    assert "postgres.failover.freshness" in failures
    assert "object_storage.restore.freshness" in failures
    assert "qdrant.snapshot.freshness" in failures


def test_naive_timestamps_and_placeholder_digests_are_rejected() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    payload = _evidence(now).model_dump(mode="json")
    payload["security"]["executed_at"] = "2026-08-03T00:00:00"
    with pytest.raises(ValidationError):
        ReleaseEvidence.model_validate(payload)

    payload = _evidence(now).model_dump(mode="json")
    payload["security"]["dast_report_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError):
        ReleaseEvidence.model_validate(payload)


def test_stale_component_identity_and_accounting_fail_closed() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.security.executed_at = now - timedelta(days=31)
    evidence.identity.key_rotation_passed = False
    evidence.identity.audit_retention_days = 30
    evidence.load.accounting_complete = False
    evidence.object_storage.latest_replication_lag_seconds = 1000.0
    evidence.analyst_pilot.unsupported_claim_rate = 0.02
    assert _validate(evidence, now) == [
        "analyst_pilot.unsupported_claim_rate",
        "identity.audit_retention_days",
        "identity.key_rotation_passed",
        "load.accounting_complete",
        "object_storage.latest_replication_lag_seconds",
        "security.freshness",
    ]


def test_release_bundle_rehashes_every_artifact_and_verifies_ed25519(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    artifact_root = tmp_path / "immutable-artifacts"
    _write_bound_artifacts(evidence, artifact_root)

    evidence_payload = evidence.model_dump_json(indent=2).encode("utf-8")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
    signature_payload = json.dumps(
        {
            "schema_version": 1,
            "algorithm": "Ed25519",
            "report_sha256": "sha256:" + hashlib.sha256(evidence_payload).hexdigest(),
            "key_id": key_id,
            "signature": base64.b64encode(private_key.sign(evidence_payload)).decode("ascii"),
        }
    ).encode("utf-8")

    verified_evidence, verification = verify_release_bundle(
        evidence_payload,
        artifact_root=artifact_root,
        signature_payload=signature_payload,
        trusted_public_key_pem=public_pem,
        expected_signer_key_id=key_id,
    )
    assert verified_evidence == evidence
    assert verification.artifacts_verified == len(CLAIM_NAMES)
    assert (
        validate_release(
            verified_evidence,
            bundle_verification=verification,
            now=now,
            max_evidence_age_days=30,
            max_drill_age_days=180,
            max_snapshot_age_hours=24,
            query_p95_limit_seconds=10.0,
            ingestion_p95_limit_seconds=600.0,
            error_rate_limit=0.01,
            injection_rate_limit=0.0,
        )
        == []
    )

    first_binding = next(iter(evidence.artifact_bindings.values()))
    tampered_path = artifact_root.joinpath(*first_binding.relative_path.split("/"))
    tampered_path.write_bytes(b"x" * len(ARTIFACT_BYTES))
    with pytest.raises(ValueError, match="artifact bytes do not match"):
        verify_release_bundle(
            evidence_payload,
            artifact_root=artifact_root,
            signature_payload=signature_payload,
            trusted_public_key_pem=public_pem,
            expected_signer_key_id=key_id,
        )


def test_release_bundle_rejects_tampered_envelope_and_unpinned_signer(tmp_path: Path) -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    artifact_root = tmp_path / "artifacts"
    _write_bound_artifacts(evidence, artifact_root)
    payload = evidence.model_dump_json().encode("utf-8")
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key()
    public_pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
    signature = json.dumps(
        {
            "schema_version": 1,
            "algorithm": "Ed25519",
            "report_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "key_id": key_id,
            "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
        }
    ).encode("utf-8")
    with pytest.raises(ValueError, match="signed report digest"):
        verify_release_bundle(
            payload + b" ",
            artifact_root=artifact_root,
            signature_payload=signature,
            trusted_public_key_pem=public_pem,
            expected_signer_key_id=key_id,
        )
    with pytest.raises(ValueError, match="independently pinned key ID"):
        verify_release_bundle(
            payload,
            artifact_root=artifact_root,
            signature_payload=signature,
            trusted_public_key_pem=public_pem,
            expected_signer_key_id="sha256:" + "b" * 64,
        )


def test_release_schema_rejects_weak_tail_cost_scope_and_artifact_bindings() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    base = _evidence(now).model_dump(mode="json")
    changes = []

    weak_tail = json.loads(json.dumps(base))
    weak_tail["load"]["stage_latency"]["query"]["samples"] = 999
    changes.append(weak_tail)

    zero_cost = json.loads(json.dumps(base))
    zero_cost["load"]["operation_cost"]["query"]["p50_usd"] = 0.0
    changes.append(zero_cost)

    inconsistent_cost = json.loads(json.dumps(base))
    inconsistent_cost["load"]["operation_cost"]["query"]["total_usd"] = 1.0
    changes.append(inconsistent_cost)

    wrong_scope = json.loads(json.dumps(base))
    wrong_scope["load"]["stage_latency"]["query"]["measurement_scope"] = "core_operation"
    changes.append(wrong_scope)

    missing_binding = json.loads(json.dumps(base))
    missing_binding["artifact_bindings"].pop("load.report")
    changes.append(missing_binding)

    escaping_path = json.loads(json.dumps(base))
    escaping_path["artifact_bindings"]["load.report"]["relative_path"] = "../report.json"
    changes.append(escaping_path)

    for payload in changes:
        with pytest.raises(ValidationError):
            ReleaseEvidence.model_validate(payload)


def test_bound_performance_report_must_match_signed_load_claims(tmp_path: Path) -> None:
    evidence = _evidence(datetime(2026, 8, 3, tzinfo=UTC))
    report = _performance_report(evidence)
    report["stages"]["query"]["duration_ms"]["p95"] = 9_000.0
    path = tmp_path / "performance.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="signed load latency"):
        _verify_performance_report(evidence, path)


def test_live_platform_controls_are_mandatory_and_fresh() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.platform.destination_egress_denied = False
    evidence.platform.strict_mtls_passed = False
    evidence.platform.executed_at = now - timedelta(days=31)

    failures = _validate(evidence, now)
    assert "platform.destination_egress_denied" in failures
    assert "platform.strict_mtls_passed" in failures
    assert "platform.freshness" in failures


def test_future_price_sheet_and_incomplete_bundle_verification_fail() -> None:
    now = datetime(2026, 8, 3, tzinfo=UTC)
    evidence = _evidence(now)
    evidence.load.price_sheet_effective_at = now + timedelta(seconds=1)
    verification = BundleVerification(
        verified=True,
        algorithm="Ed25519",
        report_sha256=DIGEST,
        key_id=DIGEST,
        artifacts_verified=len(evidence.artifact_bindings) - 1,
    )
    failures = validate_release(
        evidence,
        bundle_verification=verification,
        now=now,
        max_evidence_age_days=30,
        max_drill_age_days=180,
        max_snapshot_age_hours=24,
        query_p95_limit_seconds=10.0,
        ingestion_p95_limit_seconds=600.0,
        error_rate_limit=0.01,
        injection_rate_limit=0.0,
    )
    assert failures == ["load.price_sheet_effective_at", "release_bundle.verification"]
