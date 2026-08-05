"""Validate independently produced staging evidence before production promotion."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
    field_validator,
    model_validator,
)

SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
PERFORMANCE_STAGES = {
    "ingestion",
    "ocr",
    "transcription",
    "retrieval",
    "reranking",
    "llm_generation",
    "query",
}
MINIMUM_RELEASE_TAIL_SAMPLES = 1_000
MAX_CONTROL_FILE_BYTES = 10 * 1024 * 1024
MAX_KEY_OR_SIGNATURE_BYTES = 64 * 1024


class StrictEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @model_validator(mode="after")
    def reject_placeholder_digests(self) -> StrictEvidence:
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            if "digest" in field_name and value == "sha256:" + "0" * 64:
                raise ValueError(f"{field_name} cannot be a placeholder digest")
            if (
                field_name == "artifact_images"
                and isinstance(value, dict)
                and any(item == "sha256:" + "0" * 64 for item in value.values())
            ):
                raise ValueError("artifact image digests cannot be placeholders")
        return self


class ArtifactBinding(StrictEvidence):
    """A signed claim binding one release field to bytes under an immutable artifact root."""

    relative_path: str = Field(min_length=1, max_length=512)
    digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=1, le=1_099_511_627_776)

    @field_validator("relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("artifact paths must use POSIX separators")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or value != path.as_posix()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("artifact path must be a normalized relative path")
        return value


class ReleaseSignature(StrictEvidence):
    schema_version: Literal[1]
    algorithm: Literal["Ed25519"]
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    key_id: str = Field(pattern=SHA256_PATTERN)
    signature: str = Field(min_length=80, max_length=128)

    @model_validator(mode="after")
    def reject_placeholder_hashes(self) -> ReleaseSignature:
        placeholder = "sha256:" + "0" * 64
        if self.report_sha256 == placeholder or self.key_id == placeholder:
            raise ValueError("signature hashes cannot be placeholders")
        return self


class BundleVerification(StrictEvidence):
    verified: Literal[True]
    algorithm: Literal["Ed25519"]
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    key_id: str = Field(pattern=SHA256_PATTERN)
    artifacts_verified: int = Field(ge=1, le=10_000)


class Drill(StrictEvidence):
    executed_at: AwareDatetime
    passed: bool
    report_digest: str = Field(pattern=SHA256_PATTERN)
    rpo_seconds: float = Field(ge=0.0, le=604_800.0)
    rto_seconds: float = Field(ge=0.0, le=604_800.0)


class PostgreSQLEvidence(StrictEvidence):
    service: str = Field(min_length=3, max_length=128)
    zones: list[str] = Field(min_length=2, max_length=32)
    ready_replicas: int = Field(ge=2, le=100)
    tls_verify_full: bool
    runtime_ddl_denied: bool
    cross_tenant_rls_denied: bool
    failover: Drill
    restore: Drill

    @model_validator(mode="after")
    def distinct_zones(self) -> PostgreSQLEvidence:
        if len(set(self.zones)) != len(self.zones):
            raise ValueError("PostgreSQL zones must be distinct")
        return self


class ObjectStorageEvidence(StrictEvidence):
    service: str = Field(min_length=3, max_length=128)
    source_region: str = Field(min_length=2, max_length=64)
    replica_region: str = Field(min_length=2, max_length=64)
    versioning_enabled: bool
    replication_enabled: bool
    encryption_enabled: bool
    exact_version_delete_tested: bool
    latest_replication_lag_seconds: float = Field(ge=0.0, le=604_800.0)
    restore: Drill

    @model_validator(mode="after")
    def distinct_regions(self) -> ObjectStorageEvidence:
        if self.source_region == self.replica_region:
            raise ValueError("object storage replica must use a distinct region")
        return self


class QdrantEvidence(StrictEvidence):
    service: str = Field(min_length=3, max_length=128)
    zones: list[str] = Field(min_length=2, max_length=32)
    replication_factor: int = Field(ge=2, le=100)
    latest_snapshot_at: AwareDatetime
    latest_snapshot_digest: str = Field(pattern=SHA256_PATTERN)
    snapshot_encrypted: bool
    backup_replication_enabled: bool
    restore: Drill

    @model_validator(mode="after")
    def distinct_zones(self) -> QdrantEvidence:
        if len(set(self.zones)) != len(self.zones):
            raise ValueError("Qdrant zones must be distinct")
        return self


class SecurityEvidence(StrictEvidence):
    executed_at: AwareDatetime
    dast_report_digest: str = Field(pattern=SHA256_PATTERN)
    malformed_media_report_digest: str = Field(pattern=SHA256_PATTERN)
    dependency_report_digest: str = Field(pattern=SHA256_PATTERN)
    open_critical: int = Field(ge=0)
    open_high: int = Field(ge=0)
    parser_escape_succeeded: bool
    prompt_injection_success_rate: float = Field(ge=0.0, le=1.0)


class LatencyEvidence(StrictEvidence):
    samples: int = Field(ge=MINIMUM_RELEASE_TAIL_SAMPLES, le=10_000_000)
    measurement_scope: Literal["end_to_end", "core_operation"]
    p50_seconds: float = Field(gt=0.0, le=86_400.0)
    p95_seconds: float = Field(gt=0.0, le=86_400.0)
    p99_seconds: float = Field(gt=0.0, le=86_400.0)

    @model_validator(mode="after")
    def ordered_percentiles(self) -> LatencyEvidence:
        if not self.p50_seconds <= self.p95_seconds <= self.p99_seconds:
            raise ValueError("latency percentiles must be ordered p50 <= p95 <= p99")
        return self


class CostEvidence(StrictEvidence):
    operations: int = Field(ge=MINIMUM_RELEASE_TAIL_SAMPLES, le=10_000_000)
    total_usd: float = Field(gt=0.0, le=1_000_000_000.0)
    p50_usd: float = Field(gt=0.0, le=1_000_000.0)
    p95_usd: float = Field(gt=0.0, le=1_000_000.0)
    p99_usd: float = Field(gt=0.0, le=1_000_000.0)

    @model_validator(mode="after")
    def ordered_percentiles(self) -> CostEvidence:
        if not self.p50_usd <= self.p95_usd <= self.p99_usd:
            raise ValueError("cost percentiles must be ordered p50 <= p95 <= p99")
        minimum_implied_total = max(
            self.operations * self.p50_usd * 0.5,
            self.operations * self.p95_usd * 0.05,
            self.operations * self.p99_usd * 0.01,
        )
        if self.total_usd < minimum_implied_total:
            raise ValueError("total cost is inconsistent with its percentile distribution")
        return self


class LoadEvidence(StrictEvidence):
    executed_at: AwareDatetime
    measurement_started_at: AwareDatetime
    measurement_ended_at: AwareDatetime
    report_schema_version: Literal[2]
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    report_digest: str = Field(pattern=SHA256_PATTERN)
    price_sheet_digest: str = Field(pattern=SHA256_PATTERN)
    price_sheet_effective_at: AwareDatetime
    hardware_profile_digest: str = Field(pattern=SHA256_PATTERN)
    model_revisions: dict[str, str] = Field(min_length=1, max_length=32)
    cost_bases: list[Literal["provider_usage", "allocated_compute", "blended"]] = Field(
        min_length=1, max_length=3
    )
    currency: Literal["USD"]
    accounting_complete: bool
    zero_cost_operations: Literal[0]
    stage_latency: dict[str, LatencyEvidence] = Field(min_length=7, max_length=7)
    operation_cost: dict[str, CostEvidence] = Field(min_length=2, max_length=2)
    operation_error_rate: float = Field(ge=0.0, le=1.0)
    peak_multiplier: float = Field(ge=2.0, le=100.0)

    @model_validator(mode="after")
    def complete_dimensions(self) -> LoadEvidence:
        if not self.measurement_started_at <= self.measurement_ended_at <= self.executed_at:
            raise ValueError("load measurement and report timestamps must be ordered")
        if self.measurement_ended_at - self.measurement_started_at > timedelta(days=7):
            raise ValueError("one load evidence run cannot span more than seven days")
        if set(self.stage_latency) != PERFORMANCE_STAGES:
            raise ValueError("load evidence must contain every required pipeline stage")
        if set(self.operation_cost) != {"query", "document"}:
            raise ValueError("load evidence must contain query and document cost")
        for stage, latency in self.stage_latency.items():
            expected_scope = "end_to_end" if stage in {"query", "ingestion"} else "core_operation"
            if latency.measurement_scope != expected_scope:
                raise ValueError(f"load stage {stage} must use {expected_scope} scope")
        if len(set(self.cost_bases)) != len(self.cost_bases):
            raise ValueError("load cost bases must be unique")
        if any(
            not name.strip() or not revision.strip() or len(name) > 128 or len(revision) > 256
            for name, revision in self.model_revisions.items()
        ):
            raise ValueError("model revision bindings must be non-empty and bounded")
        return self


class PerformanceDistribution(StrictEvidence):
    mean: float = Field(ge=0.0)
    p50: float = Field(ge=0.0)
    p95: float = Field(ge=0.0)
    p99: float = Field(ge=0.0)
    min: float = Field(ge=0.0)
    max: float = Field(ge=0.0)

    @model_validator(mode="after")
    def ordered_values(self) -> PerformanceDistribution:
        values = (self.mean, self.p50, self.p95, self.p99, self.min, self.max)
        if not all(math.isfinite(value) for value in values):
            raise ValueError("performance distribution values must be finite")
        if not self.min <= self.p50 <= self.p95 <= self.p99 <= self.max:
            raise ValueError("performance distribution percentiles are inconsistent")
        return self


class PerformanceStageReport(StrictEvidence):
    measurement_scope: Literal["end_to_end", "core_operation"]
    samples: int = Field(ge=MINIMUM_RELEASE_TAIL_SAMPLES, le=10_000_000)
    errors: int = Field(ge=0, le=10_000_000)
    error_rate: float = Field(ge=0.0, le=1.0)
    duration_ms: PerformanceDistribution
    cost_usd_total: float = Field(ge=0.0, le=1_000_000_000.0)
    input_tokens_total: int = Field(ge=0, le=100_000_000_000)
    output_tokens_total: int = Field(ge=0, le=100_000_000_000)
    input_bytes_total: int = Field(ge=0, le=1_099_511_627_776_000)

    @model_validator(mode="after")
    def error_rate_matches_count(self) -> PerformanceStageReport:
        expected = round(self.errors / self.samples, 6)
        if not math.isclose(self.error_rate, expected, rel_tol=0.0, abs_tol=1e-9):
            raise ValueError("stage error rate does not match its counts")
        return self


class PerformanceCostReport(StrictEvidence):
    operations: int = Field(ge=MINIMUM_RELEASE_TAIL_SAMPLES, le=10_000_000)
    total_usd: float = Field(gt=0.0, le=1_000_000_000.0)
    per_operation_usd: PerformanceDistribution


class PerformanceAccounting(StrictEvidence):
    status: Literal["complete"]
    price_sheet_digest: str = Field(pattern=SHA256_PATTERN)
    price_sheet_effective_at: AwareDatetime
    cost_bases: list[Literal["provider_usage", "allocated_compute", "blended"]] = Field(
        min_length=1, max_length=3
    )
    zero_cost_operations: Literal[0]


class PerformanceMeasurementContract(StrictEvidence):
    child_scope: Literal["core_operation"]
    latency_population: Literal["all_terminal_statuses"]
    minimum_tail_samples_per_stage: int = Field(ge=MINIMUM_RELEASE_TAIL_SAMPLES)
    percentile_method: Literal["linear_interpolation"]
    root_scope: Literal["end_to_end"]


class PerformanceReport(StrictEvidence):
    schema_version: Literal[2]
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    warmup_samples_excluded: int = Field(ge=0, le=10_000_000)
    measured_samples: int = Field(ge=1, le=100_000_000)
    measurement_started_at: AwareDatetime
    measurement_ended_at: AwareDatetime
    operation_errors: int = Field(ge=0, le=10_000_000)
    operation_error_rate: float = Field(ge=0.0, le=1.0)
    stage_observation_errors: int = Field(ge=0, le=100_000_000)
    stage_observation_error_rate: float = Field(ge=0.0, le=1.0)
    accounting: PerformanceAccounting
    measurement_contract: PerformanceMeasurementContract
    stages: dict[str, PerformanceStageReport] = Field(min_length=7, max_length=7)
    cost: dict[str, PerformanceCostReport] = Field(min_length=2, max_length=2)
    slo: dict[str, Any] | None = None

    @model_validator(mode="after")
    def complete_report(self) -> PerformanceReport:
        if set(self.stages) != PERFORMANCE_STAGES:
            raise ValueError("performance report must contain every required stage")
        if set(self.cost) != {"query", "document"}:
            raise ValueError("performance report must contain both operation cost classes")
        if self.measurement_started_at > self.measurement_ended_at:
            raise ValueError("performance report measurement window is reversed")
        root_operations = sum(item.operations for item in self.cost.values())
        expected_error_rate = round(self.operation_errors / root_operations, 6)
        if not math.isclose(
            self.operation_error_rate, expected_error_rate, rel_tol=0.0, abs_tol=1e-9
        ):
            raise ValueError("operation error rate does not match its counts")
        expected_stage_errors = sum(item.errors for item in self.stages.values())
        if self.stage_observation_errors != expected_stage_errors:
            raise ValueError("stage error count is inconsistent")
        if self.measured_samples != sum(item.samples for item in self.stages.values()):
            raise ValueError("measured sample count is inconsistent")
        for stage, operation in (("query", "query"), ("ingestion", "document")):
            stage_report = self.stages[stage]
            cost_report = self.cost[operation]
            if stage_report.samples != cost_report.operations or not math.isclose(
                stage_report.cost_usd_total,
                cost_report.total_usd,
                rel_tol=1e-9,
                abs_tol=1e-9,
            ):
                raise ValueError("root stage and operation cost totals are inconsistent")
        expected_stage_rate = round(self.stage_observation_errors / self.measured_samples, 6)
        if not math.isclose(
            self.stage_observation_error_rate,
            expected_stage_rate,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            raise ValueError("stage observation error rate does not match its counts")
        return self


class AnalystPilotEvidence(StrictEvidence):
    executed_at: AwareDatetime
    completed: bool
    report_digest: str = Field(pattern=SHA256_PATTERN)
    analysts: int = Field(ge=2, le=10_000)
    tasks: int = Field(ge=20, le=1_000_000)
    median_time_change_percent: float = Field(ge=-100.0, le=1000.0)
    unsupported_claim_rate: float = Field(ge=0.0, le=1.0)
    severe_incidents: int = Field(ge=0)


class IdentityEvidence(StrictEvidence):
    executed_at: AwareDatetime
    report_digest: str = Field(pattern=SHA256_PATTERN)
    oidc_login_passed: bool
    invalid_issuer_denied: bool
    expired_token_denied: bool
    user_rbac_denied: bool
    service_identity_rbac_denied: bool
    cross_tenant_denied: bool
    key_rotation_passed: bool
    revoked_key_denied: bool
    audit_chain_verified: bool
    audit_retention_days: int = Field(ge=1, le=3650)


class PlatformEvidence(StrictEvidence):
    executed_at: AwareDatetime
    report_digest: str = Field(pattern=SHA256_PATTERN)
    orchestrator: str = Field(min_length=3, max_length=128)
    zones: list[str] = Field(min_length=2, max_length=32)
    autoscaling_passed: bool
    network_policy_enforced: bool
    destination_egress_denied: bool
    strict_mtls_passed: bool
    plaintext_service_denied: bool
    external_secret_sync_passed: bool
    secret_rotation_rollout_passed: bool
    otel_trace_delivery_passed: bool
    prometheus_slo_series_passed: bool
    alert_delivery_passed: bool

    @model_validator(mode="after")
    def distinct_zones(self) -> PlatformEvidence:
        if len(set(self.zones)) != len(self.zones):
            raise ValueError("platform zones must be distinct")
        return self


class ReleaseEvidence(StrictEvidence):
    schema_version: Literal[2]
    environment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    generated_at: AwareDatetime
    assessor: str = Field(min_length=3, max_length=200)
    assessor_report_url: HttpUrl
    assessor_report_digest: str = Field(pattern=SHA256_PATTERN)
    artifact_images: dict[str, str] = Field(min_length=4, max_length=32)
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    model_bundle_digest: str = Field(pattern=SHA256_PATTERN)
    postgresql: PostgreSQLEvidence
    object_storage: ObjectStorageEvidence
    qdrant: QdrantEvidence
    security: SecurityEvidence
    identity: IdentityEvidence
    platform: PlatformEvidence
    load: LoadEvidence
    analyst_pilot: AnalystPilotEvidence
    artifact_bindings: dict[str, ArtifactBinding] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def artifact_names_and_digests(self) -> ReleaseEvidence:
        required = {"api", "ui", "gateway", "malware"}
        if not required <= set(self.artifact_images):
            raise ValueError("release evidence is missing a required image")
        if any(
            not name.replace("-", "").replace("_", "").isalnum()
            or not re.fullmatch(SHA256_PATTERN, digest)
            for name, digest in self.artifact_images.items()
        ):
            raise ValueError("release image bindings are malformed")
        claimed = claimed_artifact_digests(self)
        if set(self.artifact_bindings) != set(claimed):
            missing = sorted(set(claimed) - set(self.artifact_bindings))
            extra = sorted(set(self.artifact_bindings) - set(claimed))
            detail = missing[0] if missing else extra[0]
            raise ValueError(f"release artifact binding set is incomplete or unknown: {detail}")
        paths = [binding.relative_path for binding in self.artifact_bindings.values()]
        if len(paths) != len(set(paths)):
            raise ValueError("release artifact binding paths must be unique")
        for name, digest in claimed.items():
            if self.artifact_bindings[name].digest != digest:
                raise ValueError(f"release artifact digest does not match claim: {name}")
        return self


def claimed_artifact_digests(evidence: ReleaseEvidence) -> dict[str, str]:
    """Return every release digest that must be re-derived from supplied artifact bytes."""

    claims = {
        f"artifact_images.{name}": digest for name, digest in evidence.artifact_images.items()
    }
    claims.update(
        {
            "assessor.report": evidence.assessor_report_digest,
            "configuration": evidence.configuration_digest,
            "model_bundle": evidence.model_bundle_digest,
            "postgresql.failover.report": evidence.postgresql.failover.report_digest,
            "postgresql.restore.report": evidence.postgresql.restore.report_digest,
            "object_storage.restore.report": evidence.object_storage.restore.report_digest,
            "qdrant.latest_snapshot": evidence.qdrant.latest_snapshot_digest,
            "qdrant.restore.report": evidence.qdrant.restore.report_digest,
            "security.dast_report": evidence.security.dast_report_digest,
            "security.malformed_media_report": evidence.security.malformed_media_report_digest,
            "security.dependency_report": evidence.security.dependency_report_digest,
            "identity.report": evidence.identity.report_digest,
            "platform.report": evidence.platform.report_digest,
            "load.report": evidence.load.report_digest,
            "load.price_sheet": evidence.load.price_sheet_digest,
            "load.hardware_profile": evidence.load.hardware_profile_digest,
            "analyst_pilot.report": evidence.analyst_pilot.report_digest,
        }
    )
    return claims


def _sha256_prefixed(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_bounded(path: Path, *, label: str, limit: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat {label}") from exc
    if size < 1 or size > limit:
        raise ValueError(f"{label} size is outside the allowed range")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {label}") from exc
    if len(payload) != size:
        raise ValueError(f"{label} changed while it was read")
    return payload


def _verify_artifact(root: Path, name: str, binding: ArtifactBinding) -> Path:
    relative = PurePosixPath(binding.relative_path)
    try:
        candidate = root.joinpath(*relative.parts).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"artifact path is missing or escapes the artifact root: {name}") from exc
    try:
        with candidate.open("rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"artifact is not a regular file: {name}")
            if before.st_size != binding.size_bytes:
                raise ValueError(f"artifact size does not match its signed binding: {name}")
            hasher = hashlib.sha256()
            while block := source.read(1024 * 1024):
                hasher.update(block)
            after = os.fstat(source.fileno())
    except OSError as exc:
        raise ValueError(f"cannot read release artifact: {name}") from exc
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_identity != after_identity:
        raise ValueError(f"artifact changed while it was hashed: {name}")
    actual_digest = "sha256:" + hasher.hexdigest()
    if actual_digest != binding.digest:
        raise ValueError(f"artifact bytes do not match their signed digest: {name}")
    return candidate


def _same_number(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-9)


def _verify_performance_report(evidence: ReleaseEvidence, path: Path) -> None:
    payload = _read_bounded(path, label="performance report", limit=MAX_CONTROL_FILE_BYTES)
    report = PerformanceReport.model_validate_json(payload)
    load = evidence.load
    if (
        report.schema_version != load.report_schema_version
        or report.profile_id != load.profile_id
        or report.run_id != load.run_id
        or report.measurement_started_at != load.measurement_started_at
        or report.measurement_ended_at != load.measurement_ended_at
        or report.accounting.price_sheet_digest != load.price_sheet_digest
        or report.accounting.price_sheet_effective_at != load.price_sheet_effective_at
        or set(report.accounting.cost_bases) != set(load.cost_bases)
        or report.accounting.zero_cost_operations != load.zero_cost_operations
        or not _same_number(report.operation_error_rate, load.operation_error_rate)
    ):
        raise ValueError("signed load claims do not match the bound performance report")
    for stage, claimed in load.stage_latency.items():
        measured = report.stages[stage]
        duration = measured.duration_ms
        if (
            measured.samples != claimed.samples
            or measured.measurement_scope != claimed.measurement_scope
            or not _same_number(duration.p50 / 1000, claimed.p50_seconds)
            or not _same_number(duration.p95 / 1000, claimed.p95_seconds)
            or not _same_number(duration.p99 / 1000, claimed.p99_seconds)
        ):
            raise ValueError(f"signed load latency does not match performance report: {stage}")
    for operation, cost_claim in load.operation_cost.items():
        cost_measured = report.cost[operation]
        distribution = cost_measured.per_operation_usd
        if (
            cost_measured.operations != cost_claim.operations
            or not _same_number(cost_measured.total_usd, cost_claim.total_usd)
            or not _same_number(distribution.p50, cost_claim.p50_usd)
            or not _same_number(distribution.p95, cost_claim.p95_usd)
            or not _same_number(distribution.p99, cost_claim.p99_usd)
        ):
            raise ValueError(f"signed load cost does not match performance report: {operation}")


def verify_release_bundle(
    evidence_payload: bytes,
    *,
    artifact_root: Path,
    signature_payload: bytes,
    trusted_public_key_pem: bytes,
    expected_signer_key_id: str,
) -> tuple[ReleaseEvidence, BundleVerification]:
    """Verify exact envelope bytes, an externally pinned signer, and every artifact byte claim."""

    evidence = ReleaseEvidence.model_validate_json(evidence_payload)
    signature = ReleaseSignature.model_validate_json(signature_payload)
    if not re.fullmatch(SHA256_PATTERN, expected_signer_key_id):
        raise ValueError("expected signer key ID is malformed")
    try:
        public_key = serialization.load_pem_public_key(trusted_public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ValueError("trusted release verification key is not valid PEM") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("trusted release verification key must be Ed25519")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = _sha256_prefixed(public_der)
    if key_id != expected_signer_key_id or signature.key_id != expected_signer_key_id:
        raise ValueError("release signer key does not match the independently pinned key ID")
    report_digest = _sha256_prefixed(evidence_payload)
    if signature.report_sha256 != report_digest:
        raise ValueError("release evidence bytes do not match the signed report digest")
    try:
        signature_bytes = base64.b64decode(signature.signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("release signature is not valid base64") from exc
    if len(signature_bytes) != 64:
        raise ValueError("release signature has an invalid length")
    try:
        public_key.verify(signature_bytes, evidence_payload)
    except InvalidSignature as exc:
        raise ValueError("release evidence signature verification failed") from exc

    try:
        resolved_root = artifact_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("artifact root does not exist") from exc
    if not resolved_root.is_dir():
        raise ValueError("artifact root must be a directory")
    resolved_artifacts: set[Path] = set()
    resolved_artifacts_by_name: dict[str, Path] = {}
    for name, binding in sorted(evidence.artifact_bindings.items()):
        resolved_artifact = _verify_artifact(resolved_root, name, binding)
        if resolved_artifact in resolved_artifacts:
            raise ValueError(f"multiple claims resolve to the same artifact file: {name}")
        resolved_artifacts.add(resolved_artifact)
        resolved_artifacts_by_name[name] = resolved_artifact
    _verify_performance_report(evidence, resolved_artifacts_by_name["load.report"])
    verification = BundleVerification(
        verified=True,
        algorithm="Ed25519",
        report_sha256=report_digest,
        key_id=key_id,
        artifacts_verified=len(evidence.artifact_bindings),
    )
    return evidence, verification


def validate_release(
    evidence: ReleaseEvidence,
    *,
    bundle_verification: BundleVerification,
    now: datetime,
    max_evidence_age_days: int,
    max_drill_age_days: int,
    max_snapshot_age_hours: int,
    query_p95_limit_seconds: float,
    ingestion_p95_limit_seconds: float,
    error_rate_limit: float,
    injection_rate_limit: float,
    query_p99_limit_seconds: float = 20.0,
    ingestion_p99_limit_seconds: float = 1200.0,
    max_replication_lag_seconds: float = 900.0,
    max_drill_rpo_seconds: float = 3600.0,
    max_drill_rto_seconds: float = 7200.0,
    minimum_audit_retention_days: int = 365,
    pilot_unsupported_claim_rate_limit: float = 0.01,
    pilot_time_change_limit_percent: float = -1.0,
) -> list[str]:
    if now.tzinfo is None:
        raise ValueError("validation time must be timezone-aware")
    now = now.astimezone(UTC)
    positive_limits = (
        max_evidence_age_days,
        max_drill_age_days,
        max_snapshot_age_hours,
        query_p95_limit_seconds,
        ingestion_p95_limit_seconds,
        query_p99_limit_seconds,
        ingestion_p99_limit_seconds,
        max_replication_lag_seconds,
        max_drill_rpo_seconds,
        max_drill_rto_seconds,
        minimum_audit_retention_days,
    )
    if any(not math.isfinite(float(value)) or value <= 0 for value in positive_limits):
        raise ValueError("release policy limits must be finite and positive")
    if any(
        not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in (error_rate_limit, injection_rate_limit, pilot_unsupported_claim_rate_limit)
    ):
        raise ValueError("release rate limits must be finite and between zero and one")
    if (
        not math.isfinite(pilot_time_change_limit_percent)
        or not -100.0 <= pilot_time_change_limit_percent < 0.0
    ):
        raise ValueError(
            "pilot time-change limit must require a finite, strictly positive time reduction"
        )
    failures: list[str] = []

    if not bundle_verification.verified or bundle_verification.artifacts_verified != len(
        evidence.artifact_bindings
    ):
        failures.append("release_bundle.verification")

    def stale(name: str, timestamp: datetime, age: timedelta) -> None:
        normalized = timestamp.astimezone(UTC)
        if normalized > now + timedelta(minutes=5) or now - normalized > age:
            failures.append(f"{name}.freshness")

    stale("release_evidence", evidence.generated_at, timedelta(days=max_evidence_age_days))
    stale("security", evidence.security.executed_at, timedelta(days=max_evidence_age_days))
    stale("identity", evidence.identity.executed_at, timedelta(days=max_evidence_age_days))
    stale("platform", evidence.platform.executed_at, timedelta(days=max_evidence_age_days))
    stale("load", evidence.load.executed_at, timedelta(days=max_evidence_age_days))
    if evidence.load.price_sheet_effective_at > evidence.load.executed_at:
        failures.append("load.price_sheet_effective_at")
    stale(
        "analyst_pilot",
        evidence.analyst_pilot.executed_at,
        timedelta(days=max_evidence_age_days),
    )
    for name, drill in (
        ("postgres.failover", evidence.postgresql.failover),
        ("postgres.restore", evidence.postgresql.restore),
        ("object_storage.restore", evidence.object_storage.restore),
        ("qdrant.restore", evidence.qdrant.restore),
    ):
        stale(name, drill.executed_at, timedelta(days=max_drill_age_days))
        if not drill.passed:
            failures.append(f"{name}.passed")
        if drill.rpo_seconds > max_drill_rpo_seconds:
            failures.append(f"{name}.rpo_seconds")
        if drill.rto_seconds > max_drill_rto_seconds:
            failures.append(f"{name}.rto_seconds")
    stale(
        "qdrant.snapshot",
        evidence.qdrant.latest_snapshot_at,
        timedelta(hours=max_snapshot_age_hours),
    )
    boolean_controls = {
        "postgres.tls_verify_full": evidence.postgresql.tls_verify_full,
        "postgres.runtime_ddl_denied": evidence.postgresql.runtime_ddl_denied,
        "postgres.cross_tenant_rls_denied": evidence.postgresql.cross_tenant_rls_denied,
        "object_storage.versioning_enabled": evidence.object_storage.versioning_enabled,
        "object_storage.replication_enabled": evidence.object_storage.replication_enabled,
        "object_storage.encryption_enabled": evidence.object_storage.encryption_enabled,
        "object_storage.exact_version_delete_tested": (
            evidence.object_storage.exact_version_delete_tested
        ),
        "qdrant.snapshot_encrypted": evidence.qdrant.snapshot_encrypted,
        "qdrant.backup_replication_enabled": evidence.qdrant.backup_replication_enabled,
        "security.parser_escape": not evidence.security.parser_escape_succeeded,
        "identity.oidc_login_passed": evidence.identity.oidc_login_passed,
        "identity.invalid_issuer_denied": evidence.identity.invalid_issuer_denied,
        "identity.expired_token_denied": evidence.identity.expired_token_denied,
        "identity.user_rbac_denied": evidence.identity.user_rbac_denied,
        "identity.service_identity_rbac_denied": evidence.identity.service_identity_rbac_denied,
        "identity.cross_tenant_denied": evidence.identity.cross_tenant_denied,
        "identity.key_rotation_passed": evidence.identity.key_rotation_passed,
        "identity.revoked_key_denied": evidence.identity.revoked_key_denied,
        "identity.audit_chain_verified": evidence.identity.audit_chain_verified,
        "platform.autoscaling_passed": evidence.platform.autoscaling_passed,
        "platform.network_policy_enforced": evidence.platform.network_policy_enforced,
        "platform.destination_egress_denied": evidence.platform.destination_egress_denied,
        "platform.strict_mtls_passed": evidence.platform.strict_mtls_passed,
        "platform.plaintext_service_denied": evidence.platform.plaintext_service_denied,
        "platform.external_secret_sync_passed": evidence.platform.external_secret_sync_passed,
        "platform.secret_rotation_rollout_passed": (
            evidence.platform.secret_rotation_rollout_passed
        ),
        "platform.otel_trace_delivery_passed": evidence.platform.otel_trace_delivery_passed,
        "platform.prometheus_slo_series_passed": (evidence.platform.prometheus_slo_series_passed),
        "platform.alert_delivery_passed": evidence.platform.alert_delivery_passed,
        "load.accounting_complete": evidence.load.accounting_complete,
        "analyst_pilot.completed": evidence.analyst_pilot.completed,
    }
    failures.extend(name for name, passed in boolean_controls.items() if not passed)
    if evidence.security.open_critical:
        failures.append("security.open_critical")
    if evidence.security.open_high:
        failures.append("security.open_high")
    if evidence.security.prompt_injection_success_rate > injection_rate_limit:
        failures.append("security.prompt_injection_success_rate")
    if evidence.object_storage.latest_replication_lag_seconds > max_replication_lag_seconds:
        failures.append("object_storage.latest_replication_lag_seconds")
    if evidence.load.stage_latency["query"].p95_seconds > query_p95_limit_seconds:
        failures.append("load.query_p95_seconds")
    if evidence.load.stage_latency["query"].p99_seconds > query_p99_limit_seconds:
        failures.append("load.query_p99_seconds")
    if evidence.load.stage_latency["ingestion"].p95_seconds > ingestion_p95_limit_seconds:
        failures.append("load.ingestion_p95_seconds")
    if evidence.load.stage_latency["ingestion"].p99_seconds > ingestion_p99_limit_seconds:
        failures.append("load.ingestion_p99_seconds")
    if evidence.load.operation_error_rate > error_rate_limit:
        failures.append("load.operation_error_rate")
    if evidence.analyst_pilot.severe_incidents:
        failures.append("analyst_pilot.severe_incidents")
    if evidence.analyst_pilot.unsupported_claim_rate > pilot_unsupported_claim_rate_limit:
        failures.append("analyst_pilot.unsupported_claim_rate")
    if evidence.analyst_pilot.median_time_change_percent > pilot_time_change_limit_percent:
        failures.append("analyst_pilot.median_time_change_percent")
    if evidence.identity.audit_retention_days < minimum_audit_retention_days:
        failures.append("identity.audit_retention_days")
    return sorted(set(failures))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    parser.add_argument("--expected-signer-key-id", required=True)
    parser.add_argument("--max-evidence-age-days", type=int, default=30)
    parser.add_argument("--max-drill-age-days", type=int, default=180)
    parser.add_argument("--max-snapshot-age-hours", type=int, default=24)
    parser.add_argument("--query-p95-limit-seconds", type=float, default=10.0)
    parser.add_argument("--ingestion-p95-limit-seconds", type=float, default=600.0)
    parser.add_argument("--error-rate-limit", type=float, default=0.01)
    parser.add_argument("--injection-rate-limit", type=float, default=0.0)
    parser.add_argument("--query-p99-limit-seconds", type=float, default=20.0)
    parser.add_argument("--ingestion-p99-limit-seconds", type=float, default=1200.0)
    parser.add_argument("--max-replication-lag-seconds", type=float, default=900.0)
    parser.add_argument("--max-drill-rpo-seconds", type=float, default=3600.0)
    parser.add_argument("--max-drill-rto-seconds", type=float, default=7200.0)
    parser.add_argument("--minimum-audit-retention-days", type=int, default=365)
    parser.add_argument("--pilot-unsupported-claim-rate-limit", type=float, default=0.01)
    parser.add_argument("--pilot-time-change-limit-percent", type=float, default=-1.0)
    args = parser.parse_args()
    try:
        evidence_payload = _read_bounded(
            args.evidence,
            label="release evidence",
            limit=MAX_CONTROL_FILE_BYTES,
        )
        signature_payload = _read_bounded(
            args.signature,
            label="release signature",
            limit=MAX_KEY_OR_SIGNATURE_BYTES,
        )
        trusted_public_key = _read_bounded(
            args.trusted_public_key,
            label="trusted public key",
            limit=MAX_KEY_OR_SIGNATURE_BYTES,
        )
        evidence, verification = verify_release_bundle(
            evidence_payload,
            artifact_root=args.artifact_root,
            signature_payload=signature_payload,
            trusted_public_key_pem=trusted_public_key,
            expected_signer_key_id=args.expected_signer_key_id,
        )
        failures = validate_release(
            evidence,
            bundle_verification=verification,
            now=datetime.now(UTC),
            max_evidence_age_days=args.max_evidence_age_days,
            max_drill_age_days=args.max_drill_age_days,
            max_snapshot_age_hours=args.max_snapshot_age_hours,
            query_p95_limit_seconds=args.query_p95_limit_seconds,
            ingestion_p95_limit_seconds=args.ingestion_p95_limit_seconds,
            error_rate_limit=args.error_rate_limit,
            injection_rate_limit=args.injection_rate_limit,
            query_p99_limit_seconds=args.query_p99_limit_seconds,
            ingestion_p99_limit_seconds=args.ingestion_p99_limit_seconds,
            max_replication_lag_seconds=args.max_replication_lag_seconds,
            max_drill_rpo_seconds=args.max_drill_rpo_seconds,
            max_drill_rto_seconds=args.max_drill_rto_seconds,
            minimum_audit_retention_days=args.minimum_audit_retention_days,
            pilot_unsupported_claim_rate_limit=args.pilot_unsupported_claim_rate_limit,
            pilot_time_change_limit_percent=args.pilot_time_change_limit_percent,
        )
    except (OSError, ValidationError, ValueError) as exc:
        parser.error(f"invalid release evidence: {exc}")
    print(
        json.dumps(
            {
                "approved": not failures,
                "failures": failures,
                "verification": verification.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
