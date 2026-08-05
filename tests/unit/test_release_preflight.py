from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validate_production_config import (
    ProductionConfigError,
    validate_environment,
    validate_identity_boundary,
    validate_image_reference,
    validate_observability_configuration,
    validate_postgres_dsn,
    validate_role_isolation,
    validate_s3_configuration,
    validate_scale_values,
)
from scripts.verify_model_bundle import BundleError, verify_manifest, write_manifest


def _production_environment() -> dict[str, str]:
    return {
        "CRISISWEAVE_API_IMAGE": f"registry.example/api@sha256:{'1' * 64}",
        "CRISISWEAVE_CADDY_IMAGE": f"registry.example/gateway@sha256:{'2' * 64}",
        "CRISISWEAVE_CLAMAV_IMAGE": f"registry.example/clamav@sha256:{'3' * 64}",
        "CRISISWEAVE_UI_IMAGE": f"registry.example/ui@sha256:{'4' * 64}",
        "CRISISWEAVE_DOMAIN": "crisis.example.org",
        "CRISISWEAVE_CORS_ORIGINS": "https://crisis.example.org",
        "CRISISWEAVE_TRUSTED_HOSTS": "crisis.example.org,api",
        "CRISISWEAVE_API_POSTGRES_DSN": (
            "postgresql://crisisweave_api@postgres.example.org/crisisweave?sslmode=verify-full"
        ),
        "CRISISWEAVE_WORKER_POSTGRES_DSN": (
            "postgresql://crisisweave_worker@postgres.example.org/crisisweave?sslmode=verify-full"
        ),
        "CRISISWEAVE_MIGRATION_POSTGRES_DSN": (
            "postgresql://crisisweave_migrator@postgres.example.org/crisisweave?sslmode=verify-full"
        ),
        "CRISISWEAVE_POSTGRES_API_ROLE": "crisisweave_api",
        "CRISISWEAVE_POSTGRES_WORKER_ROLE": "crisisweave_worker",
        "CRISISWEAVE_POSTGRES_POOL_MIN_SIZE": "2",
        "CRISISWEAVE_POSTGRES_POOL_MAX_SIZE": "16",
        "CRISISWEAVE_S3_BUCKET": "crisisweave-evidence-prod",
        "CRISISWEAVE_S3_PREFIX": "crisisweave/v1",
        "CRISISWEAVE_S3_REGION": "us-east-1",
        "CRISISWEAVE_S3_ENDPOINT_URL": "https://objects.example.org",
        "CRISISWEAVE_S3_ADDRESSING_STYLE": "virtual",
        "CRISISWEAVE_S3_SERVER_SIDE_ENCRYPTION": "AES256",
        "CRISISWEAVE_QDRANT_URL": "https://qdrant.example.org",
        "CRISISWEAVE_API_QDRANT_API_KEY": "api-qdrant-key-0123456789abcdef",
        "CRISISWEAVE_WORKER_QDRANT_API_KEY": "worker-qdrant-key-0123456789abcdef",
        "CRISISWEAVE_MIGRATION_QDRANT_API_KEY": "migration-qdrant-key-0123456789abcdef",
        "CRISISWEAVE_API_S3_ACCESS_KEY_ID": "api-s3-identity",
        "CRISISWEAVE_API_S3_SECRET_ACCESS_KEY": "api-s3-secret-0123456789abcdef",
        "CRISISWEAVE_WORKER_S3_ACCESS_KEY_ID": "worker-s3-identity",
        "CRISISWEAVE_WORKER_S3_SECRET_ACCESS_KEY": "worker-s3-secret-0123456789abcdef",
        "CRISISWEAVE_API_WORKERS": "4",
        "CRISISWEAVE_AUTH_MODE": "hybrid",
        "CRISISWEAVE_API_KEYS": "research@ui-2026=service-key-0123456789abcdef012345",
        "CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS": "research@ui-2026=operator",
        "CRISISWEAVE_OIDC_ISSUER_URL": "https://identity.example.org/realms/crisisweave",
        "CRISISWEAVE_OIDC_AUDIENCE": "crisisweave-api",
        "CRISISWEAVE_OIDC_JWKS_URL": "https://identity.example.org/realms/crisisweave/jwks",
        "CRISISWEAVE_GATEWAY_IPV4": "172.30.77.10",
        "CRISISWEAVE_API_GATEWAY_SUBNET": "172.30.77.0/24",
        "CRISISWEAVE_FORWARDED_ALLOW_IPS": "172.30.77.10/32",
        "CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.org/v1/traces",
        "CRISISWEAVE_OTEL_CA_HOST_PATH": "/etc/ssl/certs/ca-certificates.crt",
        "CRISISWEAVE_QUERY_COMPUTE_COST_PER_HOUR_USD": "2.50",
        "CRISISWEAVE_INGESTION_COMPUTE_COST_PER_HOUR_USD": "4.25",
        "CRISISWEAVE_EGRESS_POLICY_SHA256": "5" * 64,
    }


def _model_records() -> dict[str, dict[str, str]]:
    return {
        role: {
            "model": f"example/{role}-model",
            "path": role,
            "revision": str(index) * 40,
        }
        for index, role in enumerate(("reranker", "text", "visual", "whisper"), start=1)
    }


def _bundle(tmp_path: Path) -> Path:
    for role in ("reranker", "text", "visual", "whisper"):
        role_root = tmp_path / role
        role_root.mkdir()
        (role_root / "weights.bin").write_bytes(f"{role}-weights".encode())
    return write_manifest(tmp_path, _model_records())


def test_production_preflight_accepts_digest_pinned_boundary() -> None:
    validate_environment(_production_environment())


def test_production_preflight_accepts_oidc_without_service_key_material() -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_AUTH_MODE"] = "oidc"
    environment["CRISISWEAVE_API_KEYS"] = ""
    environment["CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS"] = ""
    validate_environment(environment)


@pytest.mark.parametrize(
    ("keys", "bindings", "revoked"),
    [
        ("", "", ""),
        ("research=service-key-0123456789abcdef012345", "research=viewer", ""),
        ("research@ui-2026=short", "research@ui-2026=viewer", ""),
        (
            "research@ui-2026=service-key-0123456789abcdef012345",
            "",
            "",
        ),
        (
            "research@ui-2026=service-key-0123456789abcdef012345",
            "research@ui-2026=unknown-role",
            "",
        ),
        (
            "research@ui-2026=service-key-0123456789abcdef012345",
            "research@ui-2026=viewer",
            "research@ui-2026",
        ),
    ],
)
def test_production_preflight_rejects_unusable_hybrid_service_keys(
    keys: str, bindings: str, revoked: str
) -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_API_KEYS"] = keys
    environment["CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS"] = bindings
    environment["CRISISWEAVE_REVOKED_SERVICE_KEY_IDS"] = revoked
    with pytest.raises(ProductionConfigError, match="service key|service-key"):
        validate_environment(environment)


def test_production_preflight_rejects_service_keys_in_oidc_only_mode() -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_AUTH_MODE"] = "oidc"
    with pytest.raises(ProductionConfigError, match="OIDC-only"):
        validate_environment(environment)


@pytest.mark.parametrize(
    "reference",
    [
        "registry.example/api:latest",
        f"registry.example/api:release@sha256:{'1' * 64}",
        f"https://registry.example/api@sha256:{'1' * 64}",
        f"registry.example/api@sha256:{'0' * 64}",
        f"registry.example/API@sha256:{'1' * 64}",
    ],
)
def test_production_preflight_rejects_mutable_or_noncanonical_image(reference: str) -> None:
    with pytest.raises(ProductionConfigError):
        validate_image_reference("CRISISWEAVE_API_IMAGE", reference)


def test_production_preflight_rejects_gateway_injection() -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_DOMAIN"] = "crisis.example.org { respond hacked }"
    with pytest.raises(ProductionConfigError):
        validate_environment(environment)


@pytest.mark.parametrize("digest", ["", "0" * 64, "A" * 64, "abc"])
def test_production_preflight_requires_reviewed_egress_policy_digest(digest: str) -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_EGRESS_POLICY_SHA256"] = digest
    with pytest.raises(ProductionConfigError, match="EGRESS_POLICY_SHA256"):
        validate_environment(environment)


def test_production_preflight_rejects_reused_service_image() -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_UI_IMAGE"] = environment["CRISISWEAVE_API_IMAGE"]
    with pytest.raises(ProductionConfigError):
        validate_environment(environment)


@pytest.mark.parametrize(
    "variable",
    ["CRISISWEAVE_API_POSTGRES_DSN", "CRISISWEAVE_S3_BUCKET"],
)
def test_production_preflight_requires_shared_persistence(variable: str) -> None:
    environment = _production_environment()
    del environment[variable]
    with pytest.raises(ProductionConfigError, match=variable):
        validate_environment(environment)


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://db.example.org/crisisweave",
        "postgresql://db.example.org/crisisweave?sslmode=require",
        "postgresql://db.example.org/crisisweave?sslmode=verify-full&sslmode=disable",
        "postgresql://db.example.org/?sslmode=verify-full",
        "http://db.example.org/crisisweave?sslmode=verify-full",
        "postgresql:///crisisweave?sslmode=verify-full",
        "postgresql://db.example.org:invalid/crisisweave?sslmode=verify-full",
        " postgresql://db.example.org/crisisweave?sslmode=verify-full",
    ],
)
def test_production_preflight_rejects_insecure_or_malformed_postgres_dsn(dsn: str) -> None:
    with pytest.raises(ProductionConfigError):
        validate_postgres_dsn(dsn)


def test_production_preflight_accepts_encoded_postgres_credentials() -> None:
    validate_postgres_dsn(
        "postgresql://service:p%40ss@db.example.org/crisisweave?connect_timeout=5&sslmode=verify-full"
    )


@pytest.mark.parametrize(
    ("variable", "replacement"),
    [
        ("CRISISWEAVE_WORKER_POSTGRES_DSN", "CRISISWEAVE_API_POSTGRES_DSN"),
        ("CRISISWEAVE_WORKER_QDRANT_API_KEY", "CRISISWEAVE_API_QDRANT_API_KEY"),
        ("CRISISWEAVE_WORKER_S3_ACCESS_KEY_ID", "CRISISWEAVE_API_S3_ACCESS_KEY_ID"),
        ("CRISISWEAVE_WORKER_S3_SECRET_ACCESS_KEY", "CRISISWEAVE_API_S3_SECRET_ACCESS_KEY"),
    ],
)
def test_production_preflight_rejects_cross_role_credential_reuse(
    variable: str, replacement: str
) -> None:
    environment = _production_environment()
    environment[variable] = environment[replacement]
    with pytest.raises(ProductionConfigError, match="distinct|differ"):
        validate_role_isolation(environment)


def test_production_preflight_rejects_role_name_or_database_target_mismatch() -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_POSTGRES_API_ROLE"] = "unexpected_api"
    with pytest.raises(ProductionConfigError, match="match"):
        validate_role_isolation(environment)

    environment = _production_environment()
    environment["CRISISWEAVE_MIGRATION_POSTGRES_DSN"] = (
        "postgresql://crisisweave_migrator@other.example.org/crisisweave?sslmode=verify-full"
    )
    with pytest.raises(ProductionConfigError, match="same database"):
        validate_role_isolation(environment)


@pytest.mark.parametrize(
    "bucket",
    [
        "UPPERCASE",
        "ab",
        "bucket..name",
        "bucket.-name",
        "192.0.2.10",
        "-bucket-name",
    ],
)
def test_production_preflight_rejects_unsafe_s3_bucket_names(bucket: str) -> None:
    with pytest.raises(ProductionConfigError, match="S3_BUCKET"):
        validate_s3_configuration({"CRISISWEAVE_S3_BUCKET": bucket})


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("CRISISWEAVE_S3_PREFIX", "../another-tenant"),
        ("CRISISWEAVE_S3_PREFIX", "evidence//v1"),
        ("CRISISWEAVE_S3_ENDPOINT_URL", "http://objects.example.org"),
        ("CRISISWEAVE_S3_ENDPOINT_URL", "https://user@objects.example.org"),
        ("CRISISWEAVE_S3_ADDRESSING_STYLE", "other"),
        ("CRISISWEAVE_S3_SERVER_SIDE_ENCRYPTION", "none"),
    ],
)
def test_production_preflight_rejects_unsafe_s3_configuration(variable: str, value: str) -> None:
    environment = {
        "CRISISWEAVE_S3_BUCKET": "crisisweave-evidence",
        "CRISISWEAVE_S3_REGION": "us-east-1",
        variable: value,
    }
    with pytest.raises(ProductionConfigError):
        validate_s3_configuration(environment)


def test_production_preflight_requires_kms_key_for_kms_encryption() -> None:
    with pytest.raises(ProductionConfigError, match="S3_KMS_KEY_ID"):
        validate_s3_configuration(
            {
                "CRISISWEAVE_S3_BUCKET": "crisisweave-evidence",
                "CRISISWEAVE_S3_REGION": "us-east-1",
                "CRISISWEAVE_S3_SERVER_SIDE_ENCRYPTION": "aws:kms",
            }
        )


@pytest.mark.parametrize("region", ["", " us-east-1", "us_east_1", "../region"])
def test_production_preflight_requires_valid_s3_region(region: str) -> None:
    with pytest.raises(ProductionConfigError, match="S3_REGION"):
        validate_s3_configuration(
            {
                "CRISISWEAVE_S3_BUCKET": "crisisweave-evidence",
                "CRISISWEAVE_S3_REGION": region,
            }
        )


@pytest.mark.parametrize("value", ["0", "-1", "+2", "1.5", " 2", "two"])
def test_production_preflight_rejects_non_positive_worker_counts(value: str) -> None:
    with pytest.raises(ProductionConfigError, match="API_WORKERS"):
        validate_scale_values({"CRISISWEAVE_API_WORKERS": value})


def test_production_preflight_rejects_excessive_scale_and_inverted_pool() -> None:
    with pytest.raises(ProductionConfigError, match="safety limit"):
        validate_scale_values({"CRISISWEAVE_API_WORKERS": "65"})
    with pytest.raises(ProductionConfigError, match="cannot exceed"):
        validate_scale_values(
            {
                "CRISISWEAVE_POSTGRES_POOL_MIN_SIZE": "9",
                "CRISISWEAVE_POSTGRES_POOL_MAX_SIZE": "8",
            }
        )


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel.example.org/v1/traces"),
        ("CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example.org/other"),
        ("CRISISWEAVE_QUERY_COMPUTE_COST_PER_HOUR_USD", "0"),
        ("CRISISWEAVE_INGESTION_COMPUTE_COST_PER_HOUR_USD", "nan"),
    ],
)
def test_production_preflight_rejects_unmeasurable_operations(variable: str, value: str) -> None:
    environment = _production_environment()
    environment[variable] = value
    with pytest.raises(ProductionConfigError):
        validate_observability_configuration(environment)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("CRISISWEAVE_AUTH_MODE", "api_key"),
        ("CRISISWEAVE_OIDC_ISSUER_URL", "http://identity.example.org"),
        ("CRISISWEAVE_OIDC_JWKS_URL", "https://user:pass@identity.example.org/jwks"),
        ("CRISISWEAVE_OIDC_AUDIENCE", ""),
        ("CRISISWEAVE_OIDC_ALGORITHMS", "HS256"),
        ("CRISISWEAVE_FORWARDED_ALLOW_IPS", "0.0.0.0/0"),
        ("CRISISWEAVE_FORWARDED_ALLOW_IPS", "proxy.example.org"),
    ],
)
def test_production_preflight_rejects_weak_identity_boundaries(variable: str, value: str) -> None:
    environment = _production_environment()
    environment[variable] = value
    with pytest.raises(ProductionConfigError):
        validate_identity_boundary(environment)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("CRISISWEAVE_GATEWAY_IPV4", "172.30.78.10"),
        ("CRISISWEAVE_GATEWAY_IPV4", "172.30.77.0"),
        ("CRISISWEAVE_API_GATEWAY_SUBNET", "0.0.0.0/0"),
        ("CRISISWEAVE_API_GATEWAY_SUBNET", "172.30.77.1/24"),
        ("CRISISWEAVE_FORWARDED_ALLOW_IPS", "172.30.77.0/24"),
    ],
)
def test_production_preflight_binds_forwarded_headers_to_the_gateway(
    variable: str, value: str
) -> None:
    environment = _production_environment()
    environment[variable] = value
    with pytest.raises(ProductionConfigError, match="gateway|FORWARDED"):
        validate_identity_boundary(environment)


@pytest.mark.parametrize("value", ["", "relative/ca.pem", "../ca.pem", "C:\\ca.pem"])
def test_production_preflight_requires_linux_otel_ca_mount(value: str) -> None:
    environment = _production_environment()
    environment["CRISISWEAVE_OTEL_CA_HOST_PATH"] = value
    with pytest.raises(ProductionConfigError, match="CA_HOST_PATH"):
        validate_observability_configuration(environment)


def test_model_bundle_manifest_binds_every_file(tmp_path: Path) -> None:
    manifest = _bundle(tmp_path)
    summary = verify_manifest(manifest)
    assert summary["file_count"] == 4
    assert summary["total_bytes"] > 0
    assert len(str(summary["content_sha256"])) == 64


def test_model_bundle_manifest_rejects_tampering(tmp_path: Path) -> None:
    manifest = _bundle(tmp_path)
    (tmp_path / "text" / "weights.bin").write_bytes(b"changed")
    with pytest.raises(BundleError, match="do not match"):
        verify_manifest(manifest)


def test_model_bundle_manifest_rejects_unlisted_files(tmp_path: Path) -> None:
    manifest = _bundle(tmp_path)
    (tmp_path / "whisper" / "unexpected.bin").write_bytes(b"unexpected")
    with pytest.raises(BundleError, match="do not match"):
        verify_manifest(manifest)


def test_model_bundle_manifest_rejects_manifest_rewrite(tmp_path: Path) -> None:
    manifest = _bundle(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["models"]["text"]["revision"] = "a" * 40
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BundleError, match="content digest"):
        verify_manifest(manifest)
