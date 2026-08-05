from __future__ import annotations

import re
from pathlib import Path

import pytest

from crisisweave.config import Settings
from crisisweave.security import (
    MalwareDetectedError,
    SecurityError,
    _check_clamd_verdict,
    verify_malware_scanner,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MEBIBYTE = 1024 * 1024


def test_production_stream_limit_exceeds_every_declared_upload_limit() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (REPOSITORY_ROOT / "deploy" / "compose.production.yaml").read_text(encoding="utf-8")

    assert "ARG CLAMAV_IMAGE=clamav/clamav:1.5.2_base" in dockerfile
    assert "FROM ${CLAMAV_IMAGE} AS clamav-runtime" in dockerfile
    assert "chmod 0444 /etc/clamav/clamd.conf" in dockerfile
    assert "USER clamav" in dockerfile
    stream_match = re.search(r"grep -qx 'StreamMaxLength (?P<mib>\d+)M'", dockerfile)
    assert stream_match is not None
    stream_limit = int(stream_match.group("mib")) * MEBIBYTE

    upload_limits = [
        int(value) for value in re.findall(r'CRISISWEAVE_MAX_UPLOAD_BYTES: "(\d+)"', compose)
    ]
    assert len(upload_limits) == 3
    assert len(set(upload_limits)) == 1
    assert stream_limit > upload_limits[0]


def test_production_topology_uses_shared_persistence_and_dedicated_workers() -> None:
    compose = (REPOSITORY_ROOT / "deploy" / "compose.production.yaml").read_text(encoding="utf-8")

    assert "CRISISWEAVE_DATABASE_BACKEND: postgresql" in compose
    assert "CRISISWEAVE_OBJECT_STORE_BACKEND: s3" in compose
    assert 'CRISISWEAVE_INGESTION_WORKER_ENABLED: "false"' in compose
    assert "environment: *api-environment" in compose
    assert compose.count("<<: *worker-environment") == 2
    assert compose.count('command: ["crisisweave", "ingestion-worker"]') == 2
    assert "  ingestion-worker-a:" in compose
    assert "  ingestion-worker-b:" in compose
    assert "  parser-a:" in compose
    assert "  parser-b:" in compose
    assert "parser-jobs-a:/parser-jobs" not in compose
    assert "parser-jobs-b:/parser-jobs" not in compose
    assert "X-Parser-Metadata" not in compose
    assert "CRISISWEAVE_RUNTIME_ROLE: ingestion_worker" in compose
    assert "  app-data:" not in compose
    assert 'command: ["crisisweave", "migrate"]' in compose
    assert "CRISISWEAVE_RUNTIME_ROLE: migration" in compose
    assert compose.count("condition: service_completed_successfully") == 3
    assert "CRISISWEAVE_API_POSTGRES_DSN" in compose
    assert "CRISISWEAVE_WORKER_POSTGRES_DSN" in compose
    assert "CRISISWEAVE_MIGRATION_POSTGRES_DSN" in compose
    assert "CRISISWEAVE_API_QDRANT_API_KEY" in compose
    assert "CRISISWEAVE_WORKER_QDRANT_API_KEY" in compose
    assert "CRISISWEAVE_MIGRATION_QDRANT_API_KEY" in compose
    assert "CRISISWEAVE_API_S3_ACCESS_KEY_ID" in compose
    assert "CRISISWEAVE_WORKER_S3_ACCESS_KEY_ID" in compose
    assert "networks: [api-gateway, api-provider-egress]" in compose
    assert compose.count("worker-storage-egress") == 3
    assert compose.count("migration-storage-egress") == 2

    api_block = compose.split("  api:", 1)[1].split("  ingestion-worker-a:", 1)[0]
    worker_environment = compose.split("x-worker-environment:", 1)[1].split(
        "x-parser-environment:", 1
    )[0]
    assert "PARSER_SERVICE_TOKEN" not in api_block
    assert "MALWARE_SCANNER_HOST" not in api_block
    assert "LLM_API_KEY" not in worker_environment
    assert "METRICS_API_KEY" not in worker_environment
    assert "TAVILY_API_KEY" not in worker_environment

    migration_environment = compose.split("x-migration-environment:", 1)[1].split(
        "x-parser-environment:", 1
    )[0]
    assert "AWS_ACCESS_KEY_ID" not in migration_environment
    assert "LLM_API_KEY" not in migration_environment
    assert "TAVILY_API_KEY" not in migration_environment
    assert "PARSER_SERVICE_TOKEN" not in migration_environment


def test_standalone_ui_auth_matches_the_api_default_and_ci_render_contract() -> None:
    compose = (REPOSITORY_ROOT / "deploy" / "compose.production.yaml").read_text(encoding="utf-8")
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "CRISISWEAVE_AUTH_MODE: ${CRISISWEAVE_AUTH_MODE:-hybrid}" in compose
    assert "CRISISWEAVE_UI_AUTH_MODE: api_key" in compose
    assert "CRISISWEAVE_AUTH_MODE: hybrid" in workflow
    assert "CRISISWEAVE_API_KEYS: ci@ui-2026=" in workflow
    assert "CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS: ci@ui-2026=operator" in workflow
    assert "CRISISWEAVE_FORWARDED_ALLOW_IPS: 172.30.77.10/32" in workflow
    assert "ipv4_address: ${CRISISWEAVE_GATEWAY_IPV4:-172.30.77.10}" in compose
    assert "/run/crisisweave/otel-ca.crt:ro" in compose


@pytest.mark.parametrize(
    "verdict",
    [
        b"stream: INSTREAM size limit exceeded. ERROR",
        b"stream: temporary file write failure. ERROR",
        b"",
    ],
)
def test_clamd_protocol_errors_are_not_malware_detections(verdict: bytes) -> None:
    with pytest.raises(SecurityError) as captured:
        _check_clamd_verdict(verdict)
    assert not isinstance(captured.value, MalwareDetectedError)


def test_clamd_found_verdict_is_distinct_from_scanner_failure() -> None:
    with pytest.raises(MalwareDetectedError):
        _check_clamd_verdict(b"stream: Win.Test.EICAR_HDB-1 FOUND")


def test_startup_canary_streams_the_full_application_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = Settings(app_env="test", data_dir=tmp_path, max_upload_bytes=1024)
    scanned_sizes: list[int] = []

    monkeypatch.setattr("crisisweave.security.malware_scanner_healthcheck", lambda _settings: True)

    def scan(path: Path, _settings: Settings, *, deadline: float | None = None) -> None:
        del deadline
        scanned_sizes.append(path.stat().st_size)
        if "eicar" in path.name:
            raise MalwareDetectedError("test detection")

    monkeypatch.setattr("crisisweave.security.run_malware_scan", scan)

    verify_malware_scanner(settings)

    assert scanned_sizes[0] == settings.max_upload_bytes
    assert scanned_sizes[1] == 68


def test_startup_canary_does_not_accept_a_scanner_error_as_eicar_detection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = Settings(app_env="test", data_dir=tmp_path, max_upload_bytes=1024)
    calls = 0

    monkeypatch.setattr("crisisweave.security.malware_scanner_healthcheck", lambda _settings: True)

    def scan(path: Path, _settings: Settings, *, deadline: float | None = None) -> None:
        nonlocal calls
        del path, deadline
        calls += 1
        if calls == 2:
            raise SecurityError("protocol failure")

    monkeypatch.setattr("crisisweave.security.run_malware_scan", scan)

    with pytest.raises(SecurityError, match="protocol failure"):
        verify_malware_scanner(settings)
