from __future__ import annotations

import pytest
from pydantic import ValidationError

from crisisweave.config import Settings

_ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - deliberate container-listener test value

PRODUCTION_STORAGE = {
    "database_backend": "postgresql",
    "ingestion_worker_enabled": False,
    "postgres_dsn": "postgresql://crisisweave@postgres/crisisweave?sslmode=verify-full",
    "object_store_backend": "s3",
    "s3_bucket": "crisisweave-evidence",
    "s3_region": "us-east-1",
}


def test_production_rejects_development_defaults(tmp_path) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", data_dir=tmp_path)


@pytest.mark.parametrize("retention_days", [6, 366])
def test_lifecycle_outbox_retention_is_bounded(retention_days: int) -> None:
    with pytest.raises(ValidationError, match="ingestion_lifecycle_retention_days"):
        Settings(_env_file=None, ingestion_lifecycle_retention_days=retention_days)


def test_lifecycle_outbox_retention_defaults_to_fourteen_days() -> None:
    assert Settings(_env_file=None).ingestion_lifecycle_retention_days == 14


def production_api_values(tmp_path) -> dict[str, object]:
    models = {}
    for name in ("text", "visual", "reranker", "whisper"):
        models[name] = tmp_path / name
        models[name].mkdir()
    manifest = tmp_path / "bundle.json"
    manifest.write_text("{}", encoding="utf-8")
    return {
        "_env_file": None,
        "app_env": "production",
        "data_dir": tmp_path,
        **PRODUCTION_STORAGE,
        "auth_mode": "hybrid",
        "oidc_issuer_url": "https://identity.example.org",
        "oidc_audience": "crisisweave-api",
        "oidc_jwks_url": "https://identity.example.org/.well-known/jwks.json",
        "api_keys": "research@active=0123456789abcdef0123456789abcdef",
        "service_key_role_bindings": "research@active=admin",
        "oversight_enabled": True,
        "postgres_rls_enabled": True,
        "metrics_api_key": "metrics-test-key-0123456789abcdef",
        "trust_proxy_headers": True,
        "forwarded_allow_ips": "127.0.0.1",
        "enable_docs": False,
        "cors_origins": "https://crisis.example.org",
        "trusted_hosts": "crisis.example.org,api",
        "telemetry_enabled": True,
        "otel_service_name": "crisisweave-api",
        "otel_exporter_otlp_endpoint": "https://otel.example.test/v1/traces",
        "cost_accounting_enabled": True,
        "query_compute_cost_per_hour_usd": 1.0,
        "embedding_provider": "sentence_transformers",
        "reranker_provider": "cross_encoder",
        "llm_provider": "openai_compatible",
        "llm_base_url": "https://llm.example.org/v1",
        "llm_api_key": "llm-test-key-0123456789abcdef0123",
        "qdrant_url": "https://qdrant.example.org",
        "qdrant_api_key": "abcdef0123456789abcdef0123456789",
        "model_local_files_only": True,
        "model_bundle_manifest": manifest,
        "text_embedding_model": str(models["text"]),
        "visual_embedding_model": str(models["visual"]),
        "reranker_model": str(models["reranker"]),
        "whisper_model": str(models["whisper"]),
    }


def test_production_accepts_hardened_minimum(tmp_path) -> None:
    settings = Settings(**production_api_values(tmp_path))
    assert settings.app_env == "production"
    assert settings.api_credentials[0][0] == "research"


def test_production_otel_ca_must_be_an_existing_file(tmp_path) -> None:
    values = production_api_values(tmp_path)
    values["otel_exporter_ca_file"] = tmp_path / "missing-ca.pem"
    with pytest.raises(ValidationError, match="OTLP CA file"):
        Settings(**values)

    ca_file = tmp_path / "otel-ca.pem"
    ca_file.write_text("test-ca", encoding="utf-8")
    values["otel_exporter_ca_file"] = ca_file
    assert Settings(**values).otel_exporter_ca_file == ca_file


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.tavily.com/search",
        "https://user:pass@api.tavily.com/search",
        "https://api.tavily.com/search?key=secret",
        "https://api.tavily.com",
    ],
)
def test_tavily_endpoint_must_be_exact_credential_free_https(tmp_path, endpoint: str) -> None:
    values = production_api_values(tmp_path)
    values.update(
        {
            "web_search_provider": "tavily",
            "tavily_api_key": "tavily-test-key-0123456789abcdef",
            "tavily_endpoint": endpoint,
        }
    )
    with pytest.raises(ValidationError, match="Tavily endpoint"):
        Settings(**values)


@pytest.mark.parametrize(
    "leaked",
    [
        {"parser_service_token": "worker-parser-key-0123456789abcdef"},
        {"malware_scanner_host": "clamav"},
    ],
)
def test_production_api_rejects_worker_credentials(tmp_path, leaked: dict[str, object]) -> None:
    values = production_api_values(tmp_path)
    values.update(leaked)

    with pytest.raises(ValidationError, match="ingestion-worker credentials"):
        Settings(**values)


def test_chunk_overlap_must_be_smaller(tmp_path) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            data_dir=tmp_path,
            chunk_chars=200,
            chunk_overlap_chars=200,
        )


def test_api_key_cannot_map_to_multiple_tenants(tmp_path) -> None:
    with pytest.raises(ValidationError, match="multiple tenants"):
        Settings(
            _env_file=None,
            data_dir=tmp_path,
            api_keys="alpha=shared-secret,beta=shared-secret",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cors_origins", "http://crisis.example.org"),
        ("cors_origins", "https://crisis.example.org/path"),
        ("cors_origins", ""),
        ("trusted_hosts", "https://crisis.example.org"),
        ("trusted_hosts", "bad host"),
        ("trusted_hosts", ""),
        ("metrics_api_key", "0123456789abcdef0123456789abcdef"),
        ("llm_base_url", "https://user:pass@llm.example.org/v1"),
        ("llm_base_url", "https://llm.example.org/v1?token=secret"),
        ("qdrant_url", "https://qdrant.example.org/#fragment"),
        ("qdrant_url", "https://qdrant.example.org\\@attacker.invalid"),
    ],
)
def test_production_rejects_malformed_origins_and_hosts(tmp_path, field: str, value: str) -> None:
    values = production_api_values(tmp_path)
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(**values)


@pytest.mark.parametrize(
    "collision",
    [
        ("llm_api_key", "qdrant-test-key-0123456789abcdef"),
        ("qdrant_api_key", "tenant-test-key-0123456789abcdef"),
        ("metrics_api_key", "qdrant-test-key-0123456789abcdef"),
    ],
)
def test_production_rejects_cross_role_credential_reuse(
    tmp_path, collision: tuple[str, str]
) -> None:
    values = production_api_values(tmp_path)
    values.update(
        {
            "api_keys": "research@active=tenant-test-key-0123456789abcdef",
            "llm_api_key": "llm-test-key-0123456789abcdef",
            "qdrant_api_key": "qdrant-test-key-0123456789abcdef",
        }
    )
    field, reused_value = collision
    values[field] = reused_value

    with pytest.raises(ValidationError, match="distinct|collide"):
        Settings(**values)


def production_worker_values(tmp_path) -> dict[str, object]:
    models = {}
    for name in ("text", "visual", "whisper"):
        models[name] = tmp_path / f"worker-{name}"
        models[name].mkdir(exist_ok=True)
    manifest = tmp_path / "worker-bundle.json"
    manifest.write_text("{}", encoding="utf-8")
    return {
        "_env_file": None,
        "app_env": "production",
        "runtime_role": "ingestion_worker",
        "data_dir": tmp_path,
        **PRODUCTION_STORAGE,
        "api_keys": "",
        "postgres_rls_enabled": True,
        "telemetry_enabled": True,
        "otel_service_name": "crisisweave-worker",
        "otel_exporter_otlp_endpoint": "https://otel.example.test/v1/traces",
        "cost_accounting_enabled": True,
        "ingestion_compute_cost_per_hour_usd": 1.0,
        "provider_canary_on_startup": False,
        "embedding_provider": "sentence_transformers",
        "qdrant_url": "https://qdrant.example.org",
        "qdrant_api_key": "worker-qdrant-key-0123456789abcdef",
        "parser_service_url": "http://parser:8001",
        "parser_service_token": "worker-parser-key-0123456789abcdef",
        "max_concurrent_ingestions": 1,
        "worker_metrics_host": _ALL_INTERFACES,
        "worker_metrics_port": 9100,
        "transcription_provider": "faster_whisper",
        "malware_scanner_host": "clamav",
        "model_local_files_only": True,
        "model_bundle_manifest": manifest,
        "text_embedding_model": str(models["text"]),
        "visual_embedding_model": str(models["visual"]),
        "whisper_model": str(models["whisper"]),
    }


def test_production_ingestion_worker_accepts_least_privilege_profile(tmp_path) -> None:
    settings = Settings(**production_worker_values(tmp_path))

    assert settings.runtime_role == "ingestion_worker"
    assert settings.llm_provider == "disabled"
    assert settings.reranker_provider == "lexical"
    assert not settings.api_key_values
    assert settings.worker_metrics_port == 9100


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("127.0.0.1", 9100),
        (_ALL_INTERFACES, 0),
        ("example.org", 9100),
        (_ALL_INTERFACES, 80),
    ],
)
def test_production_ingestion_worker_requires_scrapeable_bounded_metrics(
    tmp_path, host: str, port: int
) -> None:
    values = production_worker_values(tmp_path)
    values.update(worker_metrics_host=host, worker_metrics_port=port)

    with pytest.raises(ValidationError, match="metrics"):
        Settings(**values)


@pytest.mark.parametrize(
    "leaked",
    [
        {"api_keys": "tenant=tenant-secret-0123456789abcdef"},
        {"metrics_api_key": "metrics-secret-0123456789abcdef"},
        {
            "llm_provider": "openai_compatible",
            "llm_api_key": "llm-secret-0123456789abcdef0123",
        },
        {"tavily_api_key": "web-secret-0123456789abcdef0123"},
        {"reranker_provider": "cross_encoder"},
        {"trust_proxy_headers": True},
    ],
)
def test_production_ingestion_worker_rejects_api_only_configuration(
    tmp_path, leaked: dict[str, object]
) -> None:
    values = production_worker_values(tmp_path)
    values.update(leaked)

    with pytest.raises(ValidationError, match="ingestion workers"):
        Settings(**values)


@pytest.mark.parametrize(
    "invalid",
    [
        {"database_backend": "duckdb", "postgres_dsn": None},
        {"postgres_rls_enabled": False},
        {"ingestion_worker_enabled": True},
        {"object_store_backend": "local"},
        {"s3_region": "bad_region"},
        {"s3_endpoint_url": "http://objects.example.org"},
        {"embedding_provider": "hash"},
        {"qdrant_url": None},
        {"qdrant_api_key": "short"},
        {"model_local_files_only": False},
        {"model_bundle_manifest": "bundle.json"},
        {"text_embedding_model": "relative-text"},
        {"visual_embedding_model": "relative-visual"},
        {"log_queries": True},
        {"api_keys": "local-dev-key"},
        {"api_keys": "default=0123456789abcdef0123456789abcdef"},
        {"api_keys": "research=short"},
        {"metrics_api_key": "short"},
        {"trust_proxy_headers": False},
        {"forwarded_allow_ips": ""},
        {"reranker_provider": "lexical"},
        {"reranker_model": "relative-reranker"},
        {"llm_provider": "disabled", "llm_api_key": None},
        {"llm_api_key": "short"},
        {"llm_router_model": ""},
        {"llm_answer_model": ""},
        {"provider_canary_on_startup": False},
        {"enable_docs": True},
        {"router_temperature": 0.1},
        {"answer_temperature": 0.3},
        {"strict_prompt_guard": False},
        {"web_search_provider": "tavily", "tavily_api_key": None},
        {"web_search_provider": "tavily", "tavily_api_key": "short"},
    ],
)
def test_production_api_fails_closed_for_each_required_guard(
    tmp_path, invalid: dict[str, object]
) -> None:
    values = production_api_values(tmp_path)
    values.update(invalid)

    with pytest.raises(ValidationError):
        Settings(**values)


@pytest.mark.parametrize(
    "invalid",
    [
        {"parser_service_url": None},
        {"parser_service_token": None},
        {"parser_service_token": "short"},
        {"max_concurrent_ingestions": 2},
        {"transcription_provider": "disabled"},
        {"whisper_model": "relative-whisper"},
        {"malware_scanner_host": None},
        {
            "parser_service_token": "worker-qdrant-key-0123456789abcdef",
        },
    ],
)
def test_production_worker_fails_closed_for_each_required_guard(
    tmp_path, invalid: dict[str, object]
) -> None:
    values = production_worker_values(tmp_path)
    values.update(invalid)

    with pytest.raises(ValidationError):
        Settings(**values)


def production_migration_values(tmp_path) -> dict[str, object]:
    values = production_worker_values(tmp_path)
    values.update(
        {
            "runtime_role": "migration",
            "qdrant_api_key": "migration-qdrant-key-0123456789abcdef",
            "postgres_api_role": "crisisweave_api",
            "postgres_worker_role": "crisisweave_worker",
            "parser_service_url": None,
            "parser_service_token": None,
            "transcription_provider": "disabled",
            "malware_scanner_host": None,
            "worker_metrics_host": "127.0.0.1",
            "worker_metrics_port": 0,
        }
    )
    return values


def test_production_migration_accepts_schema_only_profile(tmp_path) -> None:
    configured = Settings(**production_migration_values(tmp_path))
    assert configured.runtime_role == "migration"
    assert configured.postgres_api_role == "crisisweave_api"
    assert configured.postgres_worker_role == "crisisweave_worker"


@pytest.mark.parametrize(
    "invalid",
    [
        {"postgres_api_role": None},
        {"postgres_api_role": "UPPERCASE"},
        {"postgres_worker_role": "crisisweave_api"},
        {"api_keys": "tenant=tenant-secret-0123456789abcdef"},
        {"parser_service_token": "parser-secret-0123456789abcdef"},
        {"trust_proxy_headers": True},
    ],
)
def test_production_migration_rejects_runtime_secrets_and_bad_roles(
    tmp_path, invalid: dict[str, object]
) -> None:
    values = production_migration_values(tmp_path)
    values.update(invalid)
    with pytest.raises(ValidationError, match="migrations|PostgreSQL"):
        Settings(**values)
