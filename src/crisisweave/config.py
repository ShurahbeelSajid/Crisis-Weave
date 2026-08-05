"""Validated configuration with fail-closed production checks."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Explicit container listener; never used as a destination.
_ALL_INTERFACES = "0.0.0.0"  # noqa: S104  # nosec B104


def _validate_https_service_url(name: str, value: str) -> None:
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError(f"production {name} URL contains whitespace or control characters")
    if "\\" in value:
        raise ValueError(f"production {name} URL contains an invalid path separator")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"production {name} URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"production {name} must be a credential-free HTTPS service URL")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CRISISWEAVE_",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "test", "production", "parser"] = "development"
    runtime_role: Literal["api", "ingestion_worker", "migration"] = "api"
    data_dir: Path = Path("data")
    log_level: str = "INFO"
    log_queries: bool = False
    telemetry_enabled: bool = False
    otel_service_name: str = "crisisweave"
    otel_exporter_otlp_endpoint: str | None = None
    otel_exporter_headers: SecretStr | None = None
    otel_exporter_ca_file: Path | None = None
    otel_trace_sample_ratio: float = Field(default=0.1, ge=0.0, le=1.0)
    cost_accounting_enabled: bool = False
    router_input_cost_per_million_usd: float = Field(default=0.0, ge=0.0, le=10_000.0)
    router_output_cost_per_million_usd: float = Field(default=0.0, ge=0.0, le=10_000.0)
    answer_input_cost_per_million_usd: float = Field(default=0.0, ge=0.0, le=10_000.0)
    answer_output_cost_per_million_usd: float = Field(default=0.0, ge=0.0, le=10_000.0)
    query_compute_cost_per_hour_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    ingestion_compute_cost_per_hour_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    slo_query_p95_seconds: float = Field(default=10.0, gt=0.0, le=600.0)
    slo_ingestion_p95_seconds: float = Field(default=600.0, gt=0.0, le=7200.0)
    slo_error_rate: float = Field(default=0.01, ge=0.0, lt=1.0)
    audit_retention_days: int = Field(default=30, ge=1, le=3650)
    max_audit_rows: int = Field(default=100_000, ge=100, le=10_000_000)
    analytics_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    max_analytics_result_bytes: int = Field(default=512 * 1024, ge=16 * 1024, le=10 * 1024**2)
    max_analytics_cell_bytes: int = Field(default=32 * 1024, ge=1024, le=1024**2)
    database_backend: Literal["duckdb", "postgresql"] = "duckdb"
    postgres_dsn: SecretStr | None = None
    postgres_pool_min_size: int = Field(default=1, ge=1, le=32)
    postgres_pool_max_size: int = Field(default=8, ge=1, le=128)
    postgres_pool_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    postgres_api_role: str | None = None
    postgres_worker_role: str | None = None
    postgres_rls_enabled: bool = False

    object_store_backend: Literal["local", "s3"] = "local"
    s3_bucket: str | None = None
    s3_prefix: str = "crisisweave"
    s3_endpoint_url: str | None = None
    s3_region: str | None = None
    s3_addressing_style: Literal["auto", "path", "virtual"] = "auto"
    s3_server_side_encryption: Literal["AES256", "aws:kms"] = "AES256"
    s3_kms_key_id: SecretStr | None = None
    object_store_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)

    api_keys: str = "local-dev-key"
    auth_mode: Literal["api_key", "oidc", "hybrid"] = "api_key"
    oidc_issuer_url: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_algorithms: str = "RS256,ES256"
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "roles"
    oidc_identity_type_claim: str = "identity_type"
    oidc_jwks_cache_seconds: int = Field(default=300, ge=30, le=86_400)
    oidc_jwks_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    oidc_jwks_max_bytes: int = Field(default=1024 * 1024, ge=16 * 1024, le=2 * 1024 * 1024)
    oidc_allow_private_jwks: bool = False
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    service_key_role_bindings: str = ""
    revoked_service_key_ids: str = ""
    identity_audit_retention_days: int = Field(default=365, ge=1, le=3650)
    max_identity_audit_rows: int = Field(default=1_000_000, ge=100, le=10_000_000)
    oversight_enabled: bool = False
    high_risk_terms: str = (
        "evacuation,shelter allocation,medical triage,dispatch,resource allocation,"
        "fatality,missing persons,dam failure,chemical release,"
        "evacuación,evacuação,évacuation,εκκένωση,निकासी,انخلا,إخلاء,evakuasi"
    )
    minimum_answer_confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    max_source_age_days: int = Field(default=30, ge=1, le=3650)
    unknown_source_freshness_requires_review: bool = False
    contradiction_escalation_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    review_retention_days: int = Field(default=365, ge=1, le=3650)
    metrics_api_key: SecretStr | None = None
    worker_metrics_host: str = "127.0.0.1"
    worker_metrics_port: int = Field(default=0, ge=0, le=65535)
    cors_origins: str = "http://localhost:8501"
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    enable_docs: bool = True
    rate_limit_requests: int = Field(default=60, ge=1, le=10000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    max_rate_limit_identities: int = Field(default=10_000, ge=100, le=1_000_000)
    trust_proxy_headers: bool = False
    forwarded_allow_ips: str = "127.0.0.1"
    max_concurrent_queries: int = Field(default=8, ge=1, le=256)
    max_concurrent_ingestions: int = Field(default=2, ge=1, le=32)
    ingestion_worker_enabled: bool = True
    queue_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    request_timeout_seconds: float = Field(default=90.0, ge=5.0, le=600.0)
    ingestion_timeout_seconds: float = Field(default=600.0, ge=30.0, le=3600.0)
    ingestion_lifecycle_retention_days: int = Field(default=14, ge=7, le=365)
    reconciliation_interval_seconds: float = Field(default=60.0, ge=5.0, le=3600.0)
    max_query_body_bytes: int = Field(default=64 * 1024, ge=1024, le=1024**2)
    query_body_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    upload_body_timeout_seconds: float = Field(default=120.0, ge=5.0, le=900.0)
    body_chunk_timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)

    llm_provider: Literal["disabled", "openai_compatible"] = "disabled"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_api_key: SecretStr | None = None
    llm_router_model: str = "qwen2.5:7b"
    llm_answer_model: str = "qwen2.5vl:7b"
    router_temperature: float = Field(default=0.0, ge=0.0, le=0.3)
    answer_temperature: float = Field(default=0.1, ge=0.0, le=0.5)
    llm_timeout_seconds: float = Field(default=45.0, ge=1.0, le=180.0)
    planner_max_tokens: int = Field(default=700, ge=64, le=4000)
    answer_max_tokens: int = Field(default=1200, ge=128, le=8000)
    max_model_response_bytes: int = Field(default=2 * 1024 * 1024, ge=4096, le=10 * 1024 * 1024)
    max_tool_calls: int = Field(default=3, ge=1, le=6)
    provider_canary_on_startup: bool = True

    embedding_provider: Literal["hash", "sentence_transformers"] = "hash"
    text_embedding_model: str = "BAAI/bge-small-en-v1.5"
    visual_embedding_model: str = "clip-ViT-B-32"
    text_vector_size: int = Field(default=384, ge=64, le=4096)
    visual_vector_size: int = Field(default=512, ge=64, le=4096)
    reranker_provider: Literal["lexical", "cross_encoder"] = "lexical"
    reranker_model: str = "BAAI/bge-reranker-base"
    model_local_files_only: bool = False
    model_bundle_manifest: Path | None = None
    qdrant_url: str | None = None
    qdrant_api_key: SecretStr | None = None
    qdrant_collection: str = "crisisweave_evidence_v1"

    web_search_provider: Literal["disabled", "tavily"] = "disabled"
    tavily_api_key: SecretStr | None = None
    tavily_endpoint: str = "https://api.tavily.com/search"
    web_allowed_domains: str = "nasa.gov,noaa.gov,usgs.gov,fema.gov"
    web_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    max_web_response_bytes: int = Field(default=1024 * 1024, ge=4096, le=10 * 1024 * 1024)

    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1024, le=1024**3)
    max_multipart_overhead_bytes: int = Field(default=1024 * 1024, ge=65_536, le=16 * 1024**2)
    max_pdf_pages: int = Field(default=250, ge=1, le=2000)
    max_image_pixels: int = Field(default=40_000_000, ge=1_000_000, le=200_000_000)
    max_video_seconds: int = Field(default=1800, ge=1, le=14400)
    max_video_frames: int = Field(default=120, ge=1, le=1000)
    max_video_dimension: int = Field(default=16_384, ge=128, le=65_536)
    max_structured_rows: int = Field(default=50_000, ge=1, le=200_000)
    max_structured_cell_chars: int = Field(default=8192, ge=256, le=65_536)
    max_structured_rows_per_tenant: int = Field(default=250_000, ge=1, le=5_000_000)
    video_frame_interval_seconds: int = Field(default=15, ge=1, le=600)
    ffmpeg_path: str = "ffmpeg"
    ffprobe_path: str = "ffprobe"
    tesseract_path: str = "tesseract"
    malware_scanner_path: str | None = None
    malware_scanner_host: str | None = None
    malware_scanner_port: int = Field(default=3310, ge=1, le=65535)
    max_malware_signature_age_hours: int = Field(default=72, ge=1, le=720)
    transcription_provider: Literal["disabled", "faster_whisper"] = "disabled"
    whisper_model: str = "small"
    transcription_timeout_seconds: int = Field(default=360, ge=30, le=3600)
    command_timeout_seconds: int = Field(default=120, ge=5, le=1800)
    extraction_timeout_seconds: int = Field(default=420, ge=30, le=3600)

    chunk_chars: int = Field(default=1800, ge=200, le=8000)
    chunk_overlap_chars: int = Field(default=200, ge=0, le=2000)
    retrieval_candidate_count: int = Field(default=30, ge=5, le=200)
    strict_prompt_guard: bool = True
    max_context_chars: int = Field(default=24_000, ge=2000, le=100_000)
    max_vision_images: int = Field(default=4, ge=0, le=12)
    max_vision_image_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=20 * 1024 * 1024)
    max_documents_per_tenant: int = Field(default=1000, ge=1, le=100_000)
    max_storage_bytes_per_tenant: int = Field(default=20 * 1024**3, ge=1024, le=10 * 1024**4)
    max_derived_bytes_per_document: int = Field(default=500 * 1024**2, ge=1024, le=10 * 1024**3)
    min_free_disk_bytes: int = Field(default=256 * 1024**2, ge=1024**2, le=10 * 1024**4)
    max_failed_documents_per_tenant: int = Field(default=100, ge=0, le=10_000)
    max_extracted_chars_per_document: int = Field(default=5_000_000, ge=1000, le=100_000_000)
    max_chunks_per_document: int = Field(default=10_000, ge=1, le=100_000)
    isolate_parsers: bool = False
    parser_worker_memory_bytes: int = Field(default=2 * 1024**3, ge=256 * 1024**2, le=32 * 1024**3)
    max_extraction_ipc_bytes: int = Field(default=128 * 1024**2, ge=1024**2, le=512 * 1024**2)
    parser_service_url: str | None = None
    parser_service_token: SecretStr | None = None

    @property
    def api_key_values(self) -> tuple[str, ...]:
        return tuple(key for _, key in self.api_credentials)

    @property
    def api_credentials(self) -> tuple[tuple[str, str], ...]:
        from crisisweave.auth import parse_service_credentials

        return tuple(
            (credential.tenant_label, credential.secret)
            for credential in parse_service_credentials(
                self.api_keys,
                self.service_key_role_bindings,
                self.revoked_service_key_ids,
            )
            if not credential.revoked
        )

    @property
    def cors_origin_values(self) -> list[str]:
        return [value.strip() for value in self.cors_origins.split(",") if value.strip()]

    @property
    def trusted_host_values(self) -> list[str]:
        return [value.strip() for value in self.trusted_hosts.split(",") if value.strip()]

    @property
    def allowed_domain_values(self) -> tuple[str, ...]:
        return tuple(
            value.lower().strip(". ")
            for value in self.web_allowed_domains.split(",")
            if value.strip()
        )

    @property
    def database_path(self) -> Path:
        return self.data_dir / "crisisweave.duckdb"

    @property
    def object_dir(self) -> Path:
        return self.data_dir / "objects"

    @property
    def artifact_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def qdrant_path(self) -> Path:
        return self.data_dir / "qdrant"

    @model_validator(mode="after")
    def validate_security_posture(self) -> Settings:
        if self.chunk_overlap_chars >= self.chunk_chars:
            raise ValueError("chunk_overlap_chars must be smaller than chunk_chars")
        if self.transcription_timeout_seconds > self.extraction_timeout_seconds:
            raise ValueError("transcription timeout cannot exceed the extraction timeout")
        if (
            self.command_timeout_seconds + self.extraction_timeout_seconds + 10
            >= self.ingestion_timeout_seconds
        ):
            raise ValueError("ingestion timeout must leave room for scanning and extraction")
        key_owners: dict[str, str] = {}
        for tenant, key in self.api_credentials:
            prior_owner = key_owners.setdefault(key, tenant)
            if prior_owner != tenant:
                raise ValueError("one API key cannot be assigned to multiple tenants")
        if self.web_search_provider == "tavily" and not self.tavily_api_key:
            raise ValueError("tavily_api_key is required when Tavily search is enabled")
        if self.web_search_provider == "tavily":
            _validate_https_service_url("Tavily endpoint", self.tavily_endpoint)
            if not urlparse(self.tavily_endpoint).path.rstrip("/"):
                raise ValueError("Tavily endpoint must include an operator-pinned request path")
        if self.malware_scanner_path and self.malware_scanner_host:
            raise ValueError("configure either a malware scanner path or host, not both")
        if self.postgres_pool_min_size > self.postgres_pool_max_size:
            raise ValueError("postgres_pool_min_size cannot exceed postgres_pool_max_size")
        if self.database_backend == "postgresql" and not self.postgres_dsn:
            raise ValueError("postgres_dsn is required for the PostgreSQL backend")
        if self.postgres_rls_enabled and self.database_backend != "postgresql":
            raise ValueError("PostgreSQL RLS can only be enabled with the PostgreSQL backend")
        algorithms = {item.strip() for item in self.oidc_algorithms.split(",") if item.strip()}
        if not algorithms or not algorithms <= {"RS256", "ES256"}:
            raise ValueError("OIDC algorithms must be a non-empty subset of RS256 and ES256")
        for claim_name in (
            self.oidc_tenant_claim,
            self.oidc_roles_claim,
            self.oidc_identity_type_claim,
        ):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", claim_name):
                raise ValueError("OIDC claim names are malformed")
        if self.auth_mode in {"oidc", "hybrid"}:
            if not self.oidc_issuer_url or not self.oidc_audience or not self.oidc_jwks_url:
                raise ValueError("OIDC authentication requires issuer, audience, and JWKS URLs")
            if not 1 <= len(self.oidc_audience) <= 255:
                raise ValueError("OIDC audience is malformed")
        if self.oversight_enabled and not any(
            item.strip() for item in self.high_risk_terms.split(",")
        ):
            raise ValueError("human oversight requires at least one high-risk term")
        if self.object_store_backend == "s3":
            if not self.s3_bucket or not re.fullmatch(
                r"(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]", self.s3_bucket
            ):
                raise ValueError("s3_bucket must be a valid DNS-compatible bucket name")
            if self.app_env == "production" and (
                not self.s3_region
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", self.s3_region)
            ):
                raise ValueError("production requires an explicit valid s3_region")
            prefix_parts = Path(self.s3_prefix.replace("\\", "/")).parts
            if (
                self.s3_prefix.startswith("/")
                or ".." in prefix_parts
                or any(ord(character) < 32 for character in self.s3_prefix)
            ):
                raise ValueError("s3_prefix must be a relative object namespace")
            if self.s3_server_side_encryption == "aws:kms" and (
                not self.s3_kms_key_id or not self.s3_kms_key_id.get_secret_value().strip()
            ):
                raise ValueError("s3_kms_key_id is required for aws:kms encryption")
        if self.malware_scanner_host and (
            "://" in self.malware_scanner_host
            or "/" in self.malware_scanner_host
            or any(ch.isspace() for ch in self.malware_scanner_host)
        ):
            raise ValueError("malware_scanner_host must be a bare DNS name or IP address")
        if self.parser_service_url:
            try:
                parser_url = urlparse(self.parser_service_url)
                parser_hostname = parser_url.hostname
            except ValueError as exc:
                raise ValueError("parser_service_url is malformed") from exc
            if (
                parser_url.scheme not in {"http", "https"}
                or not parser_hostname
                or parser_url.username
                or parser_url.password
                or parser_url.path not in {"", "/"}
                or parser_url.params
                or parser_url.query
                or parser_url.fragment
            ):
                raise ValueError(
                    "parser_service_url must be an exact credential-free HTTP(S) origin"
                )
        if self.app_env == "parser":
            if (
                not self.parser_service_token
                or len(self.parser_service_token.get_secret_value()) < 24
            ):
                raise ValueError("parser workers require a service token of at least 24 characters")
            if not self.model_local_files_only:
                raise ValueError("parser workers must load models offline")
            if self.transcription_provider == "disabled":
                raise ValueError("parser workers require video transcription")
        if self.app_env == "production":
            self._validate_production_shared()
            if self.runtime_role == "api":
                self._validate_production_api()
            elif self.runtime_role == "ingestion_worker":
                self._validate_production_ingestion_worker()
            else:
                self._validate_production_migration()
        return self

    def _validate_production_shared(self) -> None:
        if self.database_backend != "postgresql" or not self.postgres_dsn:
            raise ValueError("production requires the shared PostgreSQL backend")
        if self.worker_metrics_host not in {"127.0.0.1", _ALL_INTERFACES}:
            raise ValueError("worker metrics must bind to an explicit local interface")
        if not self.postgres_rls_enabled:
            raise ValueError("production requires PostgreSQL row-level tenant isolation")
        self._validate_postgres_dsn()
        if self.ingestion_worker_enabled:
            raise ValueError("production forbids the embedded ingestion worker")
        if self.object_store_backend != "s3":
            raise ValueError("production requires versioned S3-compatible object storage")
        if self.s3_endpoint_url:
            _validate_https_service_url("S3 endpoint", self.s3_endpoint_url)
        if self.embedding_provider == "hash":
            raise ValueError("hash embeddings are development-only")
        if not self.qdrant_url or not self.qdrant_api_key:
            raise ValueError("production requires authenticated external Qdrant")
        if len(self.qdrant_api_key.get_secret_value()) < 24:
            raise ValueError("production Qdrant credentials must contain at least 24 characters")
        _validate_https_service_url("Qdrant", self.qdrant_url)
        if not self.model_local_files_only:
            raise ValueError("production model loading must be offline/local-only")
        if not self.model_bundle_manifest or not self.model_bundle_manifest.is_absolute():
            raise ValueError("production requires an absolute model bundle manifest path")
        for name, value in (
            ("text_embedding_model", self.text_embedding_model),
            ("visual_embedding_model", self.visual_embedding_model),
        ):
            if not Path(value).is_absolute():
                raise ValueError(f"production {name} must be an absolute, preloaded model path")
        if self.log_queries:
            raise ValueError("raw query logging is forbidden in production")

    def _validate_production_api(self) -> None:
        self._validate_production_observability("api")
        if self.worker_metrics_port:
            raise ValueError("production APIs must not expose the worker metrics listener")
        if self.auth_mode not in {"oidc", "hybrid"}:
            raise ValueError("production API requires OIDC user authentication")
        if self.oidc_issuer_url is None or self.oidc_jwks_url is None:
            raise ValueError("production API requires explicit OIDC endpoints")
        _validate_https_service_url("OIDC issuer", self.oidc_issuer_url)
        _validate_https_service_url("OIDC JWKS", self.oidc_jwks_url)
        jwks_hostname = urlparse(self.oidc_jwks_url).hostname
        try:
            jwks_address = ipaddress.ip_address(jwks_hostname or "")
        except ValueError:
            jwks_address = None
        if (
            jwks_address is not None
            and not jwks_address.is_global
            and not self.oidc_allow_private_jwks
        ):
            raise ValueError("production OIDC JWKS cannot target a private or local address")
        if self.auth_mode == "hybrid":
            from crisisweave.auth import parse_service_credentials

            credentials = parse_service_credentials(
                self.api_keys,
                self.service_key_role_bindings,
                self.revoked_service_key_ids,
                production=True,
            )
            if not credentials or any(len(item.secret) < 24 for item in credentials):
                raise ValueError("production service keys must contain at least 24 characters")
        elif self.api_keys.strip() not in {"", "local-dev-key"}:
            raise ValueError("OIDC-only production APIs must not receive service API keys")
        if not self.oversight_enabled:
            raise ValueError("production API requires the human-oversight workflow")
        metrics_key = self.metrics_api_key
        if not metrics_key or len(metrics_key.get_secret_value()) < 24:
            raise ValueError("production API requires a distinct metrics key")
        if metrics_key.get_secret_value() in self.api_key_values:
            raise ValueError("the production metrics key must differ from every tenant API key")
        if not self.trust_proxy_headers or not self.forwarded_allow_ips.strip():
            raise ValueError("production API requires an explicitly trusted proxy boundary")
        if self.reranker_provider == "lexical":
            raise ValueError("production API requires a model reranker")
        if not Path(self.reranker_model).is_absolute():
            raise ValueError("production reranker_model must be an absolute, preloaded model path")
        llm_key = self.llm_api_key
        if self.llm_provider == "disabled" or not llm_key:
            raise ValueError("production API requires an authenticated LLM provider")
        if len(llm_key.get_secret_value()) < 24:
            raise ValueError("production LLM credentials must contain at least 24 characters")
        if not self.llm_router_model.strip() or not self.llm_answer_model.strip():
            raise ValueError("production requires explicit router and vision-answer models")
        if not self.provider_canary_on_startup:
            raise ValueError("production API requires the provider capability canary")
        _validate_https_service_url("LLM endpoint", self.llm_base_url)
        self._validate_production_origins_and_hosts()
        if self.enable_docs:
            raise ValueError("set enable_docs=false in production")
        if self.router_temperature != 0.0 or self.answer_temperature > 0.2:
            raise ValueError("production temperatures exceed the reproducibility policy")
        if not self.strict_prompt_guard:
            raise ValueError("strict prompt guard is required in production")
        if self.parser_service_token or self.malware_scanner_host:
            raise ValueError("production API must not receive ingestion-worker credentials")
        qdrant_key = self.qdrant_api_key
        if qdrant_key is None:
            raise ValueError("production API requires Qdrant authentication")
        role_credentials = [
            *[
                (f"tenant API key {index}", key)
                for index, (_, key) in enumerate(self.api_credentials, start=1)
            ],
            ("metrics key", metrics_key.get_secret_value()),
            ("LLM key", llm_key.get_secret_value()),
            ("Qdrant key", qdrant_key.get_secret_value()),
        ]
        if self.web_search_provider == "tavily":
            if self.tavily_api_key is None or len(self.tavily_api_key.get_secret_value()) < 24:
                raise ValueError(
                    "production Tavily credentials must contain at least 24 characters"
                )
            role_credentials.append(("Tavily key", self.tavily_api_key.get_secret_value()))
        self._validate_distinct_credentials(role_credentials)

    def _validate_production_ingestion_worker(self) -> None:
        self._validate_production_observability("ingestion_worker")
        if self.worker_metrics_host != _ALL_INTERFACES or self.worker_metrics_port < 1024:
            raise ValueError(
                "production ingestion workers require a non-privileged metrics listener"
            )
        if self.api_keys.strip() not in {"", "local-dev-key"} or self.metrics_api_key:
            raise ValueError("production ingestion workers must not receive API or metrics keys")
        if self.llm_provider != "disabled" or self.llm_api_key or self.provider_canary_on_startup:
            raise ValueError("production ingestion workers must not receive LLM configuration")
        if self.web_search_provider != "disabled" or self.tavily_api_key:
            raise ValueError("production ingestion workers must not receive web-search credentials")
        if self.reranker_provider != "lexical":
            raise ValueError("production ingestion workers must not configure a reranker")
        if self.trust_proxy_headers:
            raise ValueError("production ingestion workers must not trust proxy headers")
        if not self.parser_service_url or not self.parser_service_token:
            raise ValueError("production ingestion workers require the isolated parser service")
        if len(self.parser_service_token.get_secret_value()) < 24:
            raise ValueError("production parser credentials must contain at least 24 characters")
        if self.max_concurrent_ingestions != 1:
            raise ValueError("each production worker/parser trust zone permits one ingestion")
        if self.transcription_provider == "disabled":
            raise ValueError("production ingestion workers require video transcription")
        if not Path(self.whisper_model).is_absolute():
            raise ValueError("production whisper_model must be an absolute, preloaded model path")
        if not self.malware_scanner_host:
            raise ValueError("production ingestion workers require network-isolated clamd")
        parser_key = self.parser_service_token
        qdrant_key = self.qdrant_api_key
        if parser_key is None or qdrant_key is None:
            raise ValueError("production ingestion workers require parser and Qdrant credentials")
        self._validate_distinct_credentials(
            [
                ("parser key", parser_key.get_secret_value()),
                ("Qdrant key", qdrant_key.get_secret_value()),
            ]
        )

    def _validate_production_migration(self) -> None:
        if self.worker_metrics_port:
            raise ValueError("production migrations must not expose a metrics listener")
        if self.api_keys.strip() not in {"", "local-dev-key"} or self.metrics_api_key:
            raise ValueError("production migrations must not receive API or metrics keys")
        if self.llm_provider != "disabled" or self.llm_api_key or self.provider_canary_on_startup:
            raise ValueError("production migrations must not receive LLM configuration")
        if self.web_search_provider != "disabled" or self.tavily_api_key:
            raise ValueError("production migrations must not receive web-search credentials")
        if self.parser_service_token or self.malware_scanner_host:
            raise ValueError("production migrations must not receive parser or scanner credentials")
        if self.trust_proxy_headers:
            raise ValueError("production migrations must not trust proxy headers")
        api_role = self.postgres_api_role or ""
        worker_role = self.postgres_worker_role or ""
        role_pattern = r"[a-z_][a-z0-9_]{0,62}"
        if not re.fullmatch(role_pattern, api_role) or not re.fullmatch(role_pattern, worker_role):
            raise ValueError("production migrations require canonical PostgreSQL runtime roles")
        if api_role == worker_role:
            raise ValueError("production PostgreSQL API and worker roles must be distinct")

    @staticmethod
    def _validate_distinct_credentials(credentials: list[tuple[str, str]]) -> None:
        owners: dict[str, str] = {}
        for role, credential in credentials:
            prior_role = owners.setdefault(credential, role)
            if prior_role != role:
                raise ValueError(
                    "production role credentials must be pairwise distinct: "
                    f"{prior_role} and {role} collide"
                )

    def _validate_production_observability(self, role: str) -> None:
        if not self.telemetry_enabled or not self.otel_exporter_otlp_endpoint:
            raise ValueError("production runtime roles require OTLP telemetry")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,62}", self.otel_service_name):
            raise ValueError("production OpenTelemetry service names must be canonical")
        try:
            parsed = urlparse(self.otel_exporter_otlp_endpoint)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("production OTLP endpoint is malformed") from exc
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username
            or parsed.password
            or parsed.path.rstrip("/") != "/v1/traces"
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("production OTLP endpoint must be credential-free HTTPS /v1/traces")
        if self.otel_exporter_ca_file is not None:
            ca_file = self.otel_exporter_ca_file
            if not ca_file.is_absolute() or not ca_file.is_file():
                raise ValueError("production OTLP CA file must be an existing absolute file")
            try:
                size = ca_file.stat().st_size
            except OSError as exc:
                raise ValueError("production OTLP CA file cannot be inspected") from exc
            if not 1 <= size <= 1024 * 1024:
                raise ValueError("production OTLP CA file size is invalid")
        if not self.cost_accounting_enabled:
            raise ValueError("production runtime roles require cost accounting")
        if role == "api":
            model_prices = (
                self.router_input_cost_per_million_usd,
                self.router_output_cost_per_million_usd,
                self.answer_input_cost_per_million_usd,
                self.answer_output_cost_per_million_usd,
            )
            if self.query_compute_cost_per_hour_usd <= 0 and not any(model_prices):
                raise ValueError("production API requires a query or model cost allocation")
        elif self.ingestion_compute_cost_per_hour_usd <= 0:
            raise ValueError("production workers require an ingestion compute cost allocation")

    def _validate_postgres_dsn(self) -> None:
        if self.postgres_dsn is None:
            raise ValueError("production requires a PostgreSQL DSN")
        value = self.postgres_dsn.get_secret_value()
        if any(character.isspace() or ord(character) < 32 for character in value) or "\\" in value:
            raise ValueError("production PostgreSQL DSN contains invalid characters")
        try:
            parsed = urlparse(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("production PostgreSQL DSN is malformed") from exc
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        if (
            parsed.scheme not in {"postgres", "postgresql"}
            or not hostname
            or not parsed.path.strip("/")
            or parsed.fragment
            or parameters.get("sslmode") != ["verify-full"]
        ):
            raise ValueError(
                "production PostgreSQL DSN must name a database and use sslmode=verify-full"
            )

    def _validate_production_origins_and_hosts(self) -> None:
        origins = self.cors_origin_values
        hosts = self.trusted_host_values
        if not origins or not hosts:
            raise ValueError("production CORS origins and trusted hosts cannot be empty")
        for origin in origins:
            parsed = urlparse(origin)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "production CORS origins must be exact credential-free HTTPS origins"
                )
        hostname_pattern = re.compile(
            r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
            re.IGNORECASE,
        )
        for host in hosts:
            if host == "*" or "://" in host or "/" in host or any(ch.isspace() for ch in host):
                raise ValueError("production trusted hosts must be exact hostnames or IP addresses")
            candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                if not hostname_pattern.fullmatch(candidate):
                    raise ValueError(
                        "production trusted hosts contain a malformed hostname"
                    ) from None

    def ensure_directories(self) -> None:
        directories = [self.data_dir, self.artifact_dir]
        if self.object_store_backend == "local":
            directories.append(self.object_dir)
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        if not self.qdrant_url:
            self.qdrant_path.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
