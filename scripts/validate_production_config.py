"""Validate host-supplied invariants that Docker Compose interpolation cannot enforce."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from collections.abc import Mapping
from urllib.parse import parse_qs, unquote, urlparse

IMAGE_VARIABLES = (
    "CRISISWEAVE_API_IMAGE",
    "CRISISWEAVE_CADDY_IMAGE",
    "CRISISWEAVE_CLAMAV_IMAGE",
    "CRISISWEAVE_UI_IMAGE",
)
SHA256 = re.compile(r"[a-f0-9]{64}")
REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,254}[a-z0-9]")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
S3_BUCKET = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?")
POSITIVE_SCALE_VARIABLES = {
    "CRISISWEAVE_API_WORKERS": (2, 64),
    "CRISISWEAVE_POSTGRES_POOL_MIN_SIZE": (1, 32),
    "CRISISWEAVE_POSTGRES_POOL_MAX_SIZE": (8, 128),
}
POSTGRES_DSN_VARIABLES = (
    "CRISISWEAVE_API_POSTGRES_DSN",
    "CRISISWEAVE_WORKER_POSTGRES_DSN",
    "CRISISWEAVE_MIGRATION_POSTGRES_DSN",
)
QDRANT_KEY_VARIABLES = (
    "CRISISWEAVE_API_QDRANT_API_KEY",
    "CRISISWEAVE_WORKER_QDRANT_API_KEY",
    "CRISISWEAVE_MIGRATION_QDRANT_API_KEY",
)
S3_IDENTITY_VARIABLES = (
    "CRISISWEAVE_API_S3_ACCESS_KEY_ID",
    "CRISISWEAVE_WORKER_S3_ACCESS_KEY_ID",
)
SERVICE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}@[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
SERVICE_ROLES = {"viewer", "operator", "reviewer", "auditor", "admin"}


class ProductionConfigError(ValueError):
    """Raised when a release reference or gateway boundary is unsafe."""


def validate_image_reference(variable: str, reference: str) -> None:
    if reference != reference.strip() or reference.count("@") != 1:
        raise ProductionConfigError(f"{variable} must be one canonical digest reference")
    repository, separator, digest = reference.rpartition("@sha256:")
    if not separator or not SHA256.fullmatch(digest) or digest == "0" * 64:
        raise ProductionConfigError(
            f"{variable} must end in a non-placeholder lowercase @sha256 digest"
        )
    if (
        not REPOSITORY.fullmatch(repository)
        or "://" in repository
        or "//" in repository
        or ".." in repository
        or repository.startswith(("/", ".", "-"))
        or repository.endswith(("/", ".", "-", ":"))
        or ":" in repository.rsplit("/", 1)[-1]
    ):
        raise ProductionConfigError(f"{variable} must use a lowercase tag-free registry repository")


def validate_domain(domain: str) -> None:
    if (
        domain != domain.strip().lower()
        or len(domain) > 253
        or "." not in domain
        or any(not DNS_LABEL.fullmatch(label) for label in domain.split("."))
    ):
        raise ProductionConfigError(
            "CRISISWEAVE_DOMAIN must be a lowercase fully qualified DNS name"
        )


def validate_postgres_dsn(dsn: str, variable: str = "CRISISWEAVE_POSTGRES_DSN") -> None:
    """Require hostname-verified TLS without including the secret DSN in errors."""

    if (
        not dsn
        or dsn != dsn.strip()
        or any(character.isspace() or ord(character) < 32 for character in dsn)
    ):
        raise ProductionConfigError(f"{variable} contains invalid characters")
    if "\\" in dsn:
        raise ProductionConfigError(f"{variable} contains invalid characters")
    try:
        parsed = urlparse(dsn)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ProductionConfigError(f"{variable} is malformed") from exc
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or not hostname
        or not parsed.path.strip("/")
        or parsed.params
        or parsed.fragment
        or parameters.get("sslmode") != ["verify-full"]
    ):
        raise ProductionConfigError(f"{variable} must name a database and use sslmode=verify-full")


def validate_role_isolation(environment: Mapping[str, str]) -> None:
    """Require separate runtime/migration identities targeting the same backing services."""

    role_pattern = re.compile(r"[a-z_][a-z0-9_]{0,62}")
    api_role = environment.get("CRISISWEAVE_POSTGRES_API_ROLE", "")
    worker_role = environment.get("CRISISWEAVE_POSTGRES_WORKER_ROLE", "")
    if not role_pattern.fullmatch(api_role) or not role_pattern.fullmatch(worker_role):
        raise ProductionConfigError("PostgreSQL runtime role names must be canonical identifiers")
    if api_role == worker_role:
        raise ProductionConfigError("PostgreSQL API and worker roles must be distinct")

    usernames: list[str] = []
    targets: list[tuple[str | None, int | None, str]] = []
    for variable in POSTGRES_DSN_VARIABLES:
        dsn = environment.get(variable, "")
        validate_postgres_dsn(dsn, variable)
        parsed = urlparse(dsn)
        username = unquote(parsed.username or "")
        if not role_pattern.fullmatch(username):
            raise ProductionConfigError(f"{variable} must contain a canonical service role")
        usernames.append(username)
        targets.append((parsed.hostname, parsed.port, parsed.path))
    if len(set(usernames)) != len(usernames):
        raise ProductionConfigError("PostgreSQL API, worker, and migration identities must differ")
    if usernames[:2] != [api_role, worker_role]:
        raise ProductionConfigError(
            "PostgreSQL runtime DSN users must match the granted role names"
        )
    if len(set(targets)) != 1:
        raise ProductionConfigError("all PostgreSQL role DSNs must target the same database")

    qdrant_keys = [environment.get(variable, "") for variable in QDRANT_KEY_VARIABLES]
    if any(len(value) < 24 for value in qdrant_keys) or len(set(qdrant_keys)) != len(qdrant_keys):
        raise ProductionConfigError(
            "Qdrant API, worker, and migration credentials must be strong and distinct"
        )

    s3_access_ids = [environment.get(variable, "") for variable in S3_IDENTITY_VARIABLES]
    s3_secrets = [
        environment.get("CRISISWEAVE_API_S3_SECRET_ACCESS_KEY", ""),
        environment.get("CRISISWEAVE_WORKER_S3_SECRET_ACCESS_KEY", ""),
    ]
    if (
        any(not value.strip() for value in s3_access_ids)
        or len(set(s3_access_ids)) != len(s3_access_ids)
        or any(len(value) < 24 for value in s3_secrets)
        or len(set(s3_secrets)) != len(s3_secrets)
    ):
        raise ProductionConfigError("S3 API and worker credentials must be strong and distinct")


def _validate_https_origin(variable: str, value: str) -> None:
    if value != value.strip() or "\\" in value or any(ord(character) < 32 for character in value):
        raise ProductionConfigError(f"{variable} must be an exact credential-free HTTPS origin")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ProductionConfigError(
            f"{variable} must be an exact credential-free HTTPS origin"
        ) from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ProductionConfigError(f"{variable} must be an exact credential-free HTTPS origin")


def validate_observability_configuration(environment: Mapping[str, str]) -> None:
    variable = "CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT"
    value = environment.get(variable, "")
    if value != value.strip() or "\\" in value or any(ord(ch) < 32 for ch in value):
        raise ProductionConfigError(f"{variable} must be a credential-free HTTPS trace endpoint")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ProductionConfigError(
            f"{variable} must be a credential-free HTTPS trace endpoint"
        ) from exc
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
        raise ProductionConfigError(
            f"{variable} must be a credential-free HTTPS /v1/traces endpoint"
        )
    ca_path = environment.get("CRISISWEAVE_OTEL_CA_HOST_PATH", "")
    if not ca_path.startswith("/") or "\\" in ca_path or ".." in ca_path.split("/"):
        raise ProductionConfigError(
            "CRISISWEAVE_OTEL_CA_HOST_PATH must be an absolute Linux CA-bundle path"
        )
    for cost_variable in (
        "CRISISWEAVE_QUERY_COMPUTE_COST_PER_HOUR_USD",
        "CRISISWEAVE_INGESTION_COMPUTE_COST_PER_HOUR_USD",
    ):
        raw = environment.get(cost_variable, "")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", raw):
            raise ProductionConfigError(f"{cost_variable} must be a canonical decimal")
        if not 0 < float(raw) <= 1_000_000:
            raise ProductionConfigError(f"{cost_variable} must be positive and bounded")


def validate_identity_boundary(environment: Mapping[str, str]) -> None:
    auth_mode = environment.get("CRISISWEAVE_AUTH_MODE", "oidc")
    if auth_mode not in {"oidc", "hybrid"}:
        raise ProductionConfigError("production authentication must use oidc or hybrid mode")
    for variable in ("CRISISWEAVE_OIDC_ISSUER_URL", "CRISISWEAVE_OIDC_JWKS_URL"):
        value = environment.get(variable, "")
        if value != value.strip() or "\\" in value or any(ord(ch) < 32 for ch in value):
            raise ProductionConfigError(f"{variable} must be a credential-free HTTPS URL")
        try:
            parsed = urlparse(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ProductionConfigError(f"{variable} must be a credential-free HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username
            or parsed.password
            or parsed.params
            or parsed.query
            or parsed.fragment
            or any(part == ".." for part in parsed.path.split("/"))
        ):
            raise ProductionConfigError(f"{variable} must be a credential-free HTTPS URL")
    audience = environment.get("CRISISWEAVE_OIDC_AUDIENCE", "")
    if not 1 <= len(audience) <= 255 or audience != audience.strip():
        raise ProductionConfigError("CRISISWEAVE_OIDC_AUDIENCE is malformed")
    algorithms = {
        item.strip()
        for item in environment.get("CRISISWEAVE_OIDC_ALGORITHMS", "RS256,ES256").split(",")
        if item.strip()
    }
    if not algorithms or not algorithms <= {"RS256", "ES256"}:
        raise ProductionConfigError("OIDC algorithms must be RS256 and/or ES256")
    proxy_networks = [
        item.strip()
        for item in environment.get("CRISISWEAVE_FORWARDED_ALLOW_IPS", "").split(",")
        if item.strip()
    ]
    if not proxy_networks:
        raise ProductionConfigError("trusted proxy CIDRs are required")
    for value in proxy_networks:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ProductionConfigError("trusted proxy entries must be canonical CIDRs") from exc
        if network.prefixlen == 0:
            raise ProductionConfigError("global trusted proxy ranges are forbidden")
    try:
        gateway_address = ipaddress.IPv4Address(environment.get("CRISISWEAVE_GATEWAY_IPV4", ""))
        gateway_network = ipaddress.IPv4Network(
            environment.get("CRISISWEAVE_API_GATEWAY_SUBNET", ""), strict=True
        )
    except ValueError as exc:
        raise ProductionConfigError(
            "the Compose gateway requires canonical IPv4 addressing"
        ) from exc
    if (
        not gateway_address.is_private
        or not gateway_network.is_private
        or not 24 <= gateway_network.prefixlen <= 28
        or gateway_address not in gateway_network
        or gateway_address in {gateway_network.network_address, gateway_network.broadcast_address}
    ):
        raise ProductionConfigError(
            "the Compose gateway address must be usable in its private subnet"
        )
    expected_proxy = ipaddress.ip_network(f"{gateway_address}/32")
    if len(proxy_networks) != 1 or ipaddress.ip_network(proxy_networks[0]) != expected_proxy:
        raise ProductionConfigError(
            "CRISISWEAVE_FORWARDED_ALLOW_IPS must trust only the configured gateway address"
        )

    raw_keys = environment.get("CRISISWEAVE_API_KEYS", "").strip()
    raw_bindings = environment.get("CRISISWEAVE_SERVICE_KEY_ROLE_BINDINGS", "").strip()
    raw_revocations = environment.get("CRISISWEAVE_REVOKED_SERVICE_KEY_IDS", "").strip()
    if auth_mode == "oidc":
        if raw_keys or raw_bindings or raw_revocations:
            raise ProductionConfigError(
                "OIDC-only production configuration must not contain service-key material"
            )
        return

    credentials: dict[str, str] = {}
    secrets: set[str] = set()
    for record in raw_keys.split(","):
        if not record:
            continue
        if record != record.strip() or record.count("=") != 1:
            raise ProductionConfigError("production service keys must use tenant@key_id=secret")
        identity, secret = record.split("=", 1)
        if (
            not SERVICE_IDENTITY.fullmatch(identity)
            or len(secret) < 24
            or any(character.isspace() or ord(character) < 32 for character in secret)
        ):
            raise ProductionConfigError(
                "production service keys require a valid identity and a 24-character secret"
            )
        if identity in credentials or secret in secrets:
            raise ProductionConfigError(
                "production service-key identities and secrets must be unique"
            )
        credentials[identity] = secret
        secrets.add(secret)

    bindings: set[str] = set()
    for record in raw_bindings.split(","):
        if not record:
            continue
        if record != record.strip() or record.count("=") != 1:
            raise ProductionConfigError("service-key roles must use tenant@key_id=role|role")
        identity, role_text = record.split("=", 1)
        roles = {role.strip().lower() for role in role_text.split("|") if role.strip()}
        if (
            not SERVICE_IDENTITY.fullmatch(identity)
            or identity in bindings
            or not roles
            or not roles <= SERVICE_ROLES
        ):
            raise ProductionConfigError("service-key role bindings are malformed")
        bindings.add(identity)

    if not credentials or bindings != set(credentials):
        raise ProductionConfigError(
            "hybrid production authentication requires an explicit role binding "
            "for every service key"
        )

    revoked = {identity.strip() for identity in raw_revocations.split(",") if identity.strip()}
    if any(not SERVICE_IDENTITY.fullmatch(identity) for identity in revoked):
        raise ProductionConfigError("revoked service-key identities are malformed")
    if not set(credentials) - revoked:
        raise ProductionConfigError("at least one production service key must remain active")


def validate_s3_configuration(environment: Mapping[str, str]) -> None:
    """Validate the static half of the versioned S3 contract.

    The S3 adapter's readiness probe verifies that versioning is actually enabled on the
    remote bucket. This preflight validates every host-supplied value before Compose starts.
    """

    bucket = environment.get("CRISISWEAVE_S3_BUCKET", "")
    if (
        bucket != bucket.strip().lower()
        or not S3_BUCKET.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        raise ProductionConfigError(
            "CRISISWEAVE_S3_BUCKET must be a lowercase DNS-compatible bucket name"
        )
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        pass
    else:
        raise ProductionConfigError("CRISISWEAVE_S3_BUCKET cannot be an IP address")

    prefix = environment.get("CRISISWEAVE_S3_PREFIX", "crisisweave")
    parts = prefix.split("/")
    if (
        not prefix
        or prefix != prefix.strip("/")
        or "\\" in prefix
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 for character in prefix)
    ):
        raise ProductionConfigError(
            "CRISISWEAVE_S3_PREFIX must be a non-empty relative object namespace"
        )

    region = environment.get("CRISISWEAVE_S3_REGION", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", region):
        raise ProductionConfigError("CRISISWEAVE_S3_REGION must be an explicit signing region")

    endpoint = environment.get("CRISISWEAVE_S3_ENDPOINT_URL", "")
    if endpoint:
        _validate_https_origin("CRISISWEAVE_S3_ENDPOINT_URL", endpoint)

    addressing_style = environment.get("CRISISWEAVE_S3_ADDRESSING_STYLE", "auto")
    if addressing_style not in {"auto", "path", "virtual"}:
        raise ProductionConfigError(
            "CRISISWEAVE_S3_ADDRESSING_STYLE must be auto, path, or virtual"
        )
    encryption = environment.get("CRISISWEAVE_S3_SERVER_SIDE_ENCRYPTION", "AES256")
    if encryption not in {"AES256", "aws:kms"}:
        raise ProductionConfigError(
            "CRISISWEAVE_S3_SERVER_SIDE_ENCRYPTION must be AES256 or aws:kms"
        )
    if encryption == "aws:kms" and not environment.get("CRISISWEAVE_S3_KMS_KEY_ID", "").strip():
        raise ProductionConfigError(
            "CRISISWEAVE_S3_KMS_KEY_ID is required when S3 encryption uses aws:kms"
        )


def validate_scale_values(environment: Mapping[str, str]) -> None:
    parsed: dict[str, int] = {}
    for variable, (default, maximum) in POSITIVE_SCALE_VARIABLES.items():
        value = environment.get(variable, str(default))
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise ProductionConfigError(f"{variable} must be a canonical positive integer")
        parsed[variable] = int(value)
        if parsed[variable] > maximum:
            raise ProductionConfigError(f"{variable} exceeds the production safety limit")
    if parsed["CRISISWEAVE_POSTGRES_POOL_MIN_SIZE"] > parsed["CRISISWEAVE_POSTGRES_POOL_MAX_SIZE"]:
        raise ProductionConfigError(
            "CRISISWEAVE_POSTGRES_POOL_MIN_SIZE cannot exceed the maximum pool size"
        )


def validate_environment(environment: Mapping[str, str]) -> None:
    missing = [
        name
        for name in (
            *IMAGE_VARIABLES,
            "CRISISWEAVE_DOMAIN",
            *POSTGRES_DSN_VARIABLES,
            "CRISISWEAVE_POSTGRES_API_ROLE",
            "CRISISWEAVE_POSTGRES_WORKER_ROLE",
            "CRISISWEAVE_QDRANT_URL",
            *QDRANT_KEY_VARIABLES,
            *S3_IDENTITY_VARIABLES,
            "CRISISWEAVE_API_S3_SECRET_ACCESS_KEY",
            "CRISISWEAVE_WORKER_S3_SECRET_ACCESS_KEY",
            "CRISISWEAVE_S3_BUCKET",
            "CRISISWEAVE_S3_REGION",
            "CRISISWEAVE_OTEL_EXPORTER_OTLP_ENDPOINT",
            "CRISISWEAVE_QUERY_COMPUTE_COST_PER_HOUR_USD",
            "CRISISWEAVE_INGESTION_COMPUTE_COST_PER_HOUR_USD",
            "CRISISWEAVE_OIDC_ISSUER_URL",
            "CRISISWEAVE_OIDC_AUDIENCE",
            "CRISISWEAVE_OIDC_JWKS_URL",
            "CRISISWEAVE_FORWARDED_ALLOW_IPS",
            "CRISISWEAVE_GATEWAY_IPV4",
            "CRISISWEAVE_API_GATEWAY_SUBNET",
            "CRISISWEAVE_OTEL_CA_HOST_PATH",
            "CRISISWEAVE_EGRESS_POLICY_SHA256",
        )
        if not environment.get(name)
    ]
    if missing:
        raise ProductionConfigError(f"missing required production variable: {missing[0]}")

    egress_policy_digest = environment["CRISISWEAVE_EGRESS_POLICY_SHA256"]
    if not SHA256.fullmatch(egress_policy_digest) or egress_policy_digest == "0" * 64:
        raise ProductionConfigError(
            "CRISISWEAVE_EGRESS_POLICY_SHA256 must bind the reviewed deployment policy"
        )

    references: list[str] = []
    for variable in IMAGE_VARIABLES:
        reference = environment[variable]
        validate_image_reference(variable, reference)
        references.append(reference)
    if len(set(references)) != len(references):
        raise ProductionConfigError("production service images must use distinct references")

    domain = environment["CRISISWEAVE_DOMAIN"]
    validate_domain(domain)
    origins = {
        value.strip()
        for value in environment.get("CRISISWEAVE_CORS_ORIGINS", "").split(",")
        if value.strip()
    }
    if f"https://{domain}" not in origins:
        raise ProductionConfigError("CORS origins must contain the gateway's exact HTTPS origin")
    trusted_hosts = {
        value.strip().lower()
        for value in environment.get("CRISISWEAVE_TRUSTED_HOSTS", "").split(",")
        if value.strip()
    }
    if not {domain, "api"} <= trusted_hosts:
        raise ProductionConfigError("trusted hosts must contain the gateway domain and api")

    _validate_https_origin("CRISISWEAVE_QDRANT_URL", environment["CRISISWEAVE_QDRANT_URL"])
    validate_role_isolation(environment)
    validate_s3_configuration(environment)
    validate_scale_values(environment)
    validate_observability_configuration(environment)
    validate_identity_boundary(environment)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    try:
        validate_environment(os.environ)
    except ProductionConfigError as exc:
        parser.error(str(exc))
    print(
        "Validated immutable images, gateway boundary, isolated PostgreSQL/S3/Qdrant "
        "identities, versioned S3 configuration, and scale limits."
    )


if __name__ == "__main__":
    main()
