"""Authentication, service-key rotation, and authorization policy."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import socket
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any, Protocol
from urllib.parse import urlparse

import httpx
from fastapi import Depends, Header, HTTPException, Request, status

if TYPE_CHECKING:
    from crisisweave.config import Settings


_TENANT_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class IdentityType(StrEnum):
    USER = "user"
    SERVICE = "service"


class Permission(StrEnum):
    QUERY = "query:execute"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_WRITE = "evidence:write"
    EVIDENCE_DELETE = "evidence:delete"
    JOB_CONTROL = "jobs:control"
    REVIEW_READ = "reviews:read"
    REVIEW_DECIDE = "reviews:decide"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset({Permission.QUERY, Permission.EVIDENCE_READ}),
    "operator": frozenset(
        {
            Permission.QUERY,
            Permission.EVIDENCE_READ,
            Permission.EVIDENCE_WRITE,
            Permission.EVIDENCE_DELETE,
            Permission.JOB_CONTROL,
        }
    ),
    "reviewer": frozenset(
        {
            Permission.QUERY,
            Permission.EVIDENCE_READ,
            Permission.REVIEW_READ,
            Permission.REVIEW_DECIDE,
        }
    ),
    "auditor": frozenset({Permission.EVIDENCE_READ, Permission.REVIEW_READ, Permission.AUDIT_READ}),
}
ROLE_PERMISSIONS["admin"] = frozenset(Permission)


class AuthenticationError(ValueError):
    """A bounded authentication failure safe to translate into HTTP 401."""


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    tenant_label: str
    subject_id: str
    identity_type: IdentityType
    roles: frozenset[str]
    permissions: frozenset[Permission]
    auth_method: str
    credential_id: str | None = None

    def permits(self, permission: Permission) -> bool:
        return permission in self.permissions


@dataclass(frozen=True)
class ServiceCredential:
    tenant_label: str
    key_id: str
    secret: str
    roles: frozenset[str]
    revoked: bool = False


class TokenVerifier(Protocol):
    """Injectable OIDC verifier contract; tests never need a fake identity provider."""

    def verify(self, token: str) -> Principal: ...


def tenant_identifier(label: str) -> str:
    return hashlib.sha256(f"crisisweave-tenant:{label}".encode()).hexdigest()[:32]


def _permissions(roles: frozenset[str]) -> frozenset[Permission]:
    permissions: set[Permission] = set()
    for role in roles:
        permissions.update(ROLE_PERMISSIONS.get(role, ()))
    return frozenset(permissions)


def _derived_key_id(secret: str) -> str:
    return f"sha256-{hashlib.sha256(secret.encode()).hexdigest()[:16]}"


def parse_service_credentials(
    raw_keys: str,
    raw_bindings: str = "",
    raw_revocations: str = "",
    *,
    production: bool = False,
) -> tuple[ServiceCredential, ...]:
    """Parse overlap-safe ``tenant@key_id=secret`` service credentials.

    Legacy ``tenant=secret`` and unscoped local keys remain supported outside production.
    Role bindings use ``tenant@key_id=operator|viewer``. Production keys require explicit
    IDs and bindings so rotation and revocation are auditable rather than secret-derived.
    """

    bindings: dict[str, frozenset[str]] = {}
    for raw in raw_bindings.split(","):
        value = raw.strip()
        if not value:
            continue
        if "=" not in value:
            raise ValueError("service key role bindings must use tenant@key_id=role|role")
        identity, role_text = value.split("=", 1)
        roles = frozenset(item.strip().lower() for item in role_text.split("|") if item.strip())
        if not roles or not roles <= set(ROLE_PERMISSIONS):
            raise ValueError("service key role bindings contain an unknown or empty role")
        if identity in bindings:
            raise ValueError("service key role binding is duplicated")
        bindings[identity] = roles

    revoked = {item.strip() for item in raw_revocations.split(",") if item.strip()}
    records: list[ServiceCredential] = []
    identities: set[str] = set()
    secrets: dict[str, str] = {}
    for raw in raw_keys.split(","):
        value = raw.strip()
        if not value:
            continue
        explicit_scope = "=" in value
        left, secret = value.split("=", 1) if explicit_scope else ("default", value)
        left = left.strip()
        secret = secret.strip()
        if not left or not secret:
            raise ValueError("service API keys cannot have empty identities or secrets")
        explicit_id = "@" in left
        tenant_label, key_id = (
            left.rsplit("@", 1) if explicit_id else (left, _derived_key_id(secret))
        )
        if not _TENANT_LABEL.fullmatch(tenant_label) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("service API key tenant labels and key IDs are malformed")
        identity = f"{tenant_label}@{key_id}"
        if identity in identities:
            raise ValueError("service API key identity is duplicated")
        prior = secrets.setdefault(secret, tenant_label)
        if prior != tenant_label:
            raise ValueError("one service API key cannot be assigned to multiple tenants")
        if production and (not explicit_scope or not explicit_id or identity not in bindings):
            raise ValueError("production service keys require tenant@key_id and explicit roles")
        roles = bindings.get(identity, frozenset({"admin"}))
        records.append(
            ServiceCredential(
                tenant_label=tenant_label,
                key_id=key_id,
                secret=secret,
                roles=roles,
                revoked=identity in revoked,
            )
        )
        identities.add(identity)
    unknown_bindings = set(bindings) - identities
    unknown_revocations = revoked - identities
    if unknown_bindings:
        raise ValueError("service role bindings reference unknown key identities")
    if unknown_revocations:
        raise ValueError("service revocations reference unknown key identities")
    return tuple(records)


def resolve_service_principal(
    candidate: str | None,
    credentials: tuple[ServiceCredential, ...],
) -> Principal | None:
    if not candidate:
        return None
    match: ServiceCredential | None = None
    candidate_bytes = candidate.encode()
    # Do not return early: credential count, rather than key position, determines work.
    for credential in credentials:
        if hmac.compare_digest(candidate_bytes, credential.secret.encode()):
            match = credential
    if match is None or match.revoked:
        return None
    identity = f"{match.tenant_label}@{match.key_id}"
    return Principal(
        tenant_id=tenant_identifier(match.tenant_label),
        tenant_label=match.tenant_label,
        subject_id=identity,
        identity_type=IdentityType.SERVICE,
        roles=match.roles,
        permissions=_permissions(match.roles),
        auth_method="api_key",
        credential_id=match.key_id,
    )


def resolve_principal(
    candidate: str | None,
    credentials: tuple[tuple[str, str], ...],
) -> Principal | None:
    """Backward-compatible local resolver used by middleware unit tests."""

    parsed = tuple(
        ServiceCredential(label, _derived_key_id(secret), secret, frozenset({"admin"}))
        for label, secret in credentials
    )
    return resolve_service_principal(candidate, parsed)


class _StrictJWKSClient:
    """Bounded, no-redirect JWKS fetcher with explicit network policy and caching."""

    def __init__(
        self,
        *,
        jwt_module: Any,
        url: str,
        algorithms: tuple[str, ...],
        cache_seconds: int,
        timeout_seconds: float,
        max_bytes: int,
        allow_private: bool,
    ) -> None:
        self._jwt = jwt_module
        self._url = url
        self._algorithms = frozenset(algorithms)
        self._cache_seconds = cache_seconds
        self._timeout_seconds = timeout_seconds
        self._max_bytes = max_bytes
        self._allow_private = allow_private
        self._lock = threading.Lock()
        self._expires_at = 0.0
        self._keys: tuple[tuple[str, str, Any], ...] = ()

    def _validate_destination(self) -> None:
        parsed = urlparse(self._url)
        hostname = parsed.hostname
        if parsed.scheme != "https" or hostname is None:
            raise AuthenticationError("JWKS destination is invalid")
        try:
            addresses = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise AuthenticationError("JWKS destination could not be resolved") from exc
        if not addresses:
            raise AuthenticationError("JWKS destination could not be resolved")
        if self._allow_private:
            return
        for address in addresses:
            raw_address = str(address[4][0]).split("%", 1)[0]
            try:
                parsed_address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise AuthenticationError("JWKS destination resolved unexpectedly") from exc
            if not parsed_address.is_global:
                raise AuthenticationError("JWKS destination resolved to a non-public address")

    def _fetch(self) -> tuple[tuple[str, str, Any], ...]:
        self._validate_destination()
        timeout = httpx.Timeout(self._timeout_seconds)
        limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
        try:
            with (
                httpx.Client(
                    follow_redirects=False,
                    trust_env=False,
                    timeout=timeout,
                    limits=limits,
                ) as client,
                client.stream(
                    "GET",
                    self._url,
                    headers={
                        "Accept": "application/jwk-set+json, application/json",
                        "User-Agent": "CrisisWeave-JWKS/1",
                    },
                ) as response,
            ):
                if response.status_code != 200:
                    raise AuthenticationError("JWKS endpoint returned an invalid status")
                media_type = response.headers.get("content-type", "").partition(";")[0]
                if media_type.lower() not in {
                    "application/json",
                    "application/jwk-set+json",
                }:
                    raise AuthenticationError("JWKS endpoint returned an invalid media type")
                raw_length = response.headers.get("content-length")
                if raw_length and raw_length.isdecimal() and int(raw_length) > self._max_bytes:
                    raise AuthenticationError("JWKS response exceeds its size limit")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_bytes:
                        raise AuthenticationError("JWKS response exceeds its size limit")
        except AuthenticationError:
            raise
        except (httpx.HTTPError, OSError) as exc:
            raise AuthenticationError("JWKS endpoint could not be reached securely") from exc
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthenticationError("JWKS response is not valid JSON") from exc
        raw_keys = payload.get("keys") if isinstance(payload, dict) else None
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 100:
            raise AuthenticationError("JWKS response has an invalid key set")
        keys: list[tuple[str, str, Any]] = []
        identities: set[tuple[str, str]] = set()
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise AuthenticationError("JWKS response contains an invalid key")
            if raw_key.get("use", "sig") != "sig":
                continue
            key_operations = raw_key.get("key_ops", ["verify"])
            if not isinstance(key_operations, list) or "verify" not in key_operations:
                continue
            algorithm = raw_key.get("alg")
            key_type = raw_key.get("kty")
            if algorithm not in self._algorithms or key_type not in {"RSA", "EC"}:
                continue
            key_id = raw_key.get("kid")
            if (
                not isinstance(key_id, str)
                or not 1 <= len(key_id) <= 255
                or any(ord(character) < 32 for character in key_id)
                or "jku" in raw_key
                or "x5u" in raw_key
            ):
                raise AuthenticationError("JWKS response contains an unsafe key identity")
            identity = (key_id, algorithm)
            if identity in identities:
                raise AuthenticationError("JWKS response contains duplicate key identities")
            try:
                parsed_key = self._jwt.PyJWK.from_dict(raw_key)
            except Exception as exc:
                raise AuthenticationError("JWKS response contains an unusable key") from exc
            keys.append((key_id, algorithm, parsed_key.key))
            identities.add(identity)
        if not keys:
            raise AuthenticationError("JWKS response contains no allowed signing key")
        return tuple(keys)

    def signing_key(self, key_id: str, algorithm: str) -> Any:
        for refresh in (False, True):
            with self._lock:
                now = time.monotonic()
                if refresh or not self._keys or now >= self._expires_at:
                    self._keys = self._fetch()
                    self._expires_at = now + self._cache_seconds
                matches = [
                    key
                    for candidate_id, candidate_algorithm, key in self._keys
                    if candidate_id == key_id and candidate_algorithm == algorithm
                ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise AuthenticationError("JWKS key selection is ambiguous")
        raise AuthenticationError("Bearer token signing key is unavailable")


class OIDCJWTVerifier:
    """Strict asymmetric JWT validation against an explicitly configured OIDC JWKS."""

    def __init__(self, settings: Settings) -> None:
        if not settings.oidc_issuer_url or not settings.oidc_audience or not settings.oidc_jwks_url:
            raise RuntimeError("OIDC issuer, audience, and JWKS URL are required")
        try:
            import jwt
        except ImportError as exc:  # pragma: no cover - production dependency gate
            raise RuntimeError("PyJWT with cryptography support is required for OIDC") from exc
        self._jwt: Any = jwt
        self._issuer = settings.oidc_issuer_url
        self._audience = settings.oidc_audience
        self._tenant_claim = settings.oidc_tenant_claim
        self._roles_claim = settings.oidc_roles_claim
        self._identity_type_claim = settings.oidc_identity_type_claim
        self._algorithms = tuple(
            item.strip() for item in settings.oidc_algorithms.split(",") if item.strip()
        )
        self._clock_skew = settings.oidc_clock_skew_seconds
        self._jwks = _StrictJWKSClient(
            jwt_module=jwt,
            url=settings.oidc_jwks_url,
            algorithms=self._algorithms,
            cache_seconds=settings.oidc_jwks_cache_seconds,
            timeout_seconds=settings.oidc_jwks_timeout_seconds,
            max_bytes=settings.oidc_jwks_max_bytes,
            allow_private=settings.oidc_allow_private_jwks,
        )

    def verify(self, token: str) -> Principal:
        if not token or len(token) > 16_384 or token.count(".") != 2:
            raise AuthenticationError("Bearer token is malformed")
        try:
            header = self._jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            key_id = header.get("kid")
            if (
                algorithm not in self._algorithms
                or not isinstance(key_id, str)
                or not 1 <= len(key_id) <= 255
                or any(ord(character) < 32 for character in key_id)
            ):
                raise AuthenticationError("Bearer token algorithm or key ID is not allowed")
            token_type = header.get("typ")
            if token_type is not None and str(token_type).lower() not in {"jwt", "at+jwt"}:
                raise AuthenticationError("Bearer token type is not allowed")
            signing_key = self._jwks.signing_key(key_id, str(algorithm))
            claims = self._jwt.decode(
                token,
                signing_key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._clock_skew,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("Bearer token validation failed") from exc
        tenant_label = claims.get(self._tenant_claim)
        raw_roles = claims.get(self._roles_claim)
        subject = claims.get("sub")
        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self._audience:
            raise AuthenticationError("Bearer token authorized party is invalid")
        if not isinstance(tenant_label, str) or not _TENANT_LABEL.fullmatch(tenant_label):
            raise AuthenticationError("Bearer token tenant claim is missing or invalid")
        if (
            not isinstance(subject, str)
            or not 1 <= len(subject) <= 255
            or any(ord(character) < 32 for character in subject)
        ):
            raise AuthenticationError("Bearer token subject is missing or invalid")
        if isinstance(raw_roles, str):
            roles = frozenset(item for item in raw_roles.lower().split() if item)
        elif isinstance(raw_roles, list) and all(isinstance(item, str) for item in raw_roles):
            roles = frozenset(item.lower() for item in raw_roles)
        else:
            raise AuthenticationError("Bearer token roles claim is missing or invalid")
        if not roles or not roles <= set(ROLE_PERMISSIONS):
            raise AuthenticationError("Bearer token contains no authorized role set")
        raw_identity_type = claims.get(self._identity_type_claim)
        try:
            identity_type = IdentityType(raw_identity_type)
        except (TypeError, ValueError) as exc:
            raise AuthenticationError("Bearer token identity type is missing or invalid") from exc
        return Principal(
            tenant_id=tenant_identifier(tenant_label),
            tenant_label=tenant_label,
            subject_id=subject,
            identity_type=identity_type,
            roles=roles,
            permissions=_permissions(roles),
            auth_method="oidc",
            credential_id=str(header["kid"]),
        )


class Authenticator:
    def __init__(
        self,
        *,
        mode: str,
        service_credentials: tuple[ServiceCredential, ...],
        token_verifier: TokenVerifier | None,
    ) -> None:
        self.mode = mode
        self.service_credentials = service_credentials
        self.token_verifier = token_verifier

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
    ) -> Principal:
        if authorization and api_key:
            raise AuthenticationError("Multiple authentication methods are not allowed")
        if authorization:
            scheme, separator, token = authorization.partition(" ")
            if not separator or scheme.lower() != "bearer" or not token or " " in token:
                raise AuthenticationError("Authorization must contain one Bearer token")
            if self.mode not in {"oidc", "hybrid"} or self.token_verifier is None:
                raise AuthenticationError("Bearer authentication is not enabled")
            return self.token_verifier.verify(token)
        if api_key:
            if self.mode not in {"api_key", "hybrid"}:
                raise AuthenticationError("Service-key authentication is not enabled")
            principal = resolve_service_principal(api_key, self.service_credentials)
            if principal is not None:
                return principal
        raise AuthenticationError("Credentials are missing or invalid")


def build_authenticator(
    settings: Settings,
    *,
    token_verifier: TokenVerifier | None = None,
) -> Authenticator:
    service_credentials = parse_service_credentials(
        settings.api_keys,
        settings.service_key_role_bindings,
        settings.revoked_service_key_ids,
        production=settings.app_env == "production" and settings.auth_mode in {"api_key", "hybrid"},
    )
    if settings.auth_mode in {"oidc", "hybrid"} and token_verifier is None:
        token_verifier = OIDCJWTVerifier(settings)
    return Authenticator(
        mode=settings.auth_mode,
        service_credentials=service_credentials,
        token_verifier=token_verifier,
    )


def _http_auth_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer, ApiKey"},
    )


async def require_principal(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Principal:
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached
    try:
        principal = request.app.state.authenticator.authenticate(
            authorization=authorization,
            api_key=x_api_key,
        )
    except AuthenticationError as exc:
        raise _http_auth_error() from exc
    if not isinstance(principal, Principal):
        raise _http_auth_error()
    request.state.principal = principal
    return principal


def require_permission(permission: Permission) -> Any:
    async def authorized(
        request: Request,
        principal: Annotated[Principal, Depends(require_principal)],
    ) -> Principal:
        request.state.authorization_permission = permission.value
        if not principal.permits(permission):
            raise HTTPException(status_code=403, detail="Permission denied")
        return principal

    return authorized
