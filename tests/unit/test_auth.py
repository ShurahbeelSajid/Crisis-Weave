from __future__ import annotations

import pytest

from crisisweave import auth
from crisisweave.auth import (
    AuthenticationError,
    Authenticator,
    IdentityType,
    OIDCJWTVerifier,
    Permission,
    Principal,
    parse_service_credentials,
    resolve_service_principal,
    tenant_identifier,
)


def test_service_key_rotation_overlap_roles_and_revocation() -> None:
    credentials = parse_service_credentials(
        "alpha@old=old-secret,alpha@new=new-secret",
        "alpha@old=viewer,alpha@new=operator",
        "alpha@old",
        production=True,
    )

    assert resolve_service_principal("old-secret", credentials) is None
    principal = resolve_service_principal("new-secret", credentials)
    assert principal is not None
    assert principal.tenant_id == tenant_identifier("alpha")
    assert principal.credential_id == "new"
    assert principal.roles == frozenset({"operator"})
    assert principal.permits(Permission.EVIDENCE_WRITE)
    assert not principal.permits(Permission.REVIEW_DECIDE)


def test_production_service_keys_require_explicit_identity_and_roles() -> None:
    with pytest.raises(ValueError, match="tenant@key_id"):
        parse_service_credentials("alpha=secret", production=True)
    with pytest.raises(ValueError, match="explicit roles"):
        parse_service_credentials(
            "alpha@active=secret",
            "alpha@missing=viewer",
            production=True,
        )


class StaticVerifier:
    def verify(self, token: str) -> Principal:
        if token != "valid-token":
            raise AuthenticationError("invalid")
        return Principal(
            tenant_id=tenant_identifier("alpha"),
            tenant_label="alpha",
            subject_id="user-123",
            identity_type=IdentityType.USER,
            roles=frozenset({"reviewer"}),
            permissions=frozenset(
                {
                    Permission.QUERY,
                    Permission.EVIDENCE_READ,
                    Permission.REVIEW_READ,
                    Permission.REVIEW_DECIDE,
                }
            ),
            auth_method="oidc",
            credential_id="signing-key-1",
        )


def test_authenticator_accepts_injected_oidc_verifier_and_rejects_ambiguity() -> None:
    authenticator = Authenticator(
        mode="hybrid",
        service_credentials=parse_service_credentials("alpha=service-secret"),
        token_verifier=StaticVerifier(),
    )

    principal = authenticator.authenticate(
        authorization="Bearer valid-token",
        api_key=None,
    )
    assert principal.identity_type == IdentityType.USER
    assert principal.permits(Permission.REVIEW_DECIDE)

    with pytest.raises(AuthenticationError, match="Multiple"):
        authenticator.authenticate(
            authorization="Bearer valid-token",
            api_key="service-secret",
        )
    with pytest.raises(AuthenticationError, match="Bearer"):
        authenticator.authenticate(authorization="Basic valid-token", api_key=None)


def test_jwks_client_blocks_private_resolution_and_redirects(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client = auth._StrictJWKSClient(  # noqa: SLF001
        jwt_module=object(),
        url="https://identity.example.test/jwks.json",
        algorithms=("RS256",),
        cache_seconds=300,
        timeout_seconds=2,
        max_bytes=64 * 1024,
        allow_private=False,
    )
    monkeypatch.setattr(
        auth.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(AuthenticationError, match="non-public"):
        client._validate_destination()  # noqa: SLF001

    seen: dict[str, object] = {}

    class RedirectResponse:
        status_code = 302
        headers: dict[str, str] = {"location": "https://169.254.169.254/metadata"}

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args):  # type: ignore[no-untyped-def]
            return None

    class Client:
        def __init__(self, **kwargs):  # type: ignore[no-untyped-def]
            seen.update(kwargs)

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args):  # type: ignore[no-untyped-def]
            return None

        def stream(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return RedirectResponse()

    client._allow_private = True  # noqa: SLF001
    monkeypatch.setattr(auth.httpx, "Client", Client)
    with pytest.raises(AuthenticationError, match="invalid status"):
        client._fetch()  # noqa: SLF001
    assert seen["follow_redirects"] is False
    assert seen["trust_env"] is False


def test_oidc_verifier_requires_explicit_identity_type_claim() -> None:
    claims = {
        "iss": "https://identity.example.test",
        "aud": "crisisweave-api",
        "sub": "subject-1",
        "exp": 2_000_000_000,
        "iat": 1_900_000_000,
        "tenant_id": "alpha",
        "roles": ["reviewer"],
    }

    class JWT:
        @staticmethod
        def get_unverified_header(_token: str) -> dict[str, str]:
            return {"alg": "RS256", "kid": "key-1", "typ": "JWT"}

        @staticmethod
        def decode(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            return dict(claims)

    class Keys:
        @staticmethod
        def signing_key(_key_id: str, _algorithm: str) -> object:
            return object()

    verifier = object.__new__(OIDCJWTVerifier)
    verifier._jwt = JWT()  # noqa: SLF001
    verifier._issuer = "https://identity.example.test"  # noqa: SLF001
    verifier._audience = "crisisweave-api"  # noqa: SLF001
    verifier._tenant_claim = "tenant_id"  # noqa: SLF001
    verifier._roles_claim = "roles"  # noqa: SLF001
    verifier._identity_type_claim = "identity_type"  # noqa: SLF001
    verifier._algorithms = ("RS256",)  # noqa: SLF001
    verifier._clock_skew = 0  # noqa: SLF001
    verifier._jwks = Keys()  # noqa: SLF001

    with pytest.raises(AuthenticationError, match="identity type"):
        verifier.verify("header.payload.signature")

    claims["identity_type"] = "service"
    assert verifier.verify("header.payload.signature").identity_type == IdentityType.SERVICE
