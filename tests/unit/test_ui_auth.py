from __future__ import annotations

import pytest

from crisisweave.ui_auth import UIAuthenticationError, api_auth_headers

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.signature_value"  # gitleaks:allow


def test_local_api_key_mode_sends_only_api_key() -> None:
    assert api_auth_headers(
        "api_key",
        api_key="local-scoped-key",
        forwarded_authorization=f"Bearer {JWT}",
    ) == {"X-API-Key": "local-scoped-key"}


def test_forwarded_bearer_mode_sends_only_ingress_token() -> None:
    assert api_auth_headers(
        "forwarded_bearer",
        api_key="must-be-ignored",
        forwarded_authorization=f"Bearer {JWT}",
    ) == {"Authorization": f"Bearer {JWT}"}


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Basic dXNlcjpwYXNz",
        "Bearer not-a-jwt",
        f"Bearer {JWT}\r\nX-Injected: yes",
        "Bearer part.one.",
    ],
)
def test_forwarded_bearer_rejects_missing_or_malformed_values(
    authorization: str | None,
) -> None:
    with pytest.raises(UIAuthenticationError):
        api_auth_headers(
            "forwarded_bearer",
            api_key="ignored",
            forwarded_authorization=authorization,
        )


@pytest.mark.parametrize("api_key", ["", "contains whitespace", "line\nbreak"])
def test_local_api_key_rejects_missing_or_malformed_values(api_key: str) -> None:
    with pytest.raises(UIAuthenticationError):
        api_auth_headers("api_key", api_key=api_key, forwarded_authorization=None)
