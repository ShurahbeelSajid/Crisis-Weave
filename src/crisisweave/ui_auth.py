"""Authentication boundary for the thin Streamlit client."""

from __future__ import annotations

import re
from typing import Literal

UIAuthMode = Literal["api_key", "forwarded_bearer"]

_JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,4096}")


class UIAuthenticationError(ValueError):
    """Raised when the UI has no safe credential to send to the API."""


def api_auth_headers(
    mode: UIAuthMode,
    *,
    api_key: str,
    forwarded_authorization: str | None,
) -> dict[str, str]:
    """Return only the credential permitted by the configured UI trust boundary."""

    if mode == "api_key":
        if not api_key or len(api_key) > 4096 or any(character.isspace() for character in api_key):
            raise UIAuthenticationError("Enter a valid scoped API key in the sidebar.")
        return {"X-API-Key": api_key}

    if mode != "forwarded_bearer":
        raise UIAuthenticationError("The operator-configured UI authentication mode is invalid.")
    if not forwarded_authorization or len(forwarded_authorization) > 16_391:
        raise UIAuthenticationError("Sign in through the organizational access gateway.")
    scheme, separator, token = forwarded_authorization.partition(" ")
    if (
        not separator
        or scheme.casefold() != "bearer"
        or not _JWT_PATTERN.fullmatch(token)
        or any(character in forwarded_authorization for character in "\r\n")
    ):
        raise UIAuthenticationError("The organizational access token is missing or malformed.")
    return {"Authorization": f"Bearer {token}"}
