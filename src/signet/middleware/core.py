"""Core middleware logic: extract_bearer_token(), validate_token()."""

from __future__ import annotations

import enum

from signet.exceptions import OAuthError
from signet.middleware.models import TokenInfo
from signet.oauth.client import OAuthClient


class ValidationMode(enum.Enum):
    """Token validation strategy."""

    TOKEN_INFO = "token_info"
    INTROSPECTION = "introspection"


def extract_bearer_token(authorization: str) -> str:
    """Extract the token from an Authorization header value.

    The "Bearer" scheme is matched case-insensitively per RFC 6750.
    """
    if len(authorization) < 7 or authorization[:7].lower() != "bearer ":
        return ""
    return authorization[7:].strip()


def validate_token(
    client: OAuthClient,
    token: str,
    *,
    mode: ValidationMode = ValidationMode.TOKEN_INFO,
) -> TokenInfo:
    """Validate a Bearer token using the configured strategy."""
    if mode == ValidationMode.INTROSPECTION:
        return _validate_via_introspection(client, token)
    return _validate_via_token_info(client, token)


def _validate_via_token_info(client: OAuthClient, token: str) -> TokenInfo:
    result = client.token_info_request(token)
    if not result.active:
        raise OAuthError("invalid_token", "Token is not active")
    return TokenInfo(
        user_id=result.user_id,
        client_id=result.client_id,
        scope=result.scope,
        subject_type=result.subject_type,
        expires_at=result.exp,
    )


def _validate_via_introspection(client: OAuthClient, token: str) -> TokenInfo:
    result = client.introspect(token)
    if not result.active:
        raise OAuthError("invalid_token", "Token is not active")
    subject_type = "user"
    if result.sub.startswith("client:"):
        subject_type = "client"
    return TokenInfo(
        user_id=result.sub,
        client_id=result.client_id,
        scope=result.scope,
        subject_type=subject_type,
        expires_at=result.exp,
    )
