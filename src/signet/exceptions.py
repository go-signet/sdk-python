"""Signet exception hierarchy."""

from __future__ import annotations


class SignetError(Exception):
    """Base exception for all Signet errors."""


class OAuthError(SignetError):
    """OAuth 2.0 protocol error (RFC 6749 SS5.2)."""

    def __init__(
        self,
        code: str,
        description: str = "",
        status_code: int = 0,
    ) -> None:
        self.code = code
        self.description = description
        self.status_code = status_code
        msg = f"oauth: {code}: {description}" if description else f"oauth: {code}"
        super().__init__(msg)


class DiscoveryError(SignetError):
    """Error during OIDC discovery."""


class CredStoreError(SignetError):
    """Error in credential storage operations."""


class NotFoundError(CredStoreError):
    """No data found for the given client ID."""


class AuthFlowError(SignetError):
    """Error during an authentication flow."""


class TokenExpiredError(AuthFlowError):
    """The device code or token has expired."""


class AccessDeniedError(AuthFlowError):
    """Access was denied by the user or server."""
