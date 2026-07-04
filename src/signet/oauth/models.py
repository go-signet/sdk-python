"""OAuth 2.0 data models."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class Token:
    """OAuth 2.0 token response (RFC 6749 SS5.1)."""

    access_token: str = ""
    refresh_token: str = ""
    token_type: str = ""
    expires_in: int = 0
    scope: str = ""
    id_token: str = ""
    expires_at: float = 0.0

    def is_expired(self) -> bool:
        """Report whether the token has expired."""
        return self.expires_at > 0 and time.time() > self.expires_at

    def is_valid(self) -> bool:
        """Report whether the token has a non-empty access token and is not expired."""
        return bool(self.access_token) and not self.is_expired()


@dataclass
class DeviceAuth:
    """Device authorization response (RFC 8628 SS3.2)."""

    device_code: str = ""
    user_code: str = ""
    verification_uri: str = ""
    verification_uri_complete: str = ""
    expires_in: int = 0
    interval: int = 0


@dataclass
class IntrospectionResult:
    """Token introspection response (RFC 7662 SS2.2)."""

    active: bool = False
    scope: str = ""
    client_id: str = ""
    username: str = ""
    token_type: str = ""
    exp: int = 0
    iat: int = 0
    sub: str = ""
    iss: str = ""
    jti: str = ""


@dataclass
class UserInfo:
    """OIDC UserInfo response (OIDC Core 1.0 SS5.3)."""

    sub: str = ""
    iss: str = ""
    name: str = ""
    preferred_username: str = ""
    email: str = ""
    email_verified: bool = False
    picture: str = ""
    updated_at: int = 0
    subject_type: str = ""


@dataclass
class TokenInfo:
    """Signet tokeninfo endpoint response."""

    active: bool = False
    user_id: str = ""
    client_id: str = ""
    scope: str = ""
    exp: int = 0
    iss: str = ""
    subject_type: str = ""


@dataclass
class Endpoints:
    """Collection of OAuth 2.0 endpoint URLs."""

    token_url: str = ""
    authorize_url: str = ""
    device_authorization_url: str = ""
    revocation_url: str = ""
    introspection_url: str = ""
    userinfo_url: str = ""
    token_info_url: str = ""
