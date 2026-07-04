"""Shared test fixtures."""

from __future__ import annotations

import pytest

from signet.oauth.models import Endpoints


@pytest.fixture()
def endpoints() -> Endpoints:
    """Standard test endpoints."""
    return Endpoints(
        token_url="https://auth.example.com/oauth/token",
        authorize_url="https://auth.example.com/oauth/authorize",
        device_authorization_url="https://auth.example.com/oauth/device/code",
        revocation_url="https://auth.example.com/oauth/revoke",
        introspection_url="https://auth.example.com/oauth/introspect",
        userinfo_url="https://auth.example.com/userinfo",
        token_info_url="https://auth.example.com/oauth/tokeninfo",
    )
