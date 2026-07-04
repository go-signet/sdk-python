"""Tests for the middleware module."""

from __future__ import annotations

import httpx
import pytest

from signet.exceptions import OAuthError
from signet.middleware.core import ValidationMode, extract_bearer_token, validate_token
from signet.middleware.models import TokenInfo
from signet.oauth.client import OAuthClient
from signet.oauth.models import Endpoints


class TestTokenInfo:
    def test_has_scope(self) -> None:
        info = TokenInfo(scope="openid profile email")
        assert info.has_scope("openid")
        assert info.has_scope("profile")
        assert not info.has_scope("admin")

    def test_empty_scope(self) -> None:
        info = TokenInfo()
        assert not info.has_scope("anything")


class TestExtractBearerToken:
    def test_valid_bearer(self) -> None:
        assert extract_bearer_token("Bearer abc123") == "abc123"

    def test_case_insensitive(self) -> None:
        assert extract_bearer_token("bearer abc123") == "abc123"
        assert extract_bearer_token("BEARER abc123") == "abc123"

    def test_no_bearer(self) -> None:
        assert extract_bearer_token("Basic abc123") == ""

    def test_empty(self) -> None:
        assert extract_bearer_token("") == ""

    def test_bearer_only(self) -> None:
        assert extract_bearer_token("Bearer ") == ""

    def test_short_string(self) -> None:
        assert extract_bearer_token("Bear") == ""


class TestValidateToken:
    def test_validate_via_token_info(self) -> None:
        endpoints = Endpoints(
            token_info_url="https://auth.example.com/oauth/tokeninfo",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "user_id": "user123",
                    "client_id": "client1",
                    "scope": "openid profile",
                    "subject_type": "user",
                    "exp": 9999999999,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "client1",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )

        info = validate_token(client, "some-token")
        assert info.user_id == "user123"
        assert info.has_scope("openid")

    def test_validate_via_introspection(self) -> None:
        endpoints = Endpoints(
            introspection_url="https://auth.example.com/oauth/introspect",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": "user123",
                    "client_id": "client1",
                    "scope": "openid",
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "client1",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )

        info = validate_token(client, "some-token", mode=ValidationMode.INTROSPECTION)
        assert info.user_id == "user123"
        assert info.subject_type == "user"

    def test_validate_client_subject_type(self) -> None:
        endpoints = Endpoints(
            introspection_url="https://auth.example.com/oauth/introspect",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": "client:svc1",
                    "client_id": "svc1",
                    "scope": "api",
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "svc1",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )

        info = validate_token(client, "tok", mode=ValidationMode.INTROSPECTION)
        assert info.subject_type == "client"

    def test_inactive_token_raises(self) -> None:
        endpoints = Endpoints(
            token_info_url="https://auth.example.com/oauth/tokeninfo",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"active": False})

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "client1",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )

        with pytest.raises(OAuthError, match="not active"):
            validate_token(client, "bad-token")
