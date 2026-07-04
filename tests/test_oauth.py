"""Tests for the OAuth client module."""

from __future__ import annotations

import time

import httpx
import pytest

from signet.exceptions import OAuthError
from signet.oauth.async_client import AsyncOAuthClient
from signet.oauth.client import OAuthClient
from signet.oauth.models import (
    Endpoints,
    Token,
)


class TestTokenModel:
    def test_is_valid_with_access_token(self) -> None:
        tok = Token(access_token="abc", expires_at=time.time() + 3600)
        assert tok.is_valid()

    def test_is_expired(self) -> None:
        tok = Token(access_token="abc", expires_at=time.time() - 10)
        assert tok.is_expired()
        assert not tok.is_valid()

    def test_no_expiry_is_not_expired(self) -> None:
        tok = Token(access_token="abc", expires_at=0)
        assert not tok.is_expired()

    def test_empty_token_is_not_valid(self) -> None:
        tok = Token()
        assert not tok.is_valid()


class TestOAuthClient:
    def test_request_device_code(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/oauth/device/code"
            return httpx.Response(
                200,
                json={
                    "device_code": "dev123",
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://auth.example.com/device",
                    "expires_in": 600,
                    "interval": 5,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        auth = client.request_device_code(["openid"])
        assert auth.device_code == "dev123"
        assert auth.user_code == "ABCD-1234"

    def test_exchange_device_code(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "access_token": "at123",
                    "refresh_token": "rt123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        tok = client.exchange_device_code("dev123")
        assert tok.access_token == "at123"
        assert tok.expires_at > time.time()

    def test_client_credentials(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "access_token": "cc-token",
                    "token_type": "Bearer",
                    "expires_in": 1800,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )
        tok = client.client_credentials(["api"])
        assert tok.access_token == "cc-token"

    def test_refresh_token(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "access_token": "new-at",
                    "refresh_token": "new-rt",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        tok = client.refresh_token("old-rt")
        assert tok.access_token == "new-at"

    def test_revoke(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        client.revoke("some-token")  # Should not raise

    def test_introspect(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "scope": "openid profile",
                    "client_id": "test-client",
                    "sub": "user123",
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )
        result = client.introspect("some-token")
        assert result.active
        assert result.scope == "openid profile"

    def test_userinfo(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "Bearer" in request.headers["Authorization"]
            return httpx.Response(
                200,
                json={
                    "sub": "user123",
                    "name": "Test User",
                    "email": "test@example.com",
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        info = client.userinfo("access-token")
        assert info.sub == "user123"
        assert info.name == "Test User"

    def test_token_info_request(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "user_id": "user123",
                    "client_id": "test-client",
                    "scope": "openid",
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        info = client.token_info_request("access-token")
        assert info.active
        assert info.user_id == "user123"

    def test_error_response(self, endpoints: Endpoints) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={"error": "invalid_grant", "error_description": "Bad grant"},
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )
        with pytest.raises(OAuthError) as exc_info:
            client.exchange_device_code("bad")
        assert exc_info.value.code == "invalid_grant"
        assert exc_info.value.status_code == 400

    def test_missing_endpoint_raises(self) -> None:
        client = OAuthClient("test-client", Endpoints())
        with pytest.raises(OAuthError, match="token endpoint not configured"):
            client.exchange_device_code("code")
        with pytest.raises(OAuthError, match="device authorization endpoint"):
            client.request_device_code()
        with pytest.raises(OAuthError, match="revocation endpoint"):
            client.revoke("tok")
        with pytest.raises(OAuthError, match="introspection endpoint"):
            client.introspect("tok")
        with pytest.raises(OAuthError, match="userinfo endpoint"):
            client.userinfo("tok")
        with pytest.raises(OAuthError, match="tokeninfo endpoint"):
            client.token_info_request("tok")


class TestAsyncOAuthClient:
    @pytest.mark.asyncio
    async def test_request_device_code(self, endpoints: Endpoints) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "device_code": "dev123",
                    "user_code": "ABCD",
                    "verification_uri": "https://auth.example.com/device",
                    "expires_in": 600,
                    "interval": 5,
                },
            )

        transport = httpx.MockTransport(handler)
        client = AsyncOAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.AsyncClient(transport=transport),
        )
        auth = await client.request_device_code(["openid"])
        assert auth.device_code == "dev123"

    @pytest.mark.asyncio
    async def test_exchange_device_code(self, endpoints: Endpoints) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "access_token": "at123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        transport = httpx.MockTransport(handler)
        client = AsyncOAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.AsyncClient(transport=transport),
        )
        tok = await client.exchange_device_code("dev123")
        assert tok.access_token == "at123"

    @pytest.mark.asyncio
    async def test_error_response(self, endpoints: Endpoints) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"error": "invalid_token", "error_description": "Expired"},
            )

        transport = httpx.MockTransport(handler)
        client = AsyncOAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.AsyncClient(transport=transport),
        )
        with pytest.raises(OAuthError) as exc_info:
            await client.exchange_device_code("bad")
        assert exc_info.value.code == "invalid_token"
