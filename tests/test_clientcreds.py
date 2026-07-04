"""Tests for the clientcreds module."""

from __future__ import annotations

import time

import httpx
import pytest

from signet.clientcreds.token_source import AsyncTokenSource, TokenSource
from signet.clientcreds.transport import BearerAuth
from signet.oauth.async_client import AsyncOAuthClient
from signet.oauth.client import OAuthClient
from signet.oauth.models import Endpoints


class TestTokenSource:
    def test_fetches_and_caches(self) -> None:
        call_count = 0
        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"token-{call_count}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-svc",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )

        ts = TokenSource(client, scopes=["api"])
        tok1 = ts.token()
        tok2 = ts.token()
        assert tok1.access_token == "token-1"
        assert tok2.access_token == "token-1"  # Cached
        assert call_count == 1

    def test_refetches_on_expiry(self) -> None:
        call_count = 0
        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"token-{call_count}",
                    "token_type": "Bearer",
                    "expires_in": 1,  # Expires in 1 second
                },
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-svc",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )

        ts = TokenSource(client, expiry_delta=0)
        tok1 = ts.token()
        assert tok1.access_token == "token-1"
        # Wait for expiry
        time.sleep(1.1)
        tok2 = ts.token()
        assert tok2.access_token == "token-2"
        assert call_count == 2


class TestBearerAuth:
    def test_injects_bearer_token(self) -> None:
        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")

        def token_handler(request: httpx.Request) -> httpx.Response:
            if "/oauth/token" in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "my-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    },
                )
            # API endpoint — verify the token is injected
            assert request.headers["Authorization"] == "Bearer my-token"
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(token_handler)
        oauth_client = OAuthClient(
            "test-svc",
            endpoints,
            client_secret="secret",
            http_client=httpx.Client(transport=transport),
        )

        ts = TokenSource(oauth_client)
        with httpx.Client(transport=transport, auth=BearerAuth(ts)) as http:
            resp = http.get("https://api.example.com/data")
            assert resp.status_code == 200


class TestAsyncTokenSource:
    @pytest.mark.asyncio
    async def test_fetches_and_caches(self) -> None:
        call_count = 0
        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"async-token-{call_count}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        transport = httpx.MockTransport(handler)
        client = AsyncOAuthClient(
            "test-svc",
            endpoints,
            client_secret="secret",
            http_client=httpx.AsyncClient(transport=transport),
        )

        ts = AsyncTokenSource(client, scopes=["api"])
        tok1 = await ts.token()
        tok2 = await ts.token()
        assert tok1.access_token == "async-token-1"
        assert tok2.access_token == "async-token-1"
        assert call_count == 1
