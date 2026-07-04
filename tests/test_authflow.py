"""Tests for the authflow module."""

from __future__ import annotations

import time

import httpx
import pytest

from signet.authflow.browser import check_browser_availability
from signet.authflow.device import run_device_flow
from signet.authflow.pkce import generate_pkce
from signet.authflow.token_source import TokenSource
from signet.credstore.codecs import JSONCodec
from signet.credstore.file_store import FileStore
from signet.credstore.models import StoredToken
from signet.exceptions import AuthFlowError, TokenExpiredError
from signet.oauth.client import OAuthClient
from signet.oauth.models import Endpoints


class TestPKCE:
    def test_generate_pkce(self) -> None:
        pkce = generate_pkce()
        assert pkce.method == "S256"
        assert len(pkce.verifier) > 0
        assert len(pkce.challenge) > 0
        assert pkce.verifier != pkce.challenge

    def test_pkce_deterministic_challenge(self) -> None:
        """Verify that the same verifier always produces the same challenge."""
        import base64
        import hashlib

        pkce = generate_pkce()
        digest = hashlib.sha256(pkce.verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert pkce.challenge == expected


class TestBrowserAvailability:
    def test_returns_bool(self) -> None:
        result = check_browser_availability()
        assert isinstance(result, bool)


class TestDeviceFlow:
    def test_device_flow_success(self) -> None:
        call_count = 0
        endpoints = Endpoints(
            token_url="https://auth.example.com/oauth/token",
            device_authorization_url="https://auth.example.com/oauth/device/code",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            if "/device/code" in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "device_code": "dev123",
                        "user_code": "ABCD",
                        "verification_uri": "https://auth.example.com/device",
                        "expires_in": 600,
                        "interval": 0,
                    },
                )
            # Token endpoint
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    400,
                    json={"error": "authorization_pending"},
                )
            return httpx.Response(
                200,
                json={
                    "access_token": "at123",
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

        # Use a custom handler that doesn't print
        class SilentHandler:
            def display_code(self, auth: object) -> None:
                pass

        tok = run_device_flow(client, ["openid"], handler=SilentHandler())
        assert tok.access_token == "at123"

    def test_device_flow_expired(self) -> None:
        endpoints = Endpoints(
            token_url="https://auth.example.com/oauth/token",
            device_authorization_url="https://auth.example.com/oauth/device/code",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if "/device/code" in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "device_code": "dev123",
                        "user_code": "ABCD",
                        "verification_uri": "https://auth.example.com/device",
                        "expires_in": 0,  # Already expired
                        "interval": 0,
                    },
                )
            return httpx.Response(
                400,
                json={"error": "expired_token"},
            )

        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )

        class SilentHandler:
            def display_code(self, auth: object) -> None:
                pass

        with pytest.raises(TokenExpiredError):
            run_device_flow(client, handler=SilentHandler())


class TestTokenSource:
    def test_returns_valid_cached_token(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))

        # Pre-populate store with a valid token
        stored = StoredToken(
            access_token="cached-token",
            refresh_token="rt",
            token_type="Bearer",
            expires_at=time.time() + 3600,
            client_id="test-client",
        )
        store.save("test-client", stored)

        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
        )

        ts = TokenSource(client, store=store)  # type: ignore[arg-type]
        tok = ts.token()
        assert tok.access_token == "cached-token"

    def test_refreshes_expired_token(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))

        # Pre-populate store with an expired token
        stored = StoredToken(
            access_token="expired",
            refresh_token="rt-valid",
            token_type="Bearer",
            expires_at=time.time() - 10,
            client_id="test-client",
        )
        store.save("test-client", stored)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "access_token": "refreshed-token",
                    "refresh_token": "new-rt",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")
        transport = httpx.MockTransport(handler)
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=transport),
        )

        ts = TokenSource(client, store=store)  # type: ignore[arg-type]
        tok = ts.token()
        assert tok.access_token == "refreshed-token"

    def test_no_token_raises(self) -> None:
        endpoints = Endpoints(token_url="https://auth.example.com/oauth/token")
        client = OAuthClient(
            "test-client",
            endpoints,
            http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
        )
        ts = TokenSource(client)
        with pytest.raises(AuthFlowError, match="re-authentication required"):
            ts.token()
