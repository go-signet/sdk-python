"""Tests for the discovery module."""

from __future__ import annotations

import httpx
import pytest

from signet.discovery.async_client import AsyncDiscoveryClient
from signet.discovery.client import DiscoveryClient
from signet.discovery.models import Metadata
from signet.exceptions import DiscoveryError

ISSUER = "https://auth.example.com"

DISCOVERY_RESPONSE = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "revocation_endpoint": f"{ISSUER}/oauth/revoke",
    "response_types_supported": ["code"],
    "scopes_supported": ["openid", "profile"],
}


class TestMetadata:
    def test_to_endpoints(self) -> None:
        meta = Metadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/oauth/authorize",
            token_endpoint=f"{ISSUER}/oauth/token",
            userinfo_endpoint=f"{ISSUER}/userinfo",
            device_authorization_endpoint=f"{ISSUER}/oauth/device/code",
        )
        ep = meta.to_endpoints()
        assert ep.token_url == f"{ISSUER}/oauth/token"
        assert ep.authorize_url == f"{ISSUER}/oauth/authorize"
        assert ep.token_info_url == f"{ISSUER}/oauth/tokeninfo"

    def test_to_endpoints_no_issuer(self) -> None:
        meta = Metadata()
        ep = meta.to_endpoints()
        assert ep.token_info_url == ""


class TestDiscoveryClient:
    def test_fetch(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "/.well-known/openid-configuration" in str(request.url)
            return httpx.Response(200, json=DISCOVERY_RESPONSE)

        transport = httpx.MockTransport(handler)
        client = DiscoveryClient(
            ISSUER,
            http_client=httpx.Client(transport=transport),
        )
        meta = client.fetch()
        assert meta.issuer == ISSUER
        assert meta.token_endpoint == f"{ISSUER}/oauth/token"
        # Derived endpoints
        assert meta.device_authorization_endpoint == f"{ISSUER}/oauth/device/code"
        assert meta.introspection_endpoint == f"{ISSUER}/oauth/introspect"

    def test_cache_hit(self) -> None:
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json=DISCOVERY_RESPONSE)

        transport = httpx.MockTransport(handler)
        client = DiscoveryClient(
            ISSUER,
            http_client=httpx.Client(transport=transport),
        )
        client.fetch()
        client.fetch()
        assert call_count == 1

    def test_issuer_mismatch(self) -> None:
        bad_response = {**DISCOVERY_RESPONSE, "issuer": "https://other.example.com"}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=bad_response)

        transport = httpx.MockTransport(handler)
        client = DiscoveryClient(
            ISSUER,
            http_client=httpx.Client(transport=transport),
        )
        with pytest.raises(DiscoveryError, match="issuer mismatch"):
            client.fetch()

    def test_non_200_status(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        client = DiscoveryClient(
            ISSUER,
            http_client=httpx.Client(transport=transport),
        )
        with pytest.raises(DiscoveryError, match="unexpected status 500"):
            client.fetch()


class TestAsyncDiscoveryClient:
    @pytest.mark.asyncio
    async def test_fetch(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=DISCOVERY_RESPONSE)

        transport = httpx.MockTransport(handler)
        client = AsyncDiscoveryClient(
            ISSUER,
            http_client=httpx.AsyncClient(transport=transport),
        )
        meta = await client.fetch()
        assert meta.issuer == ISSUER
        assert meta.device_authorization_endpoint == f"{ISSUER}/oauth/device/code"

    @pytest.mark.asyncio
    async def test_cache_hit(self) -> None:
        call_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json=DISCOVERY_RESPONSE)

        transport = httpx.MockTransport(handler)
        client = AsyncDiscoveryClient(
            ISSUER,
            http_client=httpx.AsyncClient(transport=transport),
        )
        await client.fetch()
        await client.fetch()
        assert call_count == 1
