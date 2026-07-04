"""httpx.Auth implementations with auto-token injection."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator

import httpx

from signet.clientcreds.token_source import AsyncTokenSource, TokenSource


class BearerAuth(httpx.Auth):
    """httpx.Auth that automatically attaches a valid Bearer token (sync)."""

    def __init__(self, source: TokenSource) -> None:
        self._source = source

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        token = self._source.token()
        request.headers["Authorization"] = f"Bearer {token.access_token}"
        yield request


class AsyncBearerAuth(httpx.Auth):
    """httpx.Auth that automatically attaches a valid Bearer token (async)."""

    def __init__(self, source: AsyncTokenSource) -> None:
        self._source = source

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        token = await self._source.token()
        request.headers["Authorization"] = f"Bearer {token.access_token}"
        yield request
