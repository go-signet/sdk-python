"""Auto-caching TokenSource for Client Credentials grant."""

from __future__ import annotations

import asyncio
import threading
import time

from signet.oauth.async_client import AsyncOAuthClient
from signet.oauth.client import OAuthClient
from signet.oauth.models import Token

_DEFAULT_EXPIRY_DELTA = 30.0  # seconds


def _is_token_valid(token: Token | None, expiry_delta: float) -> bool:
    """Check whether a token is present and not expired."""
    if token is None or not token.access_token:
        return False
    if token.expires_at == 0:
        return True
    return (time.time() + expiry_delta) < token.expires_at


class TokenSource:
    """Thread-safe, auto-caching token source for client credentials (sync).

    Concurrent callers share a single in-flight fetch via singleflight pattern.
    """

    def __init__(
        self,
        client: OAuthClient,
        *,
        scopes: list[str] | None = None,
        expiry_delta: float = _DEFAULT_EXPIRY_DELTA,
    ) -> None:
        self._client = client
        self._scopes = scopes
        self._expiry_delta = expiry_delta
        self._lock = threading.RLock()
        self._token: Token | None = None
        self._inflight: threading.Event | None = None
        self._inflight_result: Token | None = None
        self._inflight_error: Exception | None = None

    def token(self) -> Token:
        """Return a valid access token, fetching a new one if expired."""
        # Fast path
        with self._lock:
            if _is_token_valid(self._token, self._expiry_delta):
                return self._token  # type: ignore[return-value]

        return self._slow_path()

    def _slow_path(self) -> Token:
        with self._lock:
            # Re-check after acquiring lock
            if _is_token_valid(self._token, self._expiry_delta):
                return self._token  # type: ignore[return-value]

            if self._inflight is not None:
                event = self._inflight
            else:
                event = threading.Event()
                self._inflight = event
                self._inflight_result = None
                self._inflight_error = None
                try:
                    tok = self._client.client_credentials(self._scopes)
                    self._token = tok
                    self._inflight_result = tok
                except Exception as exc:
                    self._inflight_error = exc
                finally:
                    self._inflight = None
                    event.set()
                return self._get_result()

        event.wait()
        return self._get_result()

    def _get_result(self) -> Token:
        if self._inflight_error is not None:
            raise self._inflight_error
        if self._inflight_result is None:
            raise RuntimeError("clientcreds: no token available")
        return self._inflight_result


class AsyncTokenSource:
    """Auto-caching token source for client credentials (async)."""

    def __init__(
        self,
        client: AsyncOAuthClient,
        *,
        scopes: list[str] | None = None,
        expiry_delta: float = _DEFAULT_EXPIRY_DELTA,
    ) -> None:
        self._client = client
        self._scopes = scopes
        self._expiry_delta = expiry_delta
        self._lock = asyncio.Lock()
        self._token: Token | None = None

    async def token(self) -> Token:
        """Return a valid access token, fetching a new one if expired."""
        if _is_token_valid(self._token, self._expiry_delta):
            return self._token  # type: ignore[return-value]

        async with self._lock:
            if _is_token_valid(self._token, self._expiry_delta):
                return self._token  # type: ignore[return-value]
            self._token = await self._client.client_credentials(self._scopes)
            return self._token
