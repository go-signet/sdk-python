"""Auto-refresh TokenSource with singleflight dedup."""

from __future__ import annotations

import threading

from signet.credstore.models import StoredToken
from signet.credstore.protocols import Store
from signet.exceptions import AuthFlowError, NotFoundError
from signet.oauth.client import OAuthClient
from signet.oauth.models import Token


def credstore_to_oauth(t: StoredToken) -> Token:
    return Token(
        access_token=t.access_token,
        refresh_token=t.refresh_token,
        token_type=t.token_type,
        expires_at=t.expires_at,
    )


def oauth_to_credstore(t: Token, client_id: str) -> StoredToken:
    return StoredToken(
        access_token=t.access_token,
        refresh_token=t.refresh_token,
        token_type=t.token_type,
        expires_at=t.expires_at,
        client_id=client_id,
    )


class TokenSource:
    """Provides automatic token refresh with optional persistent storage.

    Concurrent callers share a single in-flight refresh request
    via a simple Lock + Event singleflight pattern.
    """

    def __init__(
        self,
        client: OAuthClient,
        *,
        store: Store[StoredToken] | None = None,
    ) -> None:
        self._client = client
        self._store = store
        self._lock = threading.RLock()
        self._cached: Token | None = None
        self._inflight: threading.Event | None = None
        self._inflight_result: Token | None = None
        self._inflight_error: Exception | None = None

    def token(self) -> Token:
        """Return a valid token, refreshing from store or server as needed."""
        # Fast path: check in-memory cache first
        if self._cached is not None and not self._cached.is_expired():
            return self._cached

        # Check persistent store
        if self._store is not None:
            try:
                stored = self._store.load(self._client.client_id)
                if stored.is_valid():
                    tok = credstore_to_oauth(stored)
                    self._cached = tok
                    return tok
            except NotFoundError:
                pass

        return self._slow_path()

    def _slow_path(self) -> Token:
        with self._lock:
            if self._inflight is not None:
                event = self._inflight
            else:
                event = threading.Event()
                self._inflight = event
                self._inflight_result = None
                self._inflight_error = None
                # We are the leader — do the work
                try:
                    result = self._do_refresh()
                    self._inflight_result = result
                except Exception as exc:
                    self._inflight_error = exc
                finally:
                    self._inflight = None
                    event.set()
                return self._get_inflight_result()

        # Wait for the leader to finish
        event.wait()
        return self._get_inflight_result()

    def _get_inflight_result(self) -> Token:
        if self._inflight_error is not None:
            raise self._inflight_error
        if self._inflight_result is None:
            raise AuthFlowError("no valid token available, re-authentication required")
        return self._inflight_result

    def _do_refresh(self) -> Token:
        # Re-check store under singleflight
        if self._store is not None:
            try:
                stored = self._store.load(self._client.client_id)
                if stored.is_valid():
                    tok = credstore_to_oauth(stored)
                    self._cached = tok
                    return tok

                # Try refresh if we have a refresh token
                if stored.refresh_token:
                    refreshed = self._client.refresh_token(stored.refresh_token)
                    self._save_token(refreshed)
                    self._cached = refreshed
                    return refreshed
            except NotFoundError:
                pass

        raise AuthFlowError("no valid token available, re-authentication required")

    def save_token(self, token: Token) -> None:
        """Persist a token to the store (if configured)."""
        with self._lock:
            self._cached = token
            self._save_token(token)

    def _save_token(self, token: Token) -> None:
        if self._store is None:
            return
        self._store.save(
            self._client.client_id,
            oauth_to_credstore(token, self._client.client_id),
        )
