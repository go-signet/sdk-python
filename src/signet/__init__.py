"""Signet Python SDK — one-call authentication entry point."""

from __future__ import annotations

import asyncio
import enum

from signet._version import __version__
from signet.authflow.authcode import run_auth_code_flow
from signet.authflow.browser import check_browser_availability
from signet.authflow.device import async_run_device_flow, run_device_flow
from signet.authflow.token_source import TokenSource
from signet.credstore import default_token_secure_store
from signet.discovery.async_client import AsyncDiscoveryClient
from signet.discovery.client import DiscoveryClient
from signet.exceptions import AuthFlowError, NotFoundError, OAuthError, SignetError
from signet.oauth.async_client import AsyncOAuthClient
from signet.oauth.client import OAuthClient
from signet.oauth.models import Token


class FlowMode(enum.Enum):
    """Authentication flow selection strategy."""

    AUTO = "auto"
    BROWSER = "browser"
    DEVICE = "device"


def authenticate(
    signet_url: str,
    client_id: str,
    *,
    scopes: list[str] | None = None,
    service_name: str = "signet",
    store_path: str = ".signet-tokens.json",
    local_port: int = 8088,
    flow_mode: FlowMode = FlowMode.AUTO,
) -> tuple[OAuthClient, Token]:
    """Authenticate with an Signet server and return a ready-to-use client and token.

    Cached tokens are reused automatically; expired tokens are refreshed.
    When no valid token exists, the flow is determined by ``flow_mode``.
    """
    if not signet_url:
        raise SignetError("signet: signet_url is required")
    if not client_id:
        raise SignetError("signet: client_id is required")

    _scopes = scopes or []

    # 1. Discover endpoints
    disco = DiscoveryClient(signet_url)
    meta = disco.fetch()

    # 2. Create OAuth client
    client = OAuthClient(client_id, meta.to_endpoints())

    # 3. Set up token store and source
    store = default_token_secure_store(service_name, store_path)
    ts = TokenSource(client, store=store)

    # 4. Return cached/refreshed token if available
    try:
        token = ts.token()
        return client, token
    except (NotFoundError, AuthFlowError):
        pass
    except OAuthError as exc:
        # Only swallow errors indicating an invalid/expired refresh token.
        # Re-raise unexpected OAuth errors (e.g., server_error) so they surface.
        if exc.code not in ("invalid_grant", "invalid_token"):
            raise

    # 5. No valid token — run the appropriate authentication flow
    if flow_mode == FlowMode.BROWSER:
        token = run_auth_code_flow(client, _scopes, local_port=local_port)
    elif flow_mode == FlowMode.DEVICE:
        token = run_device_flow(client, _scopes)
    else:  # AUTO
        if check_browser_availability():
            token = run_auth_code_flow(client, _scopes, local_port=local_port)
        else:
            token = run_device_flow(client, _scopes)

    # 6. Persist the new token
    ts.save_token(token)

    return client, token


async def async_authenticate(
    signet_url: str,
    client_id: str,
    *,
    scopes: list[str] | None = None,
    service_name: str = "signet",
    store_path: str = ".signet-tokens.json",
    flow_mode: FlowMode = FlowMode.AUTO,
) -> tuple[AsyncOAuthClient, Token]:
    """Async version of authenticate().

    Note: Auth Code flow is not available in async mode. Device flow is used for
    BROWSER and AUTO modes when a browser is available.
    """
    if not signet_url:
        raise SignetError("signet: signet_url is required")
    if not client_id:
        raise SignetError("signet: client_id is required")

    _scopes = scopes or []

    # 1. Discover endpoints
    disco = AsyncDiscoveryClient(signet_url)
    meta = await disco.fetch()

    # 2. Create async OAuth client
    client = AsyncOAuthClient(client_id, meta.to_endpoints())

    # 3. Check stored token and attempt refresh if expired
    store = default_token_secure_store(service_name, store_path)
    try:
        stored = await asyncio.to_thread(store.load, client_id)
        from signet.authflow.token_source import credstore_to_oauth, oauth_to_credstore

        if stored.is_valid():
            token = credstore_to_oauth(stored)
            return client, token

        # Try refreshing with the stored refresh token
        if stored.refresh_token:
            try:
                token = await client.refresh_token(stored.refresh_token)
                await asyncio.to_thread(store.save, client_id, oauth_to_credstore(token, client_id))
                return client, token
            except OAuthError as exc:
                # Only swallow errors indicating an invalid/expired refresh token.
                # Re-raise unexpected OAuth errors (e.g., server_error).
                if exc.code not in ("invalid_grant", "invalid_token"):
                    raise
    except NotFoundError:
        pass

    # 4. Run device flow (always, since auth code needs sync HTTP server)
    token = await async_run_device_flow(client, _scopes)

    # 5. Persist
    from signet.authflow.token_source import oauth_to_credstore

    await asyncio.to_thread(store.save, client_id, oauth_to_credstore(token, client_id))

    return client, token


__all__ = [
    "FlowMode",
    "__version__",
    "async_authenticate",
    "authenticate",
]
