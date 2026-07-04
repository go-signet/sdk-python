"""Device Code flow (RFC 8628) — sync and async."""

from __future__ import annotations

import asyncio
import time
from typing import Protocol

from signet.authflow.browser import open_browser
from signet.exceptions import AccessDeniedError, AuthFlowError, OAuthError, TokenExpiredError
from signet.oauth.async_client import AsyncOAuthClient
from signet.oauth.client import OAuthClient
from signet.oauth.models import DeviceAuth, Token


class DeviceFlowHandler(Protocol):
    """Protocol for displaying the device code to the user."""

    def display_code(self, auth: DeviceAuth) -> None: ...


class DefaultDeviceFlowHandler:
    """Prints the user code and verification URI to stdout."""

    def display_code(self, auth: DeviceAuth) -> None:
        print(f"Open {auth.verification_uri} in your browser and enter code: {auth.user_code}")


def run_device_flow(
    client: OAuthClient,
    scopes: list[str] | None = None,
    *,
    handler: DeviceFlowHandler | None = None,
    auto_open_browser: bool = False,
) -> Token:
    """Execute the complete Device Code flow (sync)."""
    if handler is None:
        handler = DefaultDeviceFlowHandler()

    auth = client.request_device_code(scopes)
    handler.display_code(auth)

    if auto_open_browser:
        uri = auth.verification_uri_complete or auth.verification_uri
        open_browser(uri)

    return _poll_device_code(client, auth)


def _handle_poll_error(exc: OAuthError) -> str:
    """Classify a device-code polling error.

    Returns ``"continue"`` or ``"slow_down"`` for retriable errors.
    Raises the appropriate exception for terminal errors.
    """
    if exc.code == "authorization_pending":
        return "continue"
    if exc.code == "slow_down":
        return "slow_down"
    if exc.code == "expired_token":
        raise TokenExpiredError("device code expired") from exc
    if exc.code == "access_denied":
        raise AccessDeniedError("access denied by user") from exc
    raise AuthFlowError(f"exchange device code: {exc}") from exc


def _poll_device_code(client: OAuthClient, auth: DeviceAuth) -> Token:
    """Poll the token endpoint until the user authorizes or the code expires."""
    interval = max(auth.interval, 5)
    deadline = time.time() + auth.expires_in

    while True:
        if time.time() > deadline:
            raise TokenExpiredError("device code expired")

        time.sleep(interval)

        try:
            return client.exchange_device_code(auth.device_code)
        except OAuthError as exc:
            signal = _handle_poll_error(exc)
            if signal == "slow_down":
                interval += 5


async def async_run_device_flow(
    client: AsyncOAuthClient,
    scopes: list[str] | None = None,
    *,
    handler: DeviceFlowHandler | None = None,
    auto_open_browser: bool = False,
) -> Token:
    """Execute the complete Device Code flow (async)."""
    if handler is None:
        handler = DefaultDeviceFlowHandler()

    auth = await client.request_device_code(scopes)
    handler.display_code(auth)

    if auto_open_browser:
        uri = auth.verification_uri_complete or auth.verification_uri
        open_browser(uri)

    return await _async_poll_device_code(client, auth)


async def _async_poll_device_code(client: AsyncOAuthClient, auth: DeviceAuth) -> Token:
    """Poll the token endpoint asynchronously."""
    interval = max(auth.interval, 5)
    deadline = time.time() + auth.expires_in

    while True:
        if time.time() > deadline:
            raise TokenExpiredError("device code expired")

        await asyncio.sleep(interval)

        try:
            return await client.exchange_device_code(auth.device_code)
        except OAuthError as exc:
            signal = _handle_poll_error(exc)
            if signal == "slow_down":
                interval += 5
