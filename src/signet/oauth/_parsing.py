"""Shared OAuth response parsing utilities."""

from __future__ import annotations

import httpx

from signet.exceptions import OAuthError


def _parse_error_response(resp: httpx.Response) -> OAuthError:
    """Parse an OAuth error response body."""
    try:
        body = resp.json()
        if isinstance(body, dict) and body.get("error"):
            return OAuthError(
                code=body["error"],
                description=body.get("error_description", ""),
                status_code=resp.status_code,
            )
    except Exception:
        pass
    return OAuthError(
        code=resp.reason_phrase or "server_error",
        description=resp.text,
        status_code=resp.status_code,
    )
