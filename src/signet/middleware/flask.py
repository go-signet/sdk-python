"""Flask decorator for Bearer token validation."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from typing import Any

from signet.exceptions import OAuthError
from signet.middleware.core import ValidationMode, extract_bearer_token, validate_token
from signet.middleware.models import TokenInfo
from signet.oauth.client import OAuthClient

try:
    from flask import Response as FlaskResponse
    from flask import g, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for this module. Install with: pip install signet[flask]"
    ) from exc

_TOKEN_INFO_KEY = "signet_token_info"


def get_token_info() -> TokenInfo | None:
    """Retrieve the validated token info from Flask's ``g`` object."""
    return getattr(g, _TOKEN_INFO_KEY, None)


def bearer_auth(
    client: OAuthClient,
    *,
    mode: ValidationMode = ValidationMode.TOKEN_INFO,
    required_scopes: list[str] | None = None,
) -> Callable[..., Any]:
    """Flask decorator that validates Bearer tokens.

    Usage::

        @app.route("/api/protected")
        @bearer_auth(oauth_client)
        def protected():
            info = get_token_info()
            return {"user": info.user_id}
    """
    scopes = required_scopes or []

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_header = request.headers.get("Authorization", "")
            token = extract_bearer_token(auth_header)
            if not token:
                return _json_error(
                    401,
                    "missing_token",
                    "Bearer token required",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )

            try:
                info = validate_token(client, token, mode=mode)
            except OAuthError as exc:
                if exc.code == "server_error":
                    return _json_error(500, exc.code, exc.description)
                return _json_error(
                    401,
                    exc.code,
                    exc.description,
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )

            for scope in scopes:
                if not info.has_scope(scope):
                    return _json_error(
                        403,
                        "insufficient_scope",
                        f"Token does not have required scope: {scope}",
                        headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
                    )

            setattr(g, _TOKEN_INFO_KEY, info)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _json_error(
    status: int,
    error: str,
    description: str,
    *,
    headers: dict[str, str] | None = None,
) -> FlaskResponse:
    body = json.dumps({"error": error, "error_description": description})
    resp = FlaskResponse(body, status=status, content_type="application/json")
    if headers:
        for k, v in headers.items():
            resp.headers[k] = v
    return resp
