"""Django middleware class for Bearer token validation."""

from __future__ import annotations

import json
from collections.abc import Callable

from signet.exceptions import OAuthError
from signet.middleware.core import ValidationMode, extract_bearer_token, validate_token
from signet.oauth.client import OAuthClient

try:
    from django.http import HttpRequest, HttpResponse
except ImportError as exc:
    raise ImportError(
        "Django is required for this module. Install with: pip install signet[django]"
    ) from exc


class BearerAuthMiddleware:
    """Django middleware that validates Bearer tokens.

    Attaches the validated ``TokenInfo`` as ``request.token_info``.

    Usage in settings.py::

        MIDDLEWARE = [
            ...
            "signet.middleware.django.BearerAuthMiddleware",
        ]

        SIGNET_OAUTH_CLIENT = OAuthClient(...)
        SIGNET_VALIDATION_MODE = ValidationMode.TOKEN_INFO
        SIGNET_REQUIRED_SCOPES = []
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self._client: OAuthClient | None = None
        self._mode = ValidationMode.TOKEN_INFO
        self._required_scopes: list[str] = []

    def _ensure_configured(self) -> None:
        if self._client is not None:
            return
        from django.conf import settings

        self._client = getattr(settings, "SIGNET_OAUTH_CLIENT", None)
        self._mode = getattr(settings, "SIGNET_VALIDATION_MODE", ValidationMode.TOKEN_INFO)
        self._required_scopes = getattr(settings, "SIGNET_REQUIRED_SCOPES", [])

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self._ensure_configured()

        if self._client is None:
            return self.get_response(request)

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = extract_bearer_token(auth_header)
        if not token:
            return _json_error(
                401,
                "missing_token",
                "Bearer token required",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        try:
            info = validate_token(self._client, token, mode=self._mode)
        except OAuthError as exc:
            if exc.code == "server_error":
                return _json_error(500, exc.code, exc.description)
            return _json_error(
                401,
                exc.code,
                exc.description,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        for scope in self._required_scopes:
            if not info.has_scope(scope):
                return _json_error(
                    403,
                    "insufficient_scope",
                    f"Token does not have required scope: {scope}",
                    headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
                )

        request.token_info = info
        return self.get_response(request)


def _json_error(
    status: int,
    error: str,
    description: str,
    *,
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    body = json.dumps({"error": error, "error_description": description})
    resp = HttpResponse(body, status=status, content_type="application/json")
    if headers:
        for k, v in headers.items():
            resp[k] = v
    return resp
