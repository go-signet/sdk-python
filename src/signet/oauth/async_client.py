"""Asynchronous OAuth 2.0 HTTP client."""

from __future__ import annotations

import time

import httpx

from signet.exceptions import OAuthError
from signet.oauth._parsing import _parse_error_response
from signet.oauth.models import (
    DeviceAuth,
    Endpoints,
    IntrospectionResult,
    Token,
    TokenInfo,
    UserInfo,
)


class AsyncOAuthClient:
    """OAuth 2.0 HTTP client (async)."""

    def __init__(
        self,
        client_id: str,
        endpoints: Endpoints,
        *,
        client_secret: str = "",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._endpoints = endpoints
        self._http = http_client or httpx.AsyncClient(timeout=30.0)

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def endpoints(self) -> Endpoints:
        return self._endpoints

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncOAuthClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def request_device_code(self, scopes: list[str] | None = None) -> DeviceAuth:
        """Initiate a device authorization request (RFC 8628 SS3.1)."""
        if not self._endpoints.device_authorization_url:
            raise OAuthError("invalid_request", "device authorization endpoint not configured")
        data: dict[str, str] = {"client_id": self._client_id}
        if scopes:
            data["scope"] = " ".join(scopes)
        resp = await self._post_form(self._endpoints.device_authorization_url, data)
        body = resp.json()
        return DeviceAuth(
            device_code=body.get("device_code", ""),
            user_code=body.get("user_code", ""),
            verification_uri=body.get("verification_uri", ""),
            verification_uri_complete=body.get("verification_uri_complete", ""),
            expires_in=body.get("expires_in", 0),
            interval=body.get("interval", 0),
        )

    async def exchange_device_code(self, device_code: str) -> Token:
        """Exchange a device code for tokens (RFC 8628 SS3.4)."""
        return await self._token_request(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": self._client_id,
            }
        )

    async def exchange_auth_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str = "",
    ) -> Token:
        """Exchange an authorization code for tokens (RFC 6749 SS4.1.3)."""
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._client_id,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        if self._client_secret:
            data["client_secret"] = self._client_secret
        return await self._token_request(data)

    async def client_credentials(self, scopes: list[str] | None = None) -> Token:
        """Request a token using client credentials (RFC 6749 SS4.4)."""
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scopes:
            data["scope"] = " ".join(scopes)
        return await self._token_request(data)

    async def refresh_token(self, refresh_token: str) -> Token:
        """Exchange a refresh token for new tokens (RFC 6749 SS6)."""
        return await self._token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self._client_id,
            }
        )

    async def revoke(self, token: str) -> None:
        """Revoke a token (RFC 7009)."""
        if not self._endpoints.revocation_url:
            raise OAuthError("invalid_request", "revocation endpoint not configured")
        data: dict[str, str] = {
            "token": token,
            "client_id": self._client_id,
        }
        if self._client_secret:
            data["client_secret"] = self._client_secret
        resp = await self._http.post(
            self._endpoints.revocation_url,
            data=data,
        )
        if resp.status_code != 200:
            raise _parse_error_response(resp)

    async def introspect(self, token: str) -> IntrospectionResult:
        """Introspect a token (RFC 7662)."""
        if not self._endpoints.introspection_url:
            raise OAuthError("invalid_request", "introspection endpoint not configured")
        resp = await self._post_form(
            self._endpoints.introspection_url,
            {
                "token": token,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        body = resp.json()
        return IntrospectionResult(
            active=body.get("active", False),
            scope=body.get("scope", ""),
            client_id=body.get("client_id", ""),
            username=body.get("username", ""),
            token_type=body.get("token_type", ""),
            exp=body.get("exp", 0),
            iat=body.get("iat", 0),
            sub=body.get("sub", ""),
            iss=body.get("iss", ""),
            jti=body.get("jti", ""),
        )

    async def userinfo(self, access_token: str) -> UserInfo:
        """Fetch user information from the UserInfo endpoint (OIDC Core 1.0 SS5.3)."""
        if not self._endpoints.userinfo_url:
            raise OAuthError("invalid_request", "userinfo endpoint not configured")
        resp = await self._http.get(
            self._endpoints.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise _parse_error_response(resp)
        body = resp.json()
        return UserInfo(
            sub=body.get("sub", ""),
            iss=body.get("iss", ""),
            name=body.get("name", ""),
            preferred_username=body.get("preferred_username", ""),
            email=body.get("email", ""),
            email_verified=body.get("email_verified", False),
            picture=body.get("picture", ""),
            updated_at=body.get("updated_at", 0),
            subject_type=body.get("subject_type", ""),
        )

    async def token_info_request(self, access_token: str) -> TokenInfo:
        """Fetch token information from the tokeninfo endpoint."""
        if not self._endpoints.token_info_url:
            raise OAuthError("invalid_request", "tokeninfo endpoint not configured")
        resp = await self._http.get(
            self._endpoints.token_info_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise _parse_error_response(resp)
        body = resp.json()
        return TokenInfo(
            active=body.get("active", False),
            user_id=body.get("user_id", ""),
            client_id=body.get("client_id", ""),
            scope=body.get("scope", ""),
            exp=body.get("exp", 0),
            iss=body.get("iss", ""),
            subject_type=body.get("subject_type", ""),
        )

    async def _token_request(self, data: dict[str, str]) -> Token:
        """Send a token request and parse the response."""
        if not self._endpoints.token_url:
            raise OAuthError("invalid_request", "token endpoint not configured")
        resp = await self._post_form(self._endpoints.token_url, data)
        body = resp.json()
        tok = Token(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token", ""),
            token_type=body.get("token_type", ""),
            expires_in=body.get("expires_in", 0),
            scope=body.get("scope", ""),
            id_token=body.get("id_token", ""),
        )
        if tok.expires_in > 0:
            tok.expires_at = time.time() + tok.expires_in
        return tok

    async def _post_form(self, url: str, data: dict[str, str]) -> httpx.Response:
        """Send a POST request with form-encoded body."""
        resp = await self._http.post(url, data=data)
        if resp.status_code != 200:
            raise _parse_error_response(resp)
        return resp
