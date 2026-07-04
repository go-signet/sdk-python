"""Synchronous OIDC discovery client with caching."""

from __future__ import annotations

import dataclasses
import threading
import time

import httpx

from signet.discovery.models import Metadata
from signet.exceptions import DiscoveryError

_WELL_KNOWN_PATH = "/.well-known/openid-configuration"
_DEFAULT_CACHE_TTL = 3600.0  # 1 hour


def _copy_metadata(meta: Metadata) -> Metadata:
    """Return a shallow copy of Metadata with independent list fields."""
    return dataclasses.replace(
        meta,
        response_types_supported=list(meta.response_types_supported),
        subject_types_supported=list(meta.subject_types_supported),
        id_token_signing_alg_values_supported=list(meta.id_token_signing_alg_values_supported),
        scopes_supported=list(meta.scopes_supported),
        token_endpoint_auth_methods_supported=list(meta.token_endpoint_auth_methods_supported),
        grant_types_supported=list(meta.grant_types_supported),
        claims_supported=list(meta.claims_supported),
        code_challenge_methods_supported=list(meta.code_challenge_methods_supported),
    )


def _validate_and_enrich(meta: Metadata, expected_issuer: str) -> Metadata:
    """Validate issuer and fill in default endpoint URLs."""
    issuer = meta.issuer.rstrip("/")
    if issuer != expected_issuer:
        raise DiscoveryError(
            f"discovery: issuer mismatch: got {meta.issuer!r}, expected {expected_issuer!r}"
        )
    if not meta.device_authorization_endpoint:
        meta.device_authorization_endpoint = issuer + "/oauth/device/code"
    if not meta.introspection_endpoint:
        meta.introspection_endpoint = issuer + "/oauth/introspect"
    return meta


class DiscoveryClient:
    """OIDC discovery client with caching (sync)."""

    def __init__(
        self,
        issuer_url: str,
        *,
        http_client: httpx.Client | None = None,
        cache_ttl: float = _DEFAULT_CACHE_TTL,
    ) -> None:
        self._issuer_url = issuer_url.rstrip("/")
        self._http = http_client or httpx.Client(timeout=30.0)
        self._cache_ttl = cache_ttl
        self._lock = threading.RLock()
        self._cached: Metadata | None = None
        self._fetched_at: float = 0.0

    def fetch(self) -> Metadata:
        """Retrieve the OIDC provider metadata, using the cache if still valid.

        The returned Metadata is a copy; callers may safely modify it.
        """
        with self._lock:
            if self._cached is not None and (time.time() - self._fetched_at) < self._cache_ttl:
                return _copy_metadata(self._cached)
        return self._refresh()

    def _refresh(self) -> Metadata:
        with self._lock:
            if self._cached is not None and (time.time() - self._fetched_at) < self._cache_ttl:
                return _copy_metadata(self._cached)

            url = self._issuer_url + _WELL_KNOWN_PATH
            resp = self._http.get(url)
            if resp.status_code != 200:
                raise DiscoveryError(f"discovery: unexpected status {resp.status_code} from {url}")

            body = resp.json()
            meta = _parse_metadata(body)
            _validate_and_enrich(meta, self._issuer_url)

            self._cached = meta
            self._fetched_at = time.time()
            return _copy_metadata(meta)


def _get_str(body: dict[str, object], key: str) -> str:
    return str(body.get(key, "") or "")


def _get_list(body: dict[str, object], key: str) -> list[str]:
    val = body.get(key)
    return list(val) if val else []  # type: ignore[call-overload]


def _parse_metadata(body: dict[str, object]) -> Metadata:
    """Parse a JSON dict into a Metadata dataclass."""
    return Metadata(
        issuer=_get_str(body, "issuer"),
        authorization_endpoint=_get_str(body, "authorization_endpoint"),
        token_endpoint=_get_str(body, "token_endpoint"),
        userinfo_endpoint=_get_str(body, "userinfo_endpoint"),
        revocation_endpoint=_get_str(body, "revocation_endpoint"),
        introspection_endpoint=_get_str(body, "introspection_endpoint"),
        device_authorization_endpoint=_get_str(body, "device_authorization_endpoint"),
        response_types_supported=_get_list(body, "response_types_supported"),
        subject_types_supported=_get_list(body, "subject_types_supported"),
        id_token_signing_alg_values_supported=_get_list(
            body, "id_token_signing_alg_values_supported"
        ),
        scopes_supported=_get_list(body, "scopes_supported"),
        token_endpoint_auth_methods_supported=_get_list(
            body, "token_endpoint_auth_methods_supported"
        ),
        grant_types_supported=_get_list(body, "grant_types_supported"),
        claims_supported=_get_list(body, "claims_supported"),
        code_challenge_methods_supported=_get_list(body, "code_challenge_methods_supported"),
    )
