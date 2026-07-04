"""OIDC discovery data models."""

from __future__ import annotations

from dataclasses import dataclass, field

from signet.oauth.models import Endpoints


@dataclass
class Metadata:
    """Subset of OIDC Provider Metadata (RFC 8414) used by the Signet SDK."""

    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    revocation_endpoint: str = ""
    introspection_endpoint: str = ""
    device_authorization_endpoint: str = ""
    response_types_supported: list[str] = field(default_factory=list)
    subject_types_supported: list[str] = field(default_factory=list)
    id_token_signing_alg_values_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    claims_supported: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)

    def to_endpoints(self) -> Endpoints:
        """Convert metadata to an Endpoints struct."""
        token_info_url = ""
        if self.issuer:
            token_info_url = self.issuer.rstrip("/") + "/oauth/tokeninfo"
        return Endpoints(
            token_url=self.token_endpoint,
            authorize_url=self.authorization_endpoint,
            device_authorization_url=self.device_authorization_endpoint,
            revocation_url=self.revocation_endpoint,
            introspection_url=self.introspection_endpoint,
            userinfo_url=self.userinfo_endpoint,
            token_info_url=token_info_url,
        )
