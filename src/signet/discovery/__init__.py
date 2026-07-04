"""OIDC auto-discovery from /.well-known/openid-configuration."""

from signet.discovery.client import DiscoveryClient
from signet.discovery.models import Metadata

__all__ = ["DiscoveryClient", "Metadata"]
