"""Client Credentials grant (RFC 6749 SS4.4) for M2M authentication."""

from signet.clientcreds.token_source import AsyncTokenSource, TokenSource
from signet.clientcreds.transport import AsyncBearerAuth, BearerAuth

__all__ = [
    "AsyncBearerAuth",
    "AsyncTokenSource",
    "BearerAuth",
    "TokenSource",
]
