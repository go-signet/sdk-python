"""Middleware data models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TokenInfo:
    """Validated token information extracted from a request."""

    user_id: str = ""
    client_id: str = ""
    scope: str = ""
    subject_type: str = ""
    expires_at: int = 0

    def has_scope(self, scope: str) -> bool:
        """Check whether the token has a specific scope."""
        return scope in self.scope.split()
