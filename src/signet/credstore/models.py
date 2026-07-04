"""Credential storage data models."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class StoredToken:
    """Saved token for a specific client."""

    access_token: str = ""
    refresh_token: str = ""
    token_type: str = ""
    expires_at: float = 0.0
    client_id: str = ""

    def is_expired(self) -> bool:
        """Report whether the token has expired.

        Returns False if expires_at is zero (token has no expiry).
        """
        return self.expires_at > 0 and time.time() > self.expires_at

    def is_valid(self) -> bool:
        """Report whether the token has a non-empty access token and is not expired."""
        return bool(self.access_token) and not self.is_expired()
