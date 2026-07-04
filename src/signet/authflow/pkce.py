"""PKCE (RFC 7636) code challenge/verifier generation."""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass


@dataclass
class PKCE:
    """Holds a code verifier and its corresponding code challenge."""

    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce() -> PKCE:
    """Generate a new PKCE verifier and challenge pair (RFC 7636 S256)."""
    verifier_bytes = os.urandom(32)
    verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return PKCE(verifier=verifier, challenge=challenge, method="S256")
