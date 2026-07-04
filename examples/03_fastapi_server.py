"""Example 3: FastAPI server with Bearer token validation.

Every protected route requires a valid Bearer token issued by Signet.
Optional scope enforcement is shown on /admin.

Install extras:
    uv pip install signet[fastapi]

Run:
    uv run uvicorn examples.03_fastapi_server:app --reload
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from signet.discovery.client import DiscoveryClient
from signet.middleware.fastapi import BearerAuth
from signet.middleware.models import TokenInfo
from signet.oauth.client import OAuthClient

SIGNET_URL = os.environ["SIGNET_URL"]
CLIENT_ID = os.environ["CLIENT_ID"]

# Build shared OAuth client once at startup.
_meta = DiscoveryClient(SIGNET_URL).fetch()
_oauth = OAuthClient(CLIENT_ID, _meta.to_endpoints())

# Reusable dependency — validates any Bearer token.
bearer_auth = BearerAuth(_oauth)

# Dependency that also enforces a specific scope.
admin_auth = BearerAuth(_oauth, required_scopes=["admin"])

app = FastAPI(title="Signet FastAPI Example")


@app.get("/me")
async def get_me(token_info: TokenInfo = Depends(bearer_auth)) -> dict[str, object]:
    """Return the token's subject and scopes."""
    return {
        "sub": token_info.sub,
        "scopes": token_info.scopes,
        "active": token_info.active,
    }


@app.get("/admin")
async def admin_endpoint(token_info: TokenInfo = Depends(admin_auth)) -> dict[str, str]:
    """Only accessible with the 'admin' scope."""
    return {"message": f"Hello admin {token_info.sub}!"}


@app.get("/health")
async def health() -> dict[str, str]:
    """Public endpoint — no auth required."""
    return {"status": "ok"}
