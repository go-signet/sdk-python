"""Example 4: Async user login with Device Code flow.

Useful inside async applications (e.g., async CLI tools, Jupyter notebooks).
Auth Code + PKCE is not available in async mode; Device Code is always used.

Usage:
    uv run python examples/04_async_login.py
"""

from __future__ import annotations

import asyncio
import os

import signet

SIGNET_URL = os.environ["SIGNET_URL"]
CLIENT_ID = os.environ["CLIENT_ID"]


async def main() -> None:
    client, token = await signet.async_authenticate(
        SIGNET_URL,
        CLIENT_ID,
        scopes=["openid", "profile"],
    )

    print(f"Logged in!  access_token={token.access_token[:20]}...")

    userinfo = await client.userinfo(token.access_token)
    print(f"Subject: {userinfo.sub}")


if __name__ == "__main__":
    asyncio.run(main())
