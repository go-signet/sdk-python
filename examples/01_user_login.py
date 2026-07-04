"""Example 1: User login with automatic flow selection.

Tries browser (Auth Code + PKCE) first; falls back to Device Code flow
when no browser is available (e.g., SSH sessions, CI).

Usage:
    uv run python examples/01_user_login.py
"""

from __future__ import annotations

import os

import signet

SIGNET_URL = os.environ["SIGNET_URL"]
CLIENT_ID = os.environ["CLIENT_ID"]


def main() -> None:
    # authenticate() caches the token on disk and refreshes it automatically.
    client, token = signet.authenticate(
        SIGNET_URL,
        CLIENT_ID,
        scopes=["openid", "profile", "email"],
    )

    print(f"Logged in!  access_token={token.access_token[:20]}...")

    # Use the client to call an OAuth endpoint (e.g., UserInfo).
    userinfo = client.userinfo(token.access_token)
    print(f"Subject : {userinfo.sub}")
    print(f"Email   : {userinfo.email}")


if __name__ == "__main__":
    main()
