"""Authorization Code + PKCE flow with local callback server."""

from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from signet.authflow.browser import open_browser
from signet.authflow.pkce import generate_pkce
from signet.exceptions import AuthFlowError, OAuthError
from signet.oauth.client import OAuthClient
from signet.oauth.models import Token

_CALLBACK_TIMEOUT = 300.0  # 5 minutes


def _generate_state() -> str:
    """Generate a cryptographically random state string for CSRF protection."""
    return os.urandom(16).hex()


def _make_callback_handler(
    result: dict[str, str],
    event: threading.Event,
) -> type[BaseHTTPRequestHandler]:
    """Create a handler class with per-flow state to avoid class-attribute sharing."""

    class _CallbackHandler(BaseHTTPRequestHandler):
        """HTTP handler for the OAuth callback."""

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            params = parse_qs(parsed.query)

            # Only process the first callback
            if event.is_set():
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Already processed</h1></body></html>")
                return

            state = params.get("state", [""])[0]
            if state != result.get("expected_state"):
                result["error"] = "invalid_state"
                result["error_description"] = "State parameter mismatch"
                event.set()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Authentication failed</h1>"
                    b"<p>State mismatch. You can close this window.</p></body></html>"
                )
                return

            code = params.get("code", [""])[0]
            if not code:
                result["error"] = params.get("error", ["no code received"])[0]
                result["error_description"] = params.get("error_description", [""])[0]
                event.set()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Authentication failed</h1>"
                    b"<p>You can close this window.</p></body></html>"
                )
                return

            result["code"] = code
            event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Authentication successful</h1>"
                b"<p>You can close this window.</p></body></html>"
            )

        def log_message(self, fmt: str, *args: object) -> None:
            pass  # Suppress HTTP server logs

    return _CallbackHandler


def run_auth_code_flow(
    client: OAuthClient,
    scopes: list[str] | None = None,
    *,
    local_port: int = 0,
) -> Token:
    """Execute the Authorization Code + PKCE flow with a local callback server."""
    pkce = generate_pkce()
    state = _generate_state()

    # Set up per-flow shared state
    result: dict[str, str] = {"expected_state": state}
    event = threading.Event()
    handler_cls = _make_callback_handler(result, event)

    # Start the callback server
    server = HTTPServer(("127.0.0.1", local_port), handler_cls)
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Build authorization URL with proper encoding
        endpoints = client.endpoints
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client.client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(scopes or []),
                "state": state,
                "code_challenge": pkce.challenge,
                "code_challenge_method": pkce.method,
            }
        )
        auth_url = f"{endpoints.authorize_url}?{query}"

        if not open_browser(auth_url):
            print(f"Open this URL in your browser:\n{auth_url}")

        # Wait for callback with timeout
        if not event.wait(timeout=_CALLBACK_TIMEOUT):
            raise AuthFlowError(
                f"auth code flow timed out after {_CALLBACK_TIMEOUT:.0f}s waiting for callback"
            )

        if "error" in result:
            raise OAuthError(
                code=result["error"],
                description=result.get("error_description", ""),
            )

        code = result["code"]
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    return client.exchange_auth_code(code, redirect_uri, pkce.verifier)
