# Signet Python SDK

[![PyPI](https://img.shields.io/pypi/v/go-signet)](https://pypi.org/project/go-signet/)
[![Python](https://img.shields.io/pypi/pyversions/go-signet)](https://pypi.org/project/go-signet/)
[![CI](https://github.com/go-signet/sdk-python/actions/workflows/testing.yml/badge.svg)](https://github.com/go-signet/sdk-python/actions/workflows/testing.yml)
[![Trivy](https://github.com/go-signet/sdk-python/actions/workflows/trivy.yml/badge.svg)](https://github.com/go-signet/sdk-python/actions/workflows/trivy.yml)
[![License](https://img.shields.io/pypi/l/go-signet)](LICENSE)

Python SDK for [Signet](https://github.com/go-signet) — OAuth 2.0 authentication and token management.

## Installation

```bash
pip install go-signet
```

With framework support:

```bash
pip install go-signet[fastapi]
pip install go-signet[flask]
pip install go-signet[django]
```

## Quick Start

```python
from signet import authenticate

client, token = authenticate(
    "https://auth.example.com",
    "my-client-id",
    scopes=["profile", "email"],
)

print(f"Access token: {token.access_token}")
```

## Async Usage

```python
from signet import async_authenticate

client, token = await async_authenticate(
    "https://auth.example.com",
    "my-client-id",
    scopes=["profile", "email"],
)
```

## Client Credentials (M2M)

```python
from signet.discovery.client import DiscoveryClient
from signet.oauth import OAuthClient
from signet.clientcreds import TokenSource, BearerAuth
import httpx

disco = DiscoveryClient("https://auth.example.com")
meta = disco.fetch()
client = OAuthClient("my-service", meta.to_endpoints(), client_secret="secret")
ts = TokenSource(client, scopes=["api"])

# Auto-attaches Bearer token to every request
with httpx.Client(auth=BearerAuth(ts)) as http:
    resp = http.get("https://api.example.com/data")
```

## Middleware

### FastAPI

```python
from fastapi import FastAPI, Depends
from signet.middleware.fastapi import BearerAuth
from signet.middleware.models import TokenInfo

app = FastAPI()
auth = BearerAuth(oauth_client)

@app.get("/protected")
async def protected(info: TokenInfo = Depends(auth)):
    return {"user": info.user_id}
```

### Flask

```python
from flask import Flask
from signet.middleware.flask import bearer_auth, get_token_info

app = Flask(__name__)

@app.route("/protected")
@bearer_auth(oauth_client)
def protected():
    info = get_token_info()
    return {"user": info.user_id}
```

## Examples

Ready-to-run examples are in the [`examples/`](examples/) directory:

| File                                                            | Description                                                       |
| --------------------------------------------------------------- | ----------------------------------------------------------------- |
| [`01_user_login.py`](examples/01_user_login.py)                 | Interactive user login — auto-selects browser or device code flow |
| [`02_client_credentials.py`](examples/02_client_credentials.py) | M2M service authentication with auto-cached tokens                |
| [`03_fastapi_server.py`](examples/03_fastapi_server.py)         | FastAPI server with Bearer token validation and scope enforcement |
| [`04_async_login.py`](examples/04_async_login.py)               | Async user login via device code flow                             |

Set the required environment variables, then run with `uv`:

```bash
export SIGNET_URL="https://auth.example.com"
export CLIENT_ID="my-app"

uv run python examples/01_user_login.py
```

## Development

```bash
make install    # uv sync --all-extras
make test
make lint
make typecheck
```

## License

MIT
