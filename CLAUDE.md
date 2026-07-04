# CLAUDE.md

This file provides guidance to Claude Code when working with the Python SDK.

## Project Overview

Python SDK for Signet — mirrors the Go SDK's architecture using idiomatic Python patterns.

Package: `signet` (Python 3.10+, src layout with hatchling build)

## Common Commands

```bash
make install       # uv sync --all-extras (install all deps)
make test          # Run all tests with pytest
make lint          # Run ruff linter
make fmt           # Format code with ruff
make typecheck     # Run mypy strict
```

Project is managed with [uv](https://docs.astral.sh/uv/). All `make` targets use `uv run` so no manual venv activation is needed.

## Code Style

- ruff for linting and formatting (line length 100)
- mypy strict mode
- Dataclasses over Pydantic (zero extra deps)
- Sync + Async dual API in separate client classes
- Framework-specific middleware: users only import what they need
- `from __future__ import annotations` in all modules

## Architecture

- `oauth/` — Pure HTTP client layer (sync: `OAuthClient`, async: `AsyncOAuthClient`)
- `discovery/` — OIDC auto-discovery with caching
- `credstore/` — Generic credential storage (file, keyring, composite secure store)
- `authflow/` — Device Code flow, Auth Code + PKCE, auto-refresh TokenSource
- `middleware/` — Framework adapters (FastAPI, Flask, Django)
- `clientcreds/` — M2M Client Credentials with auto-caching
- `__init__.py` — `authenticate()` / `async_authenticate()` entry points

## Before Committing

All code must pass `make lint`, `make fmt`, and `make typecheck` before committing.
