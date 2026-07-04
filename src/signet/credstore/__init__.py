"""Credential storage with OS keyring integration and file-based fallback."""

from __future__ import annotations

from signet.credstore.codecs import JSONCodec, StringCodec
from signet.credstore.file_store import FileStore
from signet.credstore.keyring_store import KeyringStore
from signet.credstore.models import StoredToken
from signet.credstore.protocols import Codec, Lister, Prober, Store
from signet.credstore.secure_store import BackendChangeFunc, Diagnostics, SecureStore


def token_file_store(file_path: str) -> FileStore[StoredToken]:
    """Create a FileStore for StoredToken values using JSON encoding."""
    return FileStore(file_path, JSONCodec(StoredToken))


def token_keyring_store(service_name: str) -> KeyringStore[StoredToken]:
    """Create a KeyringStore for StoredToken values using JSON encoding."""
    return KeyringStore(service_name, JSONCodec(StoredToken))


def default_token_secure_store(
    service_name: str,
    file_path: str,
    *,
    on_change: BackendChangeFunc | None = None,
) -> SecureStore[StoredToken]:
    """Create a SecureStore for StoredToken values with sensible defaults."""
    codec: JSONCodec[StoredToken] = JSONCodec(StoredToken)
    return SecureStore(
        KeyringStore(service_name, codec),
        FileStore(file_path, codec),
        on_change=on_change,
    )


__all__ = [
    "BackendChangeFunc",
    "Codec",
    "Diagnostics",
    "FileStore",
    "JSONCodec",
    "KeyringStore",
    "Lister",
    "Prober",
    "SecureStore",
    "Store",
    "StoredToken",
    "StringCodec",
    "default_token_secure_store",
    "token_file_store",
    "token_keyring_store",
]
