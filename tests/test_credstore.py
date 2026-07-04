"""Tests for the credstore module."""

from __future__ import annotations

import json
import os
import time

import pytest

from signet.credstore.codecs import JSONCodec, StringCodec
from signet.credstore.file_store import FileStore
from signet.credstore.models import StoredToken
from signet.credstore.secure_store import SecureStore
from signet.exceptions import CredStoreError, NotFoundError


class TestStoredToken:
    def test_is_valid(self) -> None:
        tok = StoredToken(access_token="abc", expires_at=time.time() + 3600)
        assert tok.is_valid()

    def test_is_expired(self) -> None:
        tok = StoredToken(access_token="abc", expires_at=time.time() - 10)
        assert tok.is_expired()
        assert not tok.is_valid()

    def test_no_expiry(self) -> None:
        tok = StoredToken(access_token="abc")
        assert not tok.is_expired()
        assert tok.is_valid()


class TestJSONCodec:
    def test_encode_decode_dataclass(self) -> None:
        codec = JSONCodec(StoredToken)
        tok = StoredToken(access_token="abc", client_id="client1")
        encoded = codec.encode(tok)
        decoded = codec.decode(encoded)
        assert decoded.access_token == "abc"
        assert decoded.client_id == "client1"

    def test_decode_error(self) -> None:
        codec = JSONCodec(StoredToken)
        with pytest.raises(CredStoreError, match="unmarshal"):
            codec.decode("not-json")


class TestStringCodec:
    def test_identity(self) -> None:
        codec = StringCodec()
        assert codec.encode("hello") == "hello"
        assert codec.decode("hello") == "hello"


class TestFileStore:
    def test_save_load_delete(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        codec = JSONCodec(StoredToken)
        store = FileStore(path, codec)

        tok = StoredToken(access_token="abc", client_id="c1")
        store.save("c1", tok)

        loaded = store.load("c1")
        assert loaded.access_token == "abc"

        store.delete("c1")
        with pytest.raises(NotFoundError):
            store.load("c1")

    def test_load_not_found(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        with pytest.raises(NotFoundError):
            store.load("nonexistent")

    def test_save_empty_client_id(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        with pytest.raises(CredStoreError, match="client ID cannot be empty"):
            store.save("", StoredToken())

    def test_list(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        store.save("beta", StoredToken(access_token="b"))
        store.save("alpha", StoredToken(access_token="a"))
        ids = store.list()
        assert ids == ["alpha", "beta"]

    def test_description(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        assert store.description() == f"file: {path}"

    def test_atomic_write(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        store.save("c1", StoredToken(access_token="abc"))
        # Verify the file is valid JSON
        with open(path) as f:
            data = json.load(f)
        assert "data" in data
        assert "c1" in data["data"]

    def test_creates_parent_dirs(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/deep/nested/tokens.json"  # type: ignore[operator]
        store = FileStore(path, JSONCodec(StoredToken))
        store.save("c1", StoredToken(access_token="abc"))
        assert os.path.exists(path)

    def test_string_file_store(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/strings.json"  # type: ignore[operator]
        store = FileStore(path, StringCodec())
        store.save("key1", "value1")
        assert store.load("key1") == "value1"


class TestSecureStore:
    def test_file_fallback(self, tmp_path: object) -> None:
        """When keyring probe fails, should fall back to file."""
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        codec = JSONCodec(StoredToken)
        file_store = FileStore(path, codec)

        # Create a mock keyring store that fails probe
        class FakeKeyring:
            def probe(self) -> bool:
                return False

            def load(self, client_id: str) -> StoredToken:
                raise NotFoundError("not found")

            def save(self, client_id: str, data: StoredToken) -> None:
                raise CredStoreError("keyring unavailable")

            def delete(self, client_id: str) -> None:
                pass

            def description(self) -> str:
                return "fake-keyring"

        backends: list[str] = []
        store = SecureStore(
            FakeKeyring(),  # type: ignore[arg-type]
            file_store,  # type: ignore[arg-type]
            on_change=lambda b: backends.append(b),
        )

        assert not store.use_keyring
        assert backends == [f"file: {path}"]

        tok = StoredToken(access_token="abc", client_id="c1")
        store.save("c1", tok)
        loaded = store.load("c1")
        assert loaded.access_token == "abc"

    def test_diagnostic(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/tokens.json"  # type: ignore[operator]
        codec = JSONCodec(StoredToken)
        file_store = FileStore(path, codec)

        class FakeKeyring:
            def probe(self) -> bool:
                return False

            def load(self, client_id: str) -> StoredToken:
                raise NotFoundError("not found")

            def save(self, client_id: str, data: StoredToken) -> None:
                pass

            def delete(self, client_id: str) -> None:
                pass

            def description(self) -> str:
                return "fake-keyring"

        store = SecureStore(FakeKeyring(), file_store)  # type: ignore[arg-type]
        diag = store.diagnostic()
        assert not diag.use_keyring
        assert diag.can_probe
        assert diag.backend == f"file: {path}"
