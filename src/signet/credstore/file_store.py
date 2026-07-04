"""File-based credential storage with atomic writes and file locking."""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
from typing import Generic, TypeVar

from signet.credstore.protocols import Codec
from signet.exceptions import CredStoreError, NotFoundError

T = TypeVar("T")

_LOCK_MAX_RETRIES = 50
_LOCK_RETRY_DELAY = 0.1  # 100ms
_STALE_LOCK_TIMEOUT = 30.0  # 30s


class _FileLock:
    """Cross-process file lock using exclusive file creation."""

    def __init__(self, lock_path: str) -> None:
        self._lock_path = lock_path
        self._fd: int | None = None

    def acquire(self) -> None:
        for _ in range(_LOCK_MAX_RETRIES):
            try:
                self._fd = os.open(
                    self._lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                return
            except FileExistsError:
                try:
                    stat = os.stat(self._lock_path)
                    if time.time() - stat.st_mtime > _STALE_LOCK_TIMEOUT:
                        with contextlib.suppress(FileNotFoundError):
                            os.remove(self._lock_path)
                        continue
                except FileNotFoundError:
                    continue
                time.sleep(_LOCK_RETRY_DELAY)
        raise CredStoreError(
            f"timeout waiting for file lock after {_LOCK_MAX_RETRIES * _LOCK_RETRY_DELAY}s"
        )

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        with contextlib.suppress(FileNotFoundError):
            os.remove(self._lock_path)


class FileStore(Generic[T]):
    """Stores values in a JSON file with file locking and atomic writes."""

    def __init__(self, file_path: str, codec: Codec[T]) -> None:
        self._file_path = file_path
        self._codec = codec

    @property
    def file_path(self) -> str:
        return self._file_path

    def load(self, client_id: str) -> T:
        """Load data from the file for the given client ID.

        No file lock needed: Save uses atomic rename, so reads always see
        a consistent snapshot on POSIX systems.
        """
        storage = self._read_storage_map()
        encoded = storage.get(client_id)
        if encoded is None:
            raise NotFoundError(f"not found: {client_id}")
        return self._codec.decode(encoded)

    def save(self, client_id: str, data: T) -> None:
        """Save data to the file for the given client ID.

        Uses file locking to prevent race conditions.
        """
        if not client_id:
            raise CredStoreError("client ID cannot be empty")
        encoded = self._codec.encode(data)
        self._ensure_dir()

        def _do() -> None:
            storage = self._read_storage_map()
            storage[client_id] = encoded
            self._write_storage_map(storage)

        self._with_file_lock(_do)

    def delete(self, client_id: str) -> None:
        """Remove data for the given client ID from the file."""

        def _do() -> None:
            storage = self._read_storage_map()
            if client_id not in storage:
                return
            del storage[client_id]
            self._write_storage_map(storage)

        self._with_file_lock(_do)

    def list(self) -> list[str]:
        """Return all stored client IDs, sorted alphabetically."""
        storage = self._read_storage_map()
        return sorted(storage.keys())

    def description(self) -> str:
        return f"file: {self._file_path}"

    def _read_storage_map(self) -> dict[str, str]:
        try:
            with open(self._file_path) as f:
                raw = json.load(f)
            return raw.get("data", {}) if isinstance(raw, dict) else {}
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            raise CredStoreError(f"failed to read file {self._file_path!r}: {exc}") from exc

    def _write_storage_map(self, data: dict[str, str]) -> None:
        content = json.dumps({"data": data}, indent=2)
        tmp_path = self._file_path + ".tmp"
        try:
            with open(tmp_path, "w", opener=lambda p, f: os.open(p, f, 0o600)) as f:
                f.write(content)
            os.rename(tmp_path, self._file_path)
        except OSError:
            with contextlib.suppress(FileNotFoundError):
                os.remove(tmp_path)
            raise

    def _ensure_dir(self) -> None:
        parent = os.path.dirname(self._file_path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)

    def _with_file_lock(self, fn: Callable[[], None]) -> None:
        lock = _FileLock(self._file_path + ".lock")
        lock.acquire()
        try:
            fn()
        finally:
            lock.release()
