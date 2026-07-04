"""Composite store: OS keyring primary with file fallback."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from signet.credstore.protocols import Prober, Store

T = TypeVar("T")

BackendChangeFunc = Callable[[str], None]


@dataclass
class Diagnostics:
    """Point-in-time snapshot of SecureStore state."""

    backend: str
    use_keyring: bool
    can_probe: bool


class SecureStore(Generic[T]):
    """Composite Store that tries the OS keyring first and falls back to file-based storage.

    Both stores are retained so that ``refresh()`` can switch between them.
    All methods are safe for concurrent use.
    """

    def __init__(
        self,
        kr: Store[T],
        file: Store[T],
        *,
        on_change: BackendChangeFunc | None = None,
    ) -> None:
        self._kr = kr
        self._file = file
        self._on_change = on_change
        self._lock = threading.RLock()
        self._use_keyring = False

        if isinstance(kr, Prober) and kr.probe():
            self._use_keyring = True
        elif on_change is not None:
            on_change(file.description())

    def _active(self) -> Store[T]:
        with self._lock:
            return self._kr if self._use_keyring else self._file

    def refresh(self) -> bool:
        """Re-probe the keyring backend and switch if availability changed.

        Returns True if the active backend changed.
        """
        if not isinstance(self._kr, Prober):
            return False

        available = self._kr.probe()

        with self._lock:
            if available == self._use_keyring:
                return False
            self._use_keyring = available
            new_backend = self._kr.description() if available else self._file.description()
            cb = self._on_change

        if cb is not None:
            cb(new_backend)
        return True

    @property
    def use_keyring(self) -> bool:
        with self._lock:
            return self._use_keyring

    def diagnostic(self) -> Diagnostics:
        with self._lock:
            backend = self._kr if self._use_keyring else self._file
            return Diagnostics(
                backend=backend.description(),
                use_keyring=self._use_keyring,
                can_probe=isinstance(self._kr, Prober),
            )

    def load(self, client_id: str) -> T:
        return self._active().load(client_id)

    def save(self, client_id: str, data: T) -> None:
        self._active().save(client_id, data)

    def delete(self, client_id: str) -> None:
        self._active().delete(client_id)

    def description(self) -> str:
        return self._active().description()
