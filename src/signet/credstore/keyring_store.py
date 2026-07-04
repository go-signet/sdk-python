"""OS keyring credential storage.

Supports macOS Keychain, Linux Secret Service, and Windows Credential Manager.
"""

from __future__ import annotations

from typing import Generic, TypeVar

import keyring
import keyring.errors

from signet.credstore.protocols import Codec
from signet.exceptions import CredStoreError, NotFoundError

T = TypeVar("T")

_PROBE_USER = "__signet_probe__"


class KeyringStore(Generic[T]):
    """Stores values in the OS keyring."""

    def __init__(self, service_name: str, codec: Codec[T]) -> None:
        self._service_name = service_name
        self._codec = codec

    @property
    def service_name(self) -> str:
        return self._service_name

    def probe(self) -> bool:
        """Test whether the OS keyring is available."""
        try:
            keyring.set_password(self._service_name, _PROBE_USER, "probe")
            keyring.delete_password(self._service_name, _PROBE_USER)
            return True
        except Exception:
            return False

    def load(self, client_id: str) -> T:
        """Load data from the keyring for the given client ID."""
        data = keyring.get_password(self._service_name, client_id)
        if data is None:
            raise NotFoundError(f"not found: {client_id}")
        return self._codec.decode(data)

    def save(self, client_id: str, data: T) -> None:
        """Save data to the keyring for the given client ID."""
        if not client_id:
            raise CredStoreError("client ID cannot be empty")
        encoded = self._codec.encode(data)
        try:
            keyring.set_password(self._service_name, client_id, encoded)
        except Exception as exc:
            raise CredStoreError(f"failed to save to keyring: {exc}") from exc

    def delete(self, client_id: str) -> None:
        """Remove data for the given client ID from the keyring."""
        try:
            keyring.delete_password(self._service_name, client_id)
        except keyring.errors.PasswordDeleteError:
            pass
        except Exception as exc:
            raise CredStoreError(f"failed to delete from keyring: {exc}") from exc

    def description(self) -> str:
        return f"keyring: {self._service_name}"
