"""Credential storage protocols (interfaces)."""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

T = TypeVar("T")


@runtime_checkable
class Store(Protocol[T]):
    """Interface for loading, saving, and deleting data by client ID."""

    def load(self, client_id: str) -> T: ...

    def save(self, client_id: str, data: T) -> None: ...

    def delete(self, client_id: str) -> None: ...

    def description(self) -> str: ...


@runtime_checkable
class Codec(Protocol[T]):
    """Handles encoding/decoding values to/from strings for storage."""

    def encode(self, value: T) -> str: ...

    def decode(self, data: str) -> T: ...


@runtime_checkable
class Prober(Protocol):
    """Tests whether a storage backend is available."""

    def probe(self) -> bool: ...


@runtime_checkable
class Lister(Protocol):
    """Optional interface for stores that support listing stored client IDs."""

    def list(self) -> list[str]: ...
