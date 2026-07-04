"""Encoding/decoding values for storage."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Generic, TypeVar

from signet.exceptions import CredStoreError

T = TypeVar("T")


class JSONCodec(Generic[T]):
    """Encodes T as JSON."""

    def __init__(self, cls: type[T]) -> None:
        self._cls = cls

    def encode(self, value: T) -> str:
        try:
            if hasattr(value, "__dataclass_fields__"):
                return json.dumps(asdict(value))  # type: ignore[call-overload]
            return json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise CredStoreError(f"failed to marshal data: {exc}") from exc

    def decode(self, data: str) -> T:
        try:
            raw: Any = json.loads(data)
            if hasattr(self._cls, "__dataclass_fields__"):
                return self._cls(**raw)
            return raw  # type: ignore[no-any-return]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CredStoreError(f"failed to unmarshal data: {exc}") from exc


class StringCodec:
    """Identity codec for plain strings."""

    def encode(self, value: str) -> str:
        return value

    def decode(self, data: str) -> str:
        return data
