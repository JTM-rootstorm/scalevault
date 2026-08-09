"""External content-key provider boundary for sealed canonical memories."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from uuid import UUID

from kivra_memory.domain.identifiers import require_uuid7

CONTENT_KEY_BYTES = 32
MAX_PROVIDER_NAME_LENGTH = 64
MAX_PROVIDER_REFERENCE_LENGTH = 512


class KeyProviderError(Exception):
    """Safe provider-boundary failure with no provider diagnostic attached."""

    def __init__(self) -> None:
        super().__init__("sealed content key is unavailable")


@dataclass(frozen=True, slots=True)
class ContentKeyReference:
    """Opaque persistence-safe reference to key material held outside ScaleVault."""

    content_key_id: UUID
    provider_name: str
    provider_key_reference: str = field(repr=False)

    def __post_init__(self) -> None:
        require_uuid7(self.content_key_id, field_name="content_key_id")
        _validate_bounded_text(
            self.provider_name,
            field_name="provider_name",
            maximum=MAX_PROVIDER_NAME_LENGTH,
        )
        _validate_bounded_text(
            self.provider_key_reference,
            field_name="provider_key_reference",
            maximum=MAX_PROVIDER_REFERENCE_LENGTH,
        )


class ContentKeyMaterial:
    """Short-lived 256-bit key material that is always redacted from representations."""

    __slots__ = ("__key",)

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != CONTENT_KEY_BYTES:
            raise KeyProviderError()
        self.__key = key

    def __repr__(self) -> str:
        return "ContentKeyMaterial(<redacted>)"

    def __str__(self) -> str:
        return "<redacted content key>"

    def _bytes_for_crypto(self) -> bytes:
        return self.__key


@dataclass(frozen=True, slots=True)
class KeyDestructionReceipt:
    """Opaque receipt bytes whose digest, but not contents, may be persisted."""

    receipt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, bytes) or not self.receipt:
            raise KeyProviderError()


@runtime_checkable
class KeyDestroyer(Protocol):
    """Destruction-only capability for per-memory data-encryption keys."""

    @property
    def name(self) -> str:
        """Return the stable provider name persisted with opaque key references."""
        ...

    async def destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        """Irreversibly destroy a content key and return an opaque receipt.

        Destruction must be idempotent: retries after a successful destruction
        return the same stable receipt so a database transaction can safely
        record completion after an interrupted attempt.
        """
        ...


@runtime_checkable
class KeyProvider(KeyDestroyer, Protocol):
    """Root-controlled provider that can provision and read content keys."""

    async def provision_key(
        self,
        *,
        content_key_id: UUID,
        tenant_id: UUID,
        lineage_id: UUID,
        memory_id: UUID,
    ) -> ContentKeyReference:
        """Generate and retain a new independent 256-bit content key.

        Retries with the same content-key and canonical identity must return the
        same reference without replacing key material. Reuse with a different
        identity must fail closed.
        """
        ...

    async def get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        """Load transient key material for an active external reference."""
        ...


def _validate_bounded_text(value: str, *, field_name: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError(f"{field_name} is invalid")


__all__ = [
    "CONTENT_KEY_BYTES",
    "ContentKeyMaterial",
    "ContentKeyReference",
    "KeyDestroyer",
    "KeyDestructionReceipt",
    "KeyProvider",
    "KeyProviderError",
]
