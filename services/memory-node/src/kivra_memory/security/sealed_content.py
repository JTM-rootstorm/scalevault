"""Versioned authenticated envelope primitives for sealed canonical content."""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kivra_memory.domain.canonical_json import canonical_json_bytes, sha256_digest
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.security.keys import (
    ContentKeyMaterial,
    ContentKeyReference,
    KeyProvider,
)

SEALED_ENVELOPE_VERSION: Final = 1
SEALED_ENVELOPE_CONTRACT: Final = "scalevault.sealed-content-envelope.v1"
SEALED_AAD_CONTRACT: Final = "scalevault.sealed-content-aad.v1"
SEALED_ALGORITHM: Final = "AES-256-GCM"
NONCE_BYTES: Final = 12
AUTHENTICATION_TAG_BYTES: Final = 16
AAD_SHA256_BYTES: Final = 32
MIN_SEALED_PLAINTEXT_BYTES: Final = 1
MAX_SEALED_PLAINTEXT_BYTES: Final = 700 * 1024
MIN_SEALED_CIPHERTEXT_BYTES: Final = MIN_SEALED_PLAINTEXT_BYTES + AUTHENTICATION_TAG_BYTES
MAX_SEALED_CIPHERTEXT_BYTES: Final = MAX_SEALED_PLAINTEXT_BYTES + AUTHENTICATION_TAG_BYTES
MAX_SAFE_SUMMARY_CHARACTERS: Final = 1024
MAX_SAFE_SUMMARY_UTF8_BYTES: Final = 4096


class SealedContentError(Exception):
    """Base class for stable, content-free sealed-content failures."""


class InvalidSealedEnvelopeError(SealedContentError):
    """The supplied sealed envelope is structurally invalid."""

    def __init__(self) -> None:
        super().__init__("sealed content envelope is invalid")


class SealedContentAuthenticationError(SealedContentError):
    """Envelope authentication or AAD binding failed without disclosing which."""

    def __init__(self) -> None:
        super().__init__("sealed content authentication failed")


class SealedContentKeyUnavailableError(SealedContentError):
    """The selected external key provider could not supply key material."""

    def __init__(self) -> None:
        super().__init__("sealed content key is unavailable")


@dataclass(frozen=True, slots=True)
class SealedContentContext:
    """Identity and contract fields authenticated as canonical versioned AAD."""

    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    memory_id: UUID
    content_key_id: UUID
    revision: int
    event_id: UUID
    schema_version: int
    payload_version: int

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "lineage_id",
            "branch_id",
            "memory_id",
            "content_key_id",
            "event_id",
        ):
            require_uuid7(getattr(self, field_name), field_name=field_name)
        for field_name in ("revision", "schema_version", "payload_version"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 32_767:
                raise ValueError(f"{field_name} must be between 1 and 32767")

    def aad_document(self) -> dict[str, object]:
        """Return the closed v1 AAD document before RFC 8785 serialization."""

        return {
            "aad_contract": SEALED_AAD_CONTRACT,
            "algorithm": SEALED_ALGORITHM,
            "branch_id": self.branch_id,
            "content_key_id": self.content_key_id,
            "event_id": self.event_id,
            "lineage_id": self.lineage_id,
            "memory_id": self.memory_id,
            "payload_version": self.payload_version,
            "revision": self.revision,
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
        }

    def aad_bytes(self) -> bytes:
        """Return deterministic RFC 8785 AAD bytes."""

        return canonical_json_bytes(self.aad_document())


@dataclass(frozen=True, slots=True)
class SealedContentEnvelope:
    """Validated raw-byte representation persisted by the canonical node."""

    content_key_id: UUID
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    aad_sha256: bytes = field(repr=False)
    safe_summary: str
    envelope_version: int = SEALED_ENVELOPE_VERSION
    algorithm: str = SEALED_ALGORITHM

    def __post_init__(self) -> None:
        try:
            require_uuid7(self.content_key_id, field_name="content_key_id")
            _validate_envelope_version(self.envelope_version)
            if self.algorithm != SEALED_ALGORITHM:
                raise ValueError
            if not isinstance(self.nonce, bytes) or len(self.nonce) != NONCE_BYTES:
                raise ValueError
            if (
                not isinstance(self.ciphertext, bytes)
                or not MIN_SEALED_CIPHERTEXT_BYTES
                <= len(self.ciphertext)
                <= MAX_SEALED_CIPHERTEXT_BYTES
            ):
                raise ValueError
            if not isinstance(self.aad_sha256, bytes) or len(self.aad_sha256) != AAD_SHA256_BYTES:
                raise ValueError
            _validate_safe_summary(self.safe_summary)
        except (TypeError, ValueError):
            raise InvalidSealedEnvelopeError() from None

    def to_json_document(self) -> dict[str, object]:
        """Return the closed Base64 JSON-boundary representation."""

        return {
            "contract_version": SEALED_ENVELOPE_CONTRACT,
            "envelope_version": self.envelope_version,
            "algorithm": self.algorithm,
            "content_key_id": str(self.content_key_id),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "aad_sha256": self.aad_sha256.hex(),
            "safe_summary": self.safe_summary,
        }

    @classmethod
    def from_json_document(cls, document: Mapping[str, object]) -> SealedContentEnvelope:
        """Decode a strict closed JSON envelope without leaking parser diagnostics."""

        expected_fields = {
            "contract_version",
            "envelope_version",
            "algorithm",
            "content_key_id",
            "nonce",
            "ciphertext",
            "aad_sha256",
            "safe_summary",
        }
        try:
            if not isinstance(document, Mapping) or set(document) != expected_fields:
                raise ValueError
            if document["contract_version"] != SEALED_ENVELOPE_CONTRACT:
                raise ValueError
            content_key_id_value = document["content_key_id"]
            nonce_value = document["nonce"]
            ciphertext_value = document["ciphertext"]
            aad_sha256_value = document["aad_sha256"]
            envelope_version_value = document["envelope_version"]
            algorithm_value = document["algorithm"]
            safe_summary_value = document["safe_summary"]
            if (
                not isinstance(content_key_id_value, str)
                or not isinstance(nonce_value, str)
                or not isinstance(ciphertext_value, str)
                or not isinstance(aad_sha256_value, str)
                or not isinstance(envelope_version_value, int)
                or not isinstance(algorithm_value, str)
                or not isinstance(safe_summary_value, str)
            ):
                raise ValueError
            content_key_id = UUID(content_key_id_value)
            if str(content_key_id) != content_key_id_value:
                raise ValueError
            if (
                len(aad_sha256_value) != AAD_SHA256_BYTES * 2
                or aad_sha256_value != aad_sha256_value.lower()
            ):
                raise ValueError
            nonce = _decode_canonical_base64(nonce_value)
            ciphertext = _decode_canonical_base64(ciphertext_value)
            aad_sha256 = bytes.fromhex(aad_sha256_value)
            return cls(
                envelope_version=envelope_version_value,
                algorithm=algorithm_value,
                content_key_id=content_key_id,
                nonce=nonce,
                ciphertext=ciphertext,
                aad_sha256=aad_sha256,
                safe_summary=safe_summary_value,
            )
        except (binascii.Error, TypeError, ValueError, InvalidSealedEnvelopeError):
            raise InvalidSealedEnvelopeError() from None


def seal_content(
    *,
    key: ContentKeyMaterial,
    plaintext: bytes,
    context: SealedContentContext,
    safe_summary: str,
) -> SealedContentEnvelope:
    """Encrypt canonical sensitive bytes with fresh AES-256-GCM nonce and bound AAD."""

    if (
        not isinstance(plaintext, bytes)
        or not MIN_SEALED_PLAINTEXT_BYTES <= len(plaintext) <= MAX_SEALED_PLAINTEXT_BYTES
    ):
        raise InvalidSealedEnvelopeError()
    _validate_safe_summary_or_raise(safe_summary)
    nonce = secrets.token_bytes(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise SealedContentError("sealed content encryption failed")
    aad = context.aad_bytes()
    try:
        ciphertext = AESGCM(key._bytes_for_crypto()).encrypt(nonce, plaintext, aad)
    except (TypeError, ValueError):
        raise SealedContentError("sealed content encryption failed") from None
    return SealedContentEnvelope(
        content_key_id=context.content_key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        aad_sha256=sha256_digest(aad),
        safe_summary=safe_summary,
    )


def open_content(
    *,
    key: ContentKeyMaterial,
    envelope: SealedContentEnvelope,
    context: SealedContentContext,
) -> bytes:
    """Authenticate the complete binding before exposing sealed plaintext bytes."""

    aad = context.aad_bytes()
    if envelope.content_key_id != context.content_key_id or not hmac.compare_digest(
        envelope.aad_sha256, sha256_digest(aad)
    ):
        raise SealedContentAuthenticationError()
    try:
        plaintext = AESGCM(key._bytes_for_crypto()).decrypt(
            envelope.nonce, envelope.ciphertext, aad
        )
    except (InvalidTag, TypeError, ValueError):
        raise SealedContentAuthenticationError() from None
    if not MIN_SEALED_PLAINTEXT_BYTES <= len(plaintext) <= MAX_SEALED_PLAINTEXT_BYTES:
        raise SealedContentAuthenticationError()
    return plaintext


async def seal_with_provider(
    *,
    provider: KeyProvider,
    reference: ContentKeyReference,
    plaintext: bytes,
    context: SealedContentContext,
    safe_summary: str,
) -> SealedContentEnvelope:
    """Resolve a key only through its owning provider and seal content."""

    key = await _key_from_provider(provider, reference, context)
    return seal_content(key=key, plaintext=plaintext, context=context, safe_summary=safe_summary)


async def open_with_provider(
    *,
    provider: KeyProvider,
    reference: ContentKeyReference,
    envelope: SealedContentEnvelope,
    context: SealedContentContext,
) -> bytes:
    """Resolve a key only through its owning provider and authenticate content."""

    key = await _key_from_provider(provider, reference, context)
    return open_content(key=key, envelope=envelope, context=context)


async def _key_from_provider(
    provider: KeyProvider,
    reference: ContentKeyReference,
    context: SealedContentContext,
) -> ContentKeyMaterial:
    if reference.content_key_id != context.content_key_id:
        raise SealedContentKeyUnavailableError()
    try:
        if provider.name != reference.provider_name:
            raise SealedContentKeyUnavailableError()
        key = await provider.get_key(reference)
    except SealedContentKeyUnavailableError:
        raise
    except Exception:
        raise SealedContentKeyUnavailableError() from None
    if not isinstance(key, ContentKeyMaterial):
        raise SealedContentKeyUnavailableError()
    return key


def _validate_envelope_version(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != SEALED_ENVELOPE_VERSION:
        raise ValueError


def _decode_canonical_base64(value: str) -> bytes:
    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError
    return decoded


def _validate_safe_summary(value: object) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_SAFE_SUMMARY_CHARACTERS
        or not value.strip()
        or len(value.encode("utf-8")) > MAX_SAFE_SUMMARY_UTF8_BYTES
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ValueError


def _validate_safe_summary_or_raise(value: object) -> None:
    try:
        _validate_safe_summary(value)
    except (TypeError, UnicodeError, ValueError):
        raise InvalidSealedEnvelopeError() from None


__all__ = [
    "AAD_SHA256_BYTES",
    "AUTHENTICATION_TAG_BYTES",
    "MAX_SAFE_SUMMARY_CHARACTERS",
    "MAX_SEALED_CIPHERTEXT_BYTES",
    "MAX_SEALED_PLAINTEXT_BYTES",
    "MIN_SEALED_CIPHERTEXT_BYTES",
    "MIN_SEALED_PLAINTEXT_BYTES",
    "NONCE_BYTES",
    "SEALED_AAD_CONTRACT",
    "SEALED_ALGORITHM",
    "SEALED_ENVELOPE_CONTRACT",
    "SEALED_ENVELOPE_VERSION",
    "InvalidSealedEnvelopeError",
    "SealedContentAuthenticationError",
    "SealedContentContext",
    "SealedContentEnvelope",
    "SealedContentError",
    "SealedContentKeyUnavailableError",
    "open_content",
    "open_with_provider",
    "seal_content",
    "seal_with_provider",
]
