"""Application contracts for sealed canonical memory content."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.events import (
    MemoryStateV2,
    MemoryStateV3,
    SealedContentEnvelopeState,
)
from kivra_memory.security.keys import ContentKeyReference, KeyProvider
from kivra_memory.security.sealed_content import (
    SealedContentContext,
    SealedContentEnvelope,
    open_with_provider,
    seal_with_provider,
)


class SealedContentRequest(BaseModel):
    """Explicit caller request to seal a nomination under a reviewed safe summary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    safe_summary: Annotated[str, Field(min_length=1, max_length=1024)]

    @model_validator(mode="after")
    def validate_safe_summary(self) -> SealedContentRequest:
        if not self.safe_summary.strip() or len(self.safe_summary.encode("utf-8")) > 4096:
            raise ValueError("sealed-content safe summary is invalid")
        return self


class SealedMemoryPlaintext(BaseModel):
    """Closed inner plaintext document encrypted as canonical JSON bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: str = "scalevault.sealed-memory-plaintext.v1"
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: Annotated[str, Field(min_length=1, max_length=4096)]
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...],
        Field(max_length=32),
    ]
    metadata: Annotated[dict[str, object], Field(max_length=128)]

    @model_validator(mode="after")
    def validate_content(self) -> SealedMemoryPlaintext:
        if self.contract_version != "scalevault.sealed-memory-plaintext.v1":
            raise ValueError("sealed plaintext contract is unsupported")
        if not self.statement.strip() or not self.reason_to_remember.strip():
            raise ValueError("sealed plaintext content is invalid")
        if len(set(self.interpretation_limits)) != len(self.interpretation_limits):
            raise ValueError("sealed interpretation limits must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="python"))


type ContentSealer = Callable[
    ...,
    Awaitable[SealedContentEnvelope],
]
type ContentOpener = Callable[..., Awaitable[bytes]]


class SealedDigestBinder(Protocol):
    """Bind sensitive canonical material to a server-only stable secret.

    Implementations must be deterministic across node restarts and deployments
    that share an archive.  The binding secret must never be persisted in the
    canonical event store, selection history, command receipts, or archive.
    """

    def bind_digest(self, *, purpose: str, material: bytes) -> bytes: ...


class HmacSha256SealedDigestBinder:
    """HMAC-SHA-256 implementation of the sealed digest binding contract."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("sealed digest binding secret is invalid")
        self._secret = secret

    def bind_digest(self, *, purpose: str, material: bytes) -> bytes:
        try:
            purpose_bytes = purpose.encode("ascii")
        except (AttributeError, UnicodeEncodeError):
            raise ValueError("sealed digest binding unavailable") from None
        if not isinstance(material, bytes) or not purpose_bytes or len(purpose_bytes) > 64:
            raise ValueError("sealed digest binding unavailable")
        framed = len(purpose_bytes).to_bytes(2, "big") + purpose_bytes + material
        return hmac.new(self._secret, framed, hashlib.sha256).digest()


def bind_sealed_digest(
    binder: SealedDigestBinder | None,
    *,
    purpose: str,
    material: bytes,
) -> bytes:
    """Return one validated, content-free keyed digest or fail closed."""

    if binder is None:
        raise ValueError("sealed digest binding unavailable")
    try:
        digest = binder.bind_digest(purpose=purpose, material=material)
    except Exception:
        raise ValueError("sealed digest binding unavailable") from None
    if not isinstance(digest, bytes) or len(digest) != hashlib.sha256().digest_size:
        raise ValueError("sealed digest binding unavailable")
    return digest


def envelope_state(envelope: SealedContentEnvelope) -> SealedContentEnvelopeState:
    """Convert the security primitive into the canonical event representation."""

    return SealedContentEnvelopeState.model_validate(envelope.to_json_document(), strict=False)


def envelope_primitive(state: SealedContentEnvelopeState) -> SealedContentEnvelope:
    """Convert a canonical event envelope into the validated security primitive."""

    return SealedContentEnvelope.from_json_document(state.model_dump(mode="json"))


async def decrypt_memory_state(
    *,
    state: MemoryStateV3,
    provider: KeyProvider,
    reference: ContentKeyReference,
    context: SealedContentContext,
    opener: ContentOpener = open_with_provider,
) -> MemoryStateV2:
    """Open one already-authorized v3 state into the established semantic read shape."""

    plaintext_bytes = await opener(
        provider=provider,
        reference=reference,
        envelope=envelope_primitive(state.sealed_content),
        context=context,
    )
    try:
        plaintext = SealedMemoryPlaintext.model_validate_json(plaintext_bytes)
    except Exception:
        raise ValueError("sealed memory plaintext is invalid") from None
    return MemoryStateV2.model_validate(
        {
            **state.model_dump(
                mode="python",
                exclude={
                    "sealed_content",
                    "statement",
                    "reason_to_remember",
                    "interpretation_limits",
                    "metadata",
                },
            ),
            "statement": plaintext.statement,
            "reason_to_remember": plaintext.reason_to_remember,
            "interpretation_limits": plaintext.interpretation_limits,
            "metadata": plaintext.metadata,
        }
    )


__all__ = [
    "ContentOpener",
    "ContentSealer",
    "HmacSha256SealedDigestBinder",
    "SealedContentRequest",
    "SealedDigestBinder",
    "SealedMemoryPlaintext",
    "bind_sealed_digest",
    "decrypt_memory_state",
    "envelope_primitive",
    "envelope_state",
    "seal_with_provider",
]
