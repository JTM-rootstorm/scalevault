from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

import pytest
from kivra_memory.application.queries import CandidateRepository, QueryEngine
from kivra_memory.application.sealed_content import (
    HmacSha256SealedDigestBinder,
    SealedMemoryPlaintext,
    decrypt_memory_state,
    envelope_state,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import MemoryStateV3
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.keys import (
    ContentKeyMaterial,
    ContentKeyReference,
    KeyDestructionReceipt,
)
from kivra_memory.security.sealed_content import SealedContentContext, seal_content
from kivra_memory.storage.retrieval import (
    HydratedMemory,
    SealedContentBinding,
)


class _Provider:
    name = "unit-provider"

    def __init__(self, key: ContentKeyMaterial) -> None:
        self.key = key

    async def provision_key(self, **_: object) -> ContentKeyReference:
        raise NotImplementedError

    async def get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        del reference
        return self.key

    async def destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        del reference
        return KeyDestructionReceipt(b"destroyed")


def test_digest_binder_sanitizes_invalid_purpose() -> None:
    binder = HmacSha256SealedDigestBinder(b"server-only-binding-secret-32-bytes")

    with pytest.raises(ValueError, match="binding unavailable") as caught:
        binder.bind_digest(purpose="private-\N{SNOWMAN}", material=b"sensitive")

    assert caught.value.__cause__ is None


@pytest.mark.asyncio
async def test_authorized_open_restores_semantic_shape() -> None:
    now = datetime.now(UTC)
    tenant_id = new_uuid7()
    lineage_id = new_uuid7()
    branch_id = new_uuid7()
    memory_id = new_uuid7()
    content_key_id = new_uuid7()
    event_id = new_uuid7()
    context = SealedContentContext(
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        memory_id=memory_id,
        content_key_id=content_key_id,
        revision=1,
        event_id=event_id,
        schema_version=3,
        payload_version=3,
    )
    key = ContentKeyMaterial(bytes(range(32)))
    plaintext = SealedMemoryPlaintext(
        statement="The private statement.",
        reason_to_remember="It matters later.",
        interpretation_limits=("Only in this context.",),
        metadata={"reviewed": True},
    )
    envelope = seal_content(
        key=key,
        plaintext=plaintext.canonical_bytes(),
        context=context,
        safe_summary="A reviewed private fact.",
    )
    state = MemoryStateV3(
        memory_id=memory_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        subject_id=new_uuid7(),
        subject_kind=SubjectKind.GLOBAL,
        revision=1,
        category=MemoryCategory.USER_PREFERENCE,
        ontological_status=OntologicalStatus.LITERAL_USER_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=4,
        authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
        content_protection="envelope_encrypted",
        content_key_id=content_key_id,
        created_at=now,
        updated_at=now,
        fingerprint_version=1,
        normalized_fingerprint=None,
        metadata={},
        candidate_expires_at=None,
        sealed_content=envelope_state(envelope),
    )
    reference = ContentKeyReference(content_key_id, "unit-provider", "opaque")

    opened = await decrypt_memory_state(
        state=state,
        provider=_Provider(key),
        reference=reference,
        context=context,
    )

    assert opened.statement == plaintext.statement
    assert opened.reason_to_remember == plaintext.reason_to_remember
    assert opened.interpretation_limits == plaintext.interpretation_limits
    assert opened.metadata == plaintext.metadata

    transition_event_id = new_uuid7()

    class _Repository:
        async def sealed_content_binding(self, **_: object) -> SealedContentBinding:
            return SealedContentBinding(
                event_id=event_id,
                revision=1,
                schema_version=3,
                payload_version=3,
            )

        async def content_key_reference(self, **_: object) -> ContentKeyReference:
            return reference

    async def assert_creation_context(**kwargs: object) -> bytes:
        assert kwargs["context"] == context
        return plaintext.canonical_bytes()

    engine = QueryEngine(
        cast(Any, None),
        cast(Any, None),
        key_provider=_Provider(key),
        content_opener=assert_creation_context,
    )
    reopened = await engine._open_sealed_memory(
        cast(CandidateRepository, _Repository()),
        HydratedMemory(state=state, last_event_id=transition_event_id),
    )

    assert reopened is not None
    assert reopened.statement == plaintext.statement

    async def provider_failure(**_: object) -> bytes:
        raise RuntimeError("provider-private-diagnostic")

    failing_engine = QueryEngine(
        cast(Any, None),
        cast(Any, None),
        key_provider=_Provider(key),
        content_opener=provider_failure,
    )
    assert (
        await failing_engine._open_sealed_memory(
            cast(CandidateRepository, _Repository()),
            HydratedMemory(state=state, last_event_id=transition_event_id),
        )
        is None
    )
