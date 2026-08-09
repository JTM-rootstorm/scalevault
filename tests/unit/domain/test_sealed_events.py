from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from kivra_memory.application.sealed_content import envelope_state
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import (
    BranchState,
    MemoryCreatedPayloadV3,
    MemoryEvent,
    MemoryStateV3,
    TombstonedPayloadV3,
    event_hash_fields,
)
from kivra_memory.domain.folding import FoldError, ProjectionState, fold_event
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.keys import ContentKeyMaterial
from kivra_memory.security.sealed_content import SealedContentContext, seal_content


def test_v3_sealed_creation_folds_without_plaintext_canary() -> None:
    now = datetime.now(UTC)
    tenant_id = new_uuid7()
    lineage_id = new_uuid7()
    branch_id = new_uuid7()
    memory_id = new_uuid7()
    content_key_id = new_uuid7()
    event_id = new_uuid7()
    actor_id = new_uuid7()
    client_id = new_uuid7()
    canary = "SEALED-CANARY-MUST-NOT-LEAK"
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
    envelope = seal_content(
        key=ContentKeyMaterial(bytes(range(32))),
        plaintext=(f'{{"statement":"{canary}"}}').encode(),
        context=context,
        safe_summary="A reviewed private preference.",
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
    payload = MemoryCreatedPayloadV3(memory=state)
    values, canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=EventOperation.REMEMBERED,
        payload=payload,
        payload_version=3,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
    )
    event = MemoryEvent(
        schema_version=3,
        payload_version=3,
        sequence=1,
        event_id=event_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=new_uuid7(),
        session_id=None,
        ingress_id=None,
        operation=EventOperation.REMEMBERED,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
        correlation_id=new_uuid7(),
        idempotency_key="sealed-v3-create",
        policy_version=3,
        normalization_version=1,
        payload=values,
        payload_canonical=canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=now,
    )
    branch = BranchState(
        branch_id=branch_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        name="main",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=now,
    )

    folded = fold_event(ProjectionState(branches={branch_id: branch}), event)

    assert folded.memories[memory_id] == state
    assert canary not in event.payload_canonical
    assert canary not in str(event.payload)

    tombstoned_at = now + timedelta(seconds=1)
    changed_envelope = state.sealed_content.model_copy(
        update={"safe_summary": "A different reviewed summary."}
    )
    tombstone = TombstonedPayloadV3(
        previous_revision=1,
        memory=state.model_copy(
            update={
                "revision": 2,
                "status": MemoryStatus.TOMBSTONED,
                "updated_at": tombstoned_at,
                "sealed_content": changed_envelope,
            }
        ),
        forget_mode="hard",
    )
    values, canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=EventOperation.TOMBSTONED,
        payload=tombstone,
        payload_version=3,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        memory_id=memory_id,
        expected_revision=1,
        causation_event_id=event_id,
    )
    transition = MemoryEvent(
        schema_version=3,
        payload_version=3,
        sequence=2,
        event_id=new_uuid7(),
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=new_uuid7(),
        session_id=None,
        ingress_id=None,
        operation=EventOperation.TOMBSTONED,
        memory_id=memory_id,
        expected_revision=1,
        causation_event_id=event_id,
        correlation_id=new_uuid7(),
        idempotency_key="sealed-v3-tombstone",
        policy_version=3,
        normalization_version=1,
        payload=values,
        payload_canonical=canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=tombstoned_at,
    )

    with pytest.raises(FoldError, match="sealed_identity_changed"):
        fold_event(folded, transition)
