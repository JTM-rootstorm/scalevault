"""Atomic, policy-aware persistence for immutable memory events.

Transport bindings use one deliberately small authorization document::

    {"operations": ["observed", "remembered"]}

The list contains exact :class:`~kivra_memory.domain.enums.EventOperation`
values. Missing keys, non-list values, and non-string entries fail closed.
Callers own the surrounding ``AsyncSession`` transaction; this module neither
commits nor rolls it back.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Never

from pydantic import ValidationError
from sqlalchemy import and_, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.constraints import MemoryConstraintContext, validate_memory_constraints
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryStatus,
    MemoryVisibility,
    TransportKind,
)
from kivra_memory.domain.errors import DomainConstraintError, DomainError
from kivra_memory.domain.events import (
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    EventContractError,
    MemoryCreatedPayload,
    MemoryCreatedPayloadV2,
    MemoryEvent,
    MemoryState,
    MemoryStateV3,
    MemoryTransitionPayload,
    validate_event_envelope_shape,
)
from kivra_memory.storage.models.events import (
    IngressItem,
    MemoryEventCounter,
)
from kivra_memory.storage.models.events import (
    MemoryEvent as MemoryEventRow,
)
from kivra_memory.storage.models.identity import (
    Actor,
    Client,
    TransportBinding,
    TransportInstallation,
)
from kivra_memory.storage.transactions import database_sqlstate

EventBuilder = Callable[[int], MemoryEvent]


class EventStoreError(DomainError):
    """A safe, machine-identifiable event insertion failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


class LegacyGenesisPlaintextAuthorization(Enum):
    """Explicit non-persisted capability for the frozen ADR0014 import only."""

    ADR0014_FIRST_IMPORT = "adr0014_first_import"


def _reject(code: str, message: str) -> Never:
    raise EventStoreError(code, message)


def _build_and_validate(builder: EventBuilder, sequence: int) -> MemoryEvent:
    try:
        event = builder(sequence)
    except Exception:
        raise EventStoreError("event_invalid", "event construction failed validation") from None

    if not isinstance(event, MemoryEvent):
        _reject("event_invalid", "event builder returned an unsupported value")
    if event.sequence != sequence:
        _reject("event_sequence_mismatch", "event sequence does not match the allocation")

    try:
        validate_event_envelope_shape(event)
        event.typed_payload()
        event.verify_hashes()
    except (EventContractError, ValidationError, ValueError, TypeError):
        raise EventStoreError(
            "event_invalid", "event failed canonical contract validation"
        ) from None
    return event


def _operation_is_authorized(binding: TransportBinding, operation: EventOperation) -> bool:
    policy = binding.authorized_operations
    if set(policy) != {"operations"}:
        return False
    operations = policy.get("operations")
    return (
        isinstance(operations, list)
        and all(isinstance(value, str) for value in operations)
        and operation.value in operations
    )


def _after_images(event: MemoryEvent) -> tuple[MemoryState, ...]:
    payload = event.typed_payload()
    if isinstance(payload, (MemoryCreatedPayload, MemoryTransitionPayload)):
        return (payload.memory,)
    if isinstance(payload, (ConflictOpenedPayload, ConflictResolvedPayload)):
        return tuple(item.memory for item in payload.affected_memories)
    return ()


def _is_authorized_legacy_genesis_plaintext(
    binding: TransportBinding,
    event: MemoryEvent,
    memory: MemoryState,
) -> bool:
    """Recognize only the frozen ADR0014 v2 imported-candidate shape."""

    payload = event.typed_payload()
    return bool(
        binding.transport_kind == TransportKind.INTERNAL_SERVICE.value
        and event.schema_version == 2
        and event.payload_version == 2
        and event.policy_version == 2
        and event.normalization_version == 1
        and event.operation is EventOperation.OBSERVED
        and event.session_id is None
        and event.ingress_id is None
        and re.fullmatch(r"genesis-import-v1:[0-9a-f]{64}", event.idempotency_key)
        and isinstance(payload, MemoryCreatedPayloadV2)
        and payload.memory == memory
        and memory.status is MemoryStatus.CANDIDATE
        and memory.visibility is MemoryVisibility.PRIVATE_ROOT
        and memory.authority_class is AuthorityClass.IMPORTED_LEGACY_MEMORY
        and memory.content_protection == "plaintext"
        and bool(payload.evidence)
        and all(
            item.source_type == "import_manifest"
            and item.trust_classification == "trusted"
            and item.excerpt is None
            and item.content_sha256 is None
            and set(item.source_reference) == {"evidence_key"}
            and isinstance(item.source_reference["evidence_key"], str)
            and item.source_reference["evidence_key"].startswith("import-manifest:")
            and item.metadata == {}
            for item in payload.evidence
        )
    )


def _validate_after_image_constraints(
    binding: TransportBinding,
    event: MemoryEvent,
    *,
    legacy_genesis_plaintext_authorization: LegacyGenesisPlaintextAuthorization | None = None,
) -> None:
    try:
        transport_kind = TransportKind(binding.transport_kind)
    except ValueError:
        raise EventStoreError("binding_invalid", "transport binding is unavailable") from None

    for memory in _after_images(event):
        # Subject anchors and branch ceilings require projection lookups outside this
        # repository. Supplying their already-FK-protected shape here lets the shared
        # validator enforce every after-image and transport rule decidable from the
        # immutable event itself without inventing content-bearing diagnostics.
        context = MemoryConstraintContext(
            category=memory.category,
            ontological_status=memory.ontological_status,
            scope=memory.scope,
            visibility=memory.visibility,
            status=memory.status,
            sensitivity=memory.sensitivity,
            subject_kind=memory.subject_kind,
            origin_session_id=memory.origin_session_id,
            origin_session_matches=memory.origin_session_id is not None,
            structural_anchor_matches=True,
            imported_provenance=(memory.authority_class is AuthorityClass.IMPORTED_LEGACY_MEMORY),
            publication_approved=(
                memory.publication_approved_at is not None
                and memory.publication_approved_by_actor_id is not None
            ),
            branch_allows_visibility=True,
            transport_kind=transport_kind,
        )
        try:
            validate_memory_constraints(context)
        except DomainConstraintError as error:
            raise EventStoreError(
                error.code, "memory after-image violates accepted constraints"
            ) from None
        if (
            memory.sensitivity == 4
            and not isinstance(memory, MemoryStateV3)
            and not (
                legacy_genesis_plaintext_authorization
                is LegacyGenesisPlaintextAuthorization.ADR0014_FIRST_IMPORT
                and _is_authorized_legacy_genesis_plaintext(binding, event, memory)
            )
        ):
            _reject("sealed_content_required", "sensitivity-four writes require sealed content")


def _validate_transport(
    binding: TransportBinding,
    event: MemoryEvent,
    *,
    legacy_genesis_plaintext_authorization: LegacyGenesisPlaintextAuthorization | None = None,
) -> None:
    if not _operation_is_authorized(binding, event.operation):
        _reject("operation_not_authorized", "transport binding does not authorize the operation")

    if binding.transport_kind == TransportKind.GITHUB_INGRESS.value:
        if event.operation not in {EventOperation.OBSERVED, EventOperation.REMEMBERED}:
            _reject("github_operation_forbidden", "GitHub ingress operation is not permitted")
        if event.ingress_id is None:
            _reject("github_ingress_required", "GitHub ingress event requires ingress provenance")
        if any(isinstance(memory, MemoryStateV3) for memory in _after_images(event)):
            _reject("github_sealed_content_forbidden", "GitHub ingress cannot write sealed content")
    elif event.ingress_id is not None:
        _reject("ingress_forbidden", "non-GitHub event cannot contain ingress provenance")

    _validate_after_image_constraints(
        binding,
        event,
        legacy_genesis_plaintext_authorization=legacy_genesis_plaintext_authorization,
    )


def _reject_ingress() -> Never:
    _reject("github_ingress_unavailable", "GitHub ingress item is unavailable")


def _validate_ingress_item(
    ingress: IngressItem,
    binding: TransportBinding,
    event: MemoryEvent,
) -> None:
    if (
        ingress.state != "validated"
        or ingress.validated_at is None
        or ingress.result_event_id is not None
        or ingress.result_memory_id is not None
        or ingress.error_code is not None
        or ingress.safe_diagnostic is not None
        or ingress.processed_at is not None
    ):
        _reject_ingress()

    if (
        ingress.ingress_id != event.ingress_id
        or ingress.tenant_id != event.tenant_id
        or ingress.transport_binding_id != event.transport_binding_id
        or ingress.installation_id != binding.installation_id
        or ingress.actor_id != event.actor_id
        or ingress.client_id != event.client_id
        or ingress.provider != "github"
        or ingress.declared_idempotency_key != event.idempotency_key
    ):
        _reject_ingress()


async def _lock_github_ingress(
    session: AsyncSession,
    binding: TransportBinding,
    event: MemoryEvent,
) -> IngressItem | None:
    if binding.transport_kind != TransportKind.GITHUB_INGRESS.value:
        return None

    ingress_result = await session.execute(
        select(IngressItem)
        .where(
            IngressItem.tenant_id == event.tenant_id,
            IngressItem.ingress_id == event.ingress_id,
        )
        .with_for_update()
    )
    ingress = ingress_result.scalar_one_or_none()
    if ingress is None:
        _reject_ingress()
    _validate_ingress_item(ingress, binding, event)
    return ingress


def _event_row(event: MemoryEvent) -> MemoryEventRow:
    return MemoryEventRow(
        sequence=event.sequence,
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        lineage_id=event.lineage_id,
        branch_id=event.branch_id,
        actor_id=event.actor_id,
        client_id=event.client_id,
        transport_binding_id=event.transport_binding_id,
        session_id=event.session_id,
        ingress_id=event.ingress_id,
        operation=event.operation.value,
        memory_id=event.memory_id,
        expected_revision=event.expected_revision,
        causation_event_id=event.causation_event_id,
        correlation_id=event.correlation_id,
        idempotency_key=event.idempotency_key,
        schema_version=event.schema_version,
        payload_version=event.payload_version,
        policy_version=event.policy_version,
        normalization_version=event.normalization_version,
        payload=dict(event.payload),
        payload_canonical=base64.b64decode(event.payload_canonical, validate=True),
        payload_sha256=bytes.fromhex(event.payload_sha256),
        command_sha256=bytes.fromhex(event.command_sha256),
        created_at=event.created_at,
    )


async def _append_memory_event(
    session: AsyncSession,
    builder: EventBuilder,
    *,
    legacy_genesis_plaintext_authorization: LegacyGenesisPlaintextAuthorization | None = None,
) -> MemoryEvent:
    """Perform event insertion inside the caller-owned transaction."""

    counter_result = await session.execute(
        select(MemoryEventCounter).where(MemoryEventCounter.counter_id == 1).with_for_update()
    )
    counter = counter_result.scalar_one_or_none()
    if counter is None:
        _reject("event_counter_unavailable", "event sequence allocator is unavailable")

    event = _build_and_validate(builder, counter.next_sequence)

    binding_result = await session.execute(
        select(
            TransportBinding,
            Actor.revoked_at,
            Client.revoked_at,
            TransportInstallation.installation_id,
            TransportInstallation.revoked_at,
        )
        .join(
            Actor,
            and_(
                Actor.tenant_id == TransportBinding.tenant_id,
                Actor.actor_id == TransportBinding.actor_id,
            ),
        )
        .join(
            Client,
            and_(
                Client.tenant_id == TransportBinding.tenant_id,
                Client.client_id == TransportBinding.client_id,
                Client.transport_kind == TransportBinding.transport_kind,
            ),
        )
        .outerjoin(
            TransportInstallation,
            and_(
                TransportInstallation.tenant_id == TransportBinding.tenant_id,
                TransportInstallation.installation_id == TransportBinding.installation_id,
            ),
        )
        .where(
            TransportBinding.tenant_id == event.tenant_id,
            TransportBinding.transport_binding_id == event.transport_binding_id,
            TransportBinding.actor_id == event.actor_id,
            TransportBinding.client_id == event.client_id,
        )
    )
    binding_identity = binding_result.one_or_none()
    if binding_identity is None:
        _reject("binding_not_found", "transport binding is unavailable")

    (
        binding,
        actor_revoked_at,
        client_revoked_at,
        installation_id,
        installation_revoked_at,
    ) = binding_identity
    if actor_revoked_at is not None or client_revoked_at is not None:
        _reject("binding_revoked", "transport binding is unavailable")

    now = datetime.now(UTC)
    if binding.valid_until is not None and binding.valid_until <= now:
        _reject("binding_expired", "transport binding is unavailable")

    if binding.installation_id is not None:
        if installation_id is None:
            _reject("binding_installation_unavailable", "transport binding is unavailable")
        if installation_revoked_at is not None:
            _reject("binding_revoked", "transport binding is unavailable")
    elif binding.transport_kind == TransportKind.RELAY.value:
        _reject("binding_installation_unavailable", "transport binding is unavailable")

    _validate_transport(
        binding,
        event,
        legacy_genesis_plaintext_authorization=legacy_genesis_plaintext_authorization,
    )
    ingress = await _lock_github_ingress(session, binding, event)

    row = _event_row(event)
    session.add(row)
    counter.next_sequence += 1
    await session.flush()
    if ingress is not None:
        ingress.state = "accepted"
        ingress.result_event_id = event.event_id
        ingress.result_memory_id = event.memory_id
        ingress.processed_at = now
        await session.flush()
    return event


async def append_memory_event(
    session: AsyncSession,
    builder: EventBuilder,
    *,
    legacy_genesis_plaintext_authorization: LegacyGenesisPlaintextAuthorization | None = None,
) -> MemoryEvent:
    """Allocate, authorize, validate, and stage one immutable event atomically.

    The singleton counter is locked before calling ``builder``. The counter is
    changed only after all deterministic validation succeeds, and the event row
    and updated counter are flushed together. Any later transaction rollback
    therefore restores both.
    """

    try:
        return await _append_memory_event(
            session,
            builder,
            legacy_genesis_plaintext_authorization=legacy_genesis_plaintext_authorization,
        )
    except EventStoreError:
        raise
    except SQLAlchemyError as error:
        if isinstance(error, DBAPIError) and database_sqlstate(error) == "40001":
            raise
        raise EventStoreError("event_store_unavailable", "event store operation failed") from None
