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
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Never

from pydantic import ValidationError
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.enums import EventOperation, TransportKind
from kivra_memory.domain.errors import DomainError
from kivra_memory.domain.events import (
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    EventContractError,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryTransitionPayload,
    validate_event_envelope_shape,
)
from kivra_memory.storage.models.events import (
    MemoryEvent as MemoryEventRow,
)
from kivra_memory.storage.models.events import MemoryEventCounter
from kivra_memory.storage.models.identity import (
    Actor,
    Client,
    TransportBinding,
    TransportInstallation,
)

EventBuilder = Callable[[int], MemoryEvent]


class EventStoreError(DomainError):
    """A safe, machine-identifiable event insertion failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


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


def _after_image_sensitivities(event: MemoryEvent) -> tuple[int, ...]:
    payload = event.typed_payload()
    if isinstance(payload, (MemoryCreatedPayload, MemoryTransitionPayload)):
        return (payload.memory.sensitivity,)
    if isinstance(payload, (ConflictOpenedPayload, ConflictResolvedPayload)):
        return tuple(item.memory.sensitivity for item in payload.affected_memories)
    return ()


def _validate_transport(binding: TransportBinding, event: MemoryEvent) -> None:
    if not _operation_is_authorized(binding, event.operation):
        _reject("operation_not_authorized", "transport binding does not authorize the operation")

    if binding.transport_kind == TransportKind.GITHUB_INGRESS.value:
        if event.operation not in {EventOperation.OBSERVED, EventOperation.REMEMBERED}:
            _reject("github_operation_forbidden", "GitHub ingress operation is not permitted")
        if event.ingress_id is None:
            _reject("github_ingress_required", "GitHub ingress event requires ingress provenance")
    elif event.ingress_id is not None:
        _reject("ingress_forbidden", "non-GitHub event cannot contain ingress provenance")

    if binding.transport_kind == TransportKind.RELAY.value and 4 in _after_image_sensitivities(
        event
    ):
        _reject("relay_sensitivity_forbidden", "relay cannot carry sensitivity-four after-images")


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


async def _append_memory_event(session: AsyncSession, builder: EventBuilder) -> MemoryEvent:
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

    _validate_transport(binding, event)

    row = _event_row(event)
    session.add(row)
    counter.next_sequence += 1
    await session.flush()
    return event


async def append_memory_event(session: AsyncSession, builder: EventBuilder) -> MemoryEvent:
    """Allocate, authorize, validate, and stage one immutable event atomically.

    The singleton counter is locked before calling ``builder``. The counter is
    changed only after all deterministic validation succeeds, and the event row
    and updated counter are flushed together. Any later transaction rollback
    therefore restores both.
    """

    try:
        return await _append_memory_event(session, builder)
    except EventStoreError:
        raise
    except SQLAlchemyError:
        raise EventStoreError("event_store_unavailable", "event store operation failed") from None
