"""Internal, policy-pinned candidate promotion and expiry orchestration."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.commands import CandidateExpiryCommand, CandidatePromotionCommand
from kivra_memory.domain.enums import EventOperation, MemoryStatus, MemoryVisibility
from kivra_memory.domain.events import (
    BranchState,
    CandidateLifecyclePayload,
    MemoryEvent,
    MemoryStateV2,
    event_hash_fields,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    CandidateLifecycleState,
    ContentSignal,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    ExpiryEvaluation,
    LifecycleAction,
    SelectionBasis,
    evaluate_expiry,
    evaluate_promotion,
)
from kivra_memory.policy.loader import SELECTION_V1
from kivra_memory.storage.event_store import append_memory_event
from kivra_memory.storage.live_projection import (
    load_projection_state_for_update,
    stage_live_projection,
    validate_live_event,
)
from kivra_memory.storage.models import (
    Branch,
    Memory,
    MemoryEvidence,
    SelectionDecision,
    TransportBinding,
)
from kivra_memory.storage.outbox import enqueue_outbox_job
from kivra_memory.storage.projector import memory_row_to_state
from kivra_memory.storage.selection_history import append_selection_decision
from kivra_memory.storage.transactions import (
    SerializableTransactionError,
    run_serializable_transaction,
)


class CandidateLifecycleExecutionError(RuntimeError):
    """Safe, content-free lifecycle failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CandidateLifecycleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    operation: Literal["promote", "expire"]
    action: Literal["no_op", "promoted", "expired"]
    decision_id: UUID
    source_decision_id: UUID
    event_id: UUID | None = None
    memory_id: UUID
    revision: int
    policy_sha256: str
    reason_code: str


class _LifecycleIdentifiers:
    """Retry-stable identifiers and evaluation time for one lifecycle command."""

    def __init__(self, *, evaluated_at: datetime) -> None:
        self.decision_id = new_uuid7()
        self.event_id = new_uuid7()
        self.correlation_id = new_uuid7()
        self.job_ids = (new_uuid7(), new_uuid7())
        self.evaluated_at = evaluated_at


def _branch_state(row: Branch) -> BranchState:
    return BranchState(
        branch_id=row.branch_id,
        tenant_id=row.tenant_id,
        lineage_id=row.lineage_id,
        parent_branch_id=row.parent_branch_id,
        fork_event_sequence=row.fork_event_sequence,
        name=row.name,
        visibility_ceiling=MemoryVisibility(row.visibility_ceiling),
        created_at=row.created_at,
        sealed_at=row.sealed_at,
    )


def _evidence(row: MemoryEvidence) -> EvidenceSummary:
    kind = row.source_type
    return EvidenceSummary(
        evidence_key=str(row.source_reference.get("evidence_key", row.evidence_id)),
        kind=EvidenceKind(kind)
        if kind in {item.value for item in EvidenceKind}
        else EvidenceKind.ASSISTANT_OBSERVATION,
        trust=EvidenceTrust(row.trust_classification)
        if row.trust_classification in {item.value for item in EvidenceTrust}
        else EvidenceTrust.UNVERIFIED,
    )


def _signals(decision: SelectionDecision) -> frozenset[ContentSignal]:
    values = set(decision.matched_rule_ids)
    result: set[ContentSignal] = set()
    if any("roleplay" in str(value) for value in values):
        result.add(ContentSignal.ROLEPLAYED_SCENE)
    if any("sentience" in str(value) for value in values):
        result.add(ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM)
    return frozenset(result)


def _event(
    *,
    operation: EventOperation,
    principal: CommandPrincipal,
    branch_id: UUID,
    lineage_id: UUID,
    memory_id: UUID,
    expected_revision: int,
    payload: CandidateLifecyclePayload,
    event_id: UUID,
    correlation_id: UUID,
    idempotency_key: str,
    created_at: datetime,
    policy_rule_code: str,
) -> MemoryEvent:
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
    )
    del policy_rule_code
    return MemoryEvent(
        schema_version=2,
        payload_version=2,
        sequence=1,
        event_id=event_id,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        transport_binding_id=principal.transport_binding_id,
        session_id=None,
        ingress_id=None,
        operation=operation,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        policy_version=2,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


class CandidateLifecycleEngine:
    """Apply one internal lifecycle command under an exact candidate lock."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def promote(
        self,
        principal: CommandPrincipal,
        command: CandidatePromotionCommand,
        *,
        now: datetime | None = None,
    ) -> CandidateLifecycleResult:
        return await self._execute(principal, command, operation="promote", now=now)

    async def expire(
        self,
        principal: CommandPrincipal,
        command: CandidateExpiryCommand,
        *,
        now: datetime | None = None,
    ) -> CandidateLifecycleResult:
        return await self._execute(principal, command, operation="expire", now=now)

    async def _execute(
        self,
        principal: CommandPrincipal,
        command: CandidatePromotionCommand | CandidateExpiryCommand,
        *,
        operation: Literal["promote", "expire"],
        now: datetime | None,
    ) -> CandidateLifecycleResult:
        required = f"memory.lifecycle.{operation}"
        if required not in principal.scopes or principal.ingress_id is not None:
            raise CandidateLifecycleExecutionError("forbidden")
        identifiers = _LifecycleIdentifiers(evaluated_at=now or datetime.now(UTC))

        async def attempt(session: AsyncSession) -> CandidateLifecycleResult:
            return await self._attempt(
                session,
                principal,
                command,
                operation=operation,
                identifiers=identifiers,
            )

        try:
            return await run_serializable_transaction(
                self._session_factory, principal.tenant_id, attempt
            )
        except CandidateLifecycleExecutionError:
            raise
        except SerializableTransactionError as error:
            raise CandidateLifecycleExecutionError("serialization_exhausted") from error
        except SQLAlchemyError as error:
            raise CandidateLifecycleExecutionError("dependency_unavailable") from error

    async def _attempt(
        self,
        session: AsyncSession,
        principal: CommandPrincipal,
        command: CandidatePromotionCommand | CandidateExpiryCommand,
        *,
        operation: Literal["promote", "expire"],
        identifiers: _LifecycleIdentifiers,
    ) -> CandidateLifecycleResult:
        binding_kind = await session.scalar(
            select(TransportBinding.transport_kind).where(
                TransportBinding.tenant_id == principal.tenant_id,
                TransportBinding.transport_binding_id == principal.transport_binding_id,
                TransportBinding.actor_id == principal.actor_id,
                TransportBinding.client_id == principal.client_id,
            )
        )
        if binding_kind != "internal_service":
            raise CandidateLifecycleExecutionError("forbidden")
        memory = await session.scalar(
            select(Memory)
            .where(
                Memory.tenant_id == principal.tenant_id,
                Memory.memory_id == command.memory_id,
            )
            .with_for_update()
        )
        if memory is None:
            return self._noop(
                operation, command.memory_id, command.selection_decision_id, 0, "not_found"
            )
        if memory.revision != command.expected_revision:
            return self._noop(
                operation,
                memory.memory_id,
                command.selection_decision_id,
                memory.revision,
                "stale_revision",
            )
        if memory.status != MemoryStatus.CANDIDATE.value:
            return self._noop(
                operation,
                memory.memory_id,
                command.selection_decision_id,
                memory.revision,
                "not_candidate",
            )
        source = await session.scalar(
            select(SelectionDecision).where(
                SelectionDecision.tenant_id == principal.tenant_id,
                SelectionDecision.decision_id == command.selection_decision_id,
                SelectionDecision.memory_id == memory.memory_id,
                SelectionDecision.outcome == "candidate",
            )
        )
        if source is None:
            return self._noop(
                operation,
                memory.memory_id,
                command.selection_decision_id,
                memory.revision,
                "decision_missing",
            )
        evidence_rows = (
            await session.scalars(
                select(MemoryEvidence).where(
                    MemoryEvidence.tenant_id == principal.tenant_id,
                    MemoryEvidence.lineage_id == memory.lineage_id,
                    MemoryEvidence.memory_id == memory.memory_id,
                    MemoryEvidence.status == "active",
                )
            )
        ).all()
        current = MemoryStateV2.model_validate(
            memory_row_to_state(memory).model_dump(mode="python")
        )
        evidence = tuple(_evidence(row) for row in evidence_rows)
        lifecycle = CandidateLifecycleState(
            status=MemoryStatus.CANDIDATE,
            selection_basis=SelectionBasis(source.selection_basis),
            content_signals=_signals(source),
            evidence=evidence,
            policy_profile_version="selection-v1",
            policy_profile_sha256=bytes(source.policy_sha256).hex(),
        )
        now = identifiers.evaluated_at
        if operation == "promote":
            decision = evaluate_promotion(lifecycle)
            action = decision.action.value
            target_status = MemoryStatus.ACTIVE
            event_operation = EventOperation.CANDIDATE_PROMOTED
            result_action: Literal["no_op", "promoted", "expired"] = "promoted"
        else:
            if current.candidate_expires_at is None:
                return self._noop(
                    operation,
                    memory.memory_id,
                    command.selection_decision_id,
                    memory.revision,
                    "expiry_missing",
                )
            decision = evaluate_expiry(
                ExpiryEvaluation(
                    candidate=lifecycle, deadline=current.candidate_expires_at, evaluated_at=now
                )
            )
            action = decision.action.value
            target_status = MemoryStatus.RETIRED
            event_operation = EventOperation.CANDIDATE_EXPIRED
            result_action = "expired"
        if action != LifecycleAction.PROMOTE.value and action != LifecycleAction.RETIRE.value:
            return CandidateLifecycleResult(
                operation=operation,
                action="no_op",
                decision_id=source.decision_id,
                source_decision_id=source.decision_id,
                memory_id=memory.memory_id,
                revision=memory.revision,
                policy_sha256=decision.policy_profile_sha256,
                reason_code=decision.reason_code.value,
            )

        decision_id = identifiers.decision_id
        event_id = identifiers.event_id
        correlation_id = identifiers.correlation_id
        idempotency_key = (
            f"candidate-{operation}-{command.selection_decision_id}-{command.expected_revision}"
        )
        after = MemoryStateV2.model_validate(
            {
                **current.model_dump(mode="python"),
                "revision": current.revision + 1,
                "status": target_status,
                "updated_at": now,
                "candidate_expires_at": None,
            }
        )
        payload = CandidateLifecyclePayload(
            previous_revision=current.revision,
            memory=after,
            selection_decision_id=decision_id,
            policy_rule_code=decision.reason_code.value,
            evidence=(),
        )
        branch = await session.scalar(
            select(Branch).where(
                Branch.tenant_id == memory.tenant_id,
                Branch.lineage_id == memory.lineage_id,
                Branch.branch_id == memory.branch_id,
            )
        )
        if branch is None:
            raise CandidateLifecycleExecutionError("not_found")
        event = await append_memory_event(
            session,
            lambda sequence: _event(
                operation=event_operation,
                principal=principal,
                branch_id=memory.branch_id,
                lineage_id=memory.lineage_id,
                memory_id=memory.memory_id,
                expected_revision=current.revision,
                payload=payload,
                event_id=event_id,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
                created_at=now,
                policy_rule_code=command.policy_rule_code,
            ).model_copy(update={"sequence": sequence}),
        )
        before = await load_projection_state_for_update(
            session, event=event, branch=_branch_state(branch)
        )
        after_projection = validate_live_event(before, event)
        await stage_live_projection(session, before=before, after=after_projection, event=event)
        await append_selection_decision(
            session,
            lambda sequence: SelectionDecision(
                selection_sequence=sequence,
                decision_id=decision_id,
                tenant_id=principal.tenant_id,
                lineage_id=memory.lineage_id,
                branch_id=memory.branch_id,
                persona_id=source.persona_id,
                actor_id=principal.actor_id,
                client_id=principal.client_id,
                transport_binding_id=principal.transport_binding_id,
                policy_id="scalevault-memory-selection",
                policy_version=1,
                policy_sha256=bytes.fromhex(decision.policy_profile_sha256),
                policy_rule_code=decision.reason_code.value,
                input_sha256=hashlib.sha256(
                    canonical_json_bytes(command.model_dump(mode="json"))
                ).digest(),
                source_kind="candidate_reassessment"
                if operation == "promote"
                else "candidate_expiry",
                requested_operation=operation,
                outcome=result_action,
                reason_codes=[decision.reason_code.value],
                matched_rule_ids=[],
                selection_basis=source.selection_basis,
                scope=source.scope,
                visibility=source.visibility,
                sensitivity=source.sensitivity,
                subject_id=source.subject_id,
                subject_kind=source.subject_kind,
                memory_id=memory.memory_id,
                event_id=event.event_id,
            ),
        )
        await enqueue_outbox_job(
            session,
            tenant_id=principal.tenant_id,
            job_type="embed_memory",
            aggregate_type="memory",
            aggregate_id=memory.memory_id,
            references={
                "memory_id": memory.memory_id,
                "memory_version": after.revision,
                "event_id": event.event_id,
            },
            job_uuid=identifiers.job_ids[0],
        )
        await enqueue_outbox_job(
            session,
            tenant_id=principal.tenant_id,
            job_type="export_git_batch",
            aggregate_type="event",
            aggregate_id=event.event_id,
            references={"event_id": event.event_id, "event_sequence": event.sequence},
            job_uuid=identifiers.job_ids[1],
        )
        await session.flush()
        return CandidateLifecycleResult(
            operation=operation,
            action=result_action,
            decision_id=decision_id,
            source_decision_id=source.decision_id,
            event_id=event.event_id,
            memory_id=memory.memory_id,
            revision=after.revision,
            policy_sha256=decision.policy_profile_sha256,
            reason_code=decision.reason_code.value,
        )

    @staticmethod
    def _noop(
        operation: Literal["promote", "expire"],
        memory_id: UUID,
        source_decision_id: UUID,
        revision: int,
        reason_code: str,
    ) -> CandidateLifecycleResult:
        return CandidateLifecycleResult(
            operation=operation,
            action="no_op",
            decision_id=source_decision_id,
            source_decision_id=source_decision_id,
            memory_id=memory_id,
            revision=max(revision, 1),
            policy_sha256=SELECTION_V1.sha256_hex,
            reason_code=reason_code,
        )
