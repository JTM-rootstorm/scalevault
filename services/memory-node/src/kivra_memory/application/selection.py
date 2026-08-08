"""Transport-neutral orchestration for policy-gated memory nominations.

The policy package consumes only structured, trusted facts.  This module is the
boundary that resolves those facts, binds them to authenticated identity, and
persists the resulting decision and (when applicable) canonical memory event in
one transaction.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
)
from kivra_memory.domain.events import (
    BranchState,
    CandidateLifecyclePayload,
    EvidenceState,
    MemoryCreatedPayloadV2,
    MemoryEvent,
    MemoryStateV2,
    event_hash_fields,
)
from kivra_memory.domain.fingerprints import exact_memory_fingerprint
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.policy import (
    CandidateLifecycleState,
    ContentSignal,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    LifecycleAction,
    NominationProposal,
    PolicyDecision,
    PolicyOutcome,
    SelectionBasis,
    SelectionRequest,
    content_signals_from_rule_ids,
    evaluate_promotion,
    evaluate_selection,
)
from kivra_memory.storage.event_store import EventStoreError, append_memory_event
from kivra_memory.storage.live_projection import (
    load_projection_state_for_update,
    stage_live_projection,
    validate_live_event,
)
from kivra_memory.storage.locks import (
    acquire_advisory_xact_locks,
    advisory_lock_key,
    idempotency_advisory_lock_key,
)
from kivra_memory.storage.models import (
    Branch,
    CommandReceipt,
    Lineage,
    LogicalSession,
    Memory,
    MemoryEvidence,
    Persona,
    SelectionDecision,
    Subject,
    TransportBinding,
)
from kivra_memory.storage.outbox import OutboxReferenceValue, enqueue_outbox_job
from kivra_memory.storage.projector import ProjectionPersistenceError, memory_row_to_state
from kivra_memory.storage.selection_history import (
    SelectionHistoryError,
    append_selection_decision,
)
from kivra_memory.storage.transactions import (
    SerializableTransactionError,
    run_serializable_transaction,
)


class SelectionExecutionError(RuntimeError):
    """Safe, content-free nomination failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NominationCommandLike(Protocol):
    """Structural form shared by the MCP and private-seed nomination DTOs."""

    idempotency_key: str
    persona_id: UUID
    branch_id: UUID
    reason: str
    proposal: NominationProposal
    logical_session_id: UUID | None


class ResolvedNominationContext(BaseModel):
    """Trusted, payload-free facts supplied by an authenticated resolver."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_kind: Literal[
        "live_interaction",
        "reviewed_seed",
        "github_proposal",
        "candidate_reassessment",
        "candidate_expiry",
    ]
    effective_authority_class: AuthorityClass
    content_signals: frozenset[ContentSignal] = frozenset()
    evidence: tuple[EvidenceSummary, ...] = ()

    @field_validator("evidence")
    @classmethod
    def validate_evidence_keys(
        cls, value: tuple[EvidenceSummary, ...]
    ) -> tuple[EvidenceSummary, ...]:
        keys = tuple(item.evidence_key for item in value)
        if len(keys) != len(set(keys)):
            raise ValueError("resolved evidence keys must be unique")
        return value


class NominationResolver(Protocol):
    async def resolve(
        self, principal: CommandPrincipal, command: NominationCommandLike, /
    ) -> ResolvedNominationContext: ...


class PromotionPrincipalProvider(Protocol):
    """Resolve the server-owned identity used for lifecycle promotion events."""

    async def resolve(
        self,
        nominator: CommandPrincipal,
        command: NominationCommandLike,
        memory_id: UUID,
        /,
    ) -> CommandPrincipal: ...


class SelectionResult(BaseModel):
    """Content-free successful nomination receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    contract_version: Literal["mcp-mutation-v2"] = "mcp-mutation-v2"
    operation: Literal["nominate"] = "nominate"
    receipt_id: UUID
    decision_id: UUID
    outcome: Literal["omit", "reject", "candidate", "active", "promoted"]
    policy_version: Literal["selection-v1"] = "selection-v1"
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_codes: tuple[str, ...] = Field(max_length=8)
    matched_rule_ids: tuple[str, ...] = Field(max_length=16)
    event_id: UUID | None
    memory_id: UUID | None
    revision: int | None = Field(default=None, ge=1, le=(1 << 53) - 1)
    idempotent_replay: bool = False
    warnings: tuple[str, ...] = Field(default=(), max_length=16)

    @field_validator("receipt_id", "decision_id", "event_id", "memory_id")
    @classmethod
    def validate_ids(cls, value: UUID | None) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name="nomination_identifier")
        return value

    @field_validator("reason_codes", "warnings")
    @classmethod
    def validate_safe_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for code in value:
            if re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) is None:
                raise ValueError("nomination codes are bounded")
        if len(value) != len(set(value)):
            raise ValueError("nomination codes must be unique")
        return value

    @field_validator("matched_rule_ids")
    @classmethod
    def validate_rule_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for rule_id in value:
            if re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", rule_id) is None:
                raise ValueError("nomination rule identifiers are bounded")
        if len(value) != len(set(value)):
            raise ValueError("nomination rule identifiers must be unique")
        return value

    @model_validator(mode="after")
    def validate_result_shape(self) -> SelectionResult:
        linked = (self.event_id is not None, self.memory_id is not None, self.revision is not None)
        if self.outcome in {"omit", "reject"} and any(linked):
            raise ValueError("omit and reject receipts cannot identify an event")
        if self.outcome in {"candidate", "active", "promoted"} and not all(linked):
            raise ValueError("durable nomination receipts require event, memory, and revision")
        if (self.memory_id is None) != (self.revision is None):
            raise ValueError("memory identifier and revision must be supplied together")
        return self


class _NominationIdentifiers:
    def __init__(self, *, evidence_count: int) -> None:
        self.receipt_id = new_uuid7()
        self.decision_id = new_uuid7()
        self.event_id = new_uuid7()
        self.memory_id = new_uuid7()
        self.correlation_id = new_uuid7()
        self.evidence_ids = tuple(new_uuid7() for _ in range(evidence_count))
        self.job_ids = tuple(new_uuid7() for _ in range(4))
        self.created_at = datetime.now(UTC)


def _selection_request(
    proposal: NominationProposal,
    resolved: ResolvedNominationContext,
) -> SelectionRequest:
    return SelectionRequest(
        basis=proposal.selection_basis,
        category=proposal.category,
        ontological_status=proposal.ontological_status,
        scope=proposal.scope,
        visibility=proposal.visibility,
        effective_authority_class=resolved.effective_authority_class,
        content_signals=resolved.content_signals,
        epistemic_qualifiers=frozenset(proposal.epistemic_qualifiers),
        reason_to_remember=proposal.reason_to_remember,
        interpretation_limits=proposal.interpretation_limits,
        evidence=resolved.evidence,
    )


def _command_material(
    principal: CommandPrincipal,
    command: NominationCommandLike,
) -> dict[str, object]:
    """Return only authenticated wire-command material for idempotent replay."""

    return {
        "tenant_id": str(principal.tenant_id),
        "actor_id": str(principal.actor_id),
        "client_id": str(principal.client_id),
        "idempotency_key": command.idempotency_key,
        "persona_id": str(command.persona_id),
        "branch_id": str(command.branch_id),
        "reason": command.reason,
        "proposal": command.proposal.model_dump(mode="json"),
        "logical_session_id": (
            str(command.logical_session_id) if command.logical_session_id is not None else None
        ),
    }


def _command_digest(principal: CommandPrincipal, command: NominationCommandLike) -> bytes:
    """Hash the stable command independently of resolver-owned trusted facts."""

    return hashlib.sha256(canonical_json_bytes(_command_material(principal, command))).digest()


def _input_digest(
    principal: CommandPrincipal,
    command: NominationCommandLike,
    resolved: ResolvedNominationContext,
) -> bytes:
    """Hash the full policy input, including ordered resolver-owned facts."""

    resolved_material: dict[str, object] = {
        "source_kind": resolved.source_kind,
        "effective_authority_class": resolved.effective_authority_class.value,
        "content_signals": sorted(signal.value for signal in resolved.content_signals),
        "evidence": [
            {
                "evidence_key": item.evidence_key,
                "kind": item.kind.value,
                "trust": item.trust.value,
            }
            for item in sorted(resolved.evidence, key=lambda item: item.evidence_key)
        ],
    }
    material = {**_command_material(principal, command), "resolved": resolved_material}
    return hashlib.sha256(canonical_json_bytes(material)).digest()


def _policy_rule_code(decision: PolicyDecision, fallback: str = "already_covered") -> str:
    if decision.matched_rule_ids:
        candidate = decision.matched_rule_ids[0].replace(".", "_")
        if candidate and candidate[0].isalpha():
            return candidate[:64]
    return fallback


def _replay_from_receipt(
    receipt: CommandReceipt,
    *,
    command_digest: bytes,
) -> SelectionResult:
    """Verify all immutable receipt representations before returning a replay."""

    canonical = bytes(receipt.result_canonical)
    result_sha256 = bytes(receipt.result_sha256)
    if (
        bytes(receipt.command_sha256) != command_digest
        or hashlib.sha256(canonical).digest() != result_sha256
    ):
        code = (
            "idempotency_key_reused"
            if bytes(receipt.command_sha256) != command_digest
            else "dependency_unavailable"
        )
        raise SelectionExecutionError(code)
    try:
        if canonical_json_bytes(receipt.result) != canonical:
            raise ValueError("receipt representations differ")
        replay = SelectionResult.model_validate_json(canonical, strict=False)
        if canonical_json_bytes(replay.model_dump(mode="json")) != canonical:
            raise ValueError("receipt is not canonical")
    except (ValidationError, ValueError, TypeError):
        raise SelectionExecutionError("dependency_unavailable") from None
    if (
        replay.idempotent_replay
        or replay.receipt_id != receipt.receipt_id
        or replay.decision_id != receipt.selection_decision_id
        or replay.event_id != receipt.event_id
        or replay.memory_id != receipt.memory_id
        or replay.revision != receipt.memory_revision
    ):
        raise SelectionExecutionError("dependency_unavailable")
    return replay.model_copy(update={"idempotent_replay": True})


def _validate_unsealed_identity(
    *,
    persona_retired_at: datetime | None,
    lineage_sealed_at: datetime | None,
    branch_sealed_at: datetime | None,
) -> None:
    """Fail closed when any mutable identity container is no longer writable."""

    if (
        persona_retired_at is not None
        or lineage_sealed_at is not None
        or branch_sealed_at is not None
    ):
        raise SelectionExecutionError("forbidden")


def _validate_session_scope_anchors(
    command: NominationCommandLike,
    *,
    subject_origin_session_id: UUID | None,
) -> None:
    """Bind scene-local and episodic nominations to one authenticated session."""

    proposal = command.proposal
    if proposal.scope in {MemoryScope.SCENE_LOCAL, MemoryScope.EPISODIC} and (
        command.logical_session_id is None
        or proposal.origin_session_id != command.logical_session_id
        or subject_origin_session_id != command.logical_session_id
    ):
        raise SelectionExecutionError("forbidden")


def _evidence_state(
    *,
    summary: EvidenceSummary,
    evidence_id: UUID,
    tenant_id: UUID,
    lineage_id: UUID,
    branch_id: UUID,
    memory_id: UUID,
    created_at: datetime,
) -> EvidenceState:
    return EvidenceState(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        memory_id=memory_id,
        source_type=summary.kind.value,
        source_reference={"evidence_key": summary.evidence_key},
        trust_classification=summary.trust.value,
        created_at=created_at,
        metadata={},
    )


def _stored_evidence_summary(row: MemoryEvidence) -> EvidenceSummary:
    """Convert persisted, payload-free evidence back into policy facts."""

    kind = row.source_type
    trust = row.trust_classification
    return EvidenceSummary(
        evidence_key=str(row.source_reference.get("evidence_key", row.evidence_id)),
        kind=EvidenceKind(kind)
        if kind in {item.value for item in EvidenceKind}
        else EvidenceKind.ASSISTANT_OBSERVATION,
        trust=EvidenceTrust(trust)
        if trust in {item.value for item in EvidenceTrust}
        else EvidenceTrust.UNVERIFIED,
    )


def _new_candidate_evidence(
    stored: tuple[EvidenceSummary, ...], resolved: tuple[EvidenceSummary, ...]
) -> tuple[EvidenceSummary, ...]:
    """Keep duplicate nominations from reusing the same evidence key."""

    stored_keys = {item.evidence_key for item in stored}
    return tuple(item for item in resolved if item.evidence_key not in stored_keys)


def _event(
    *,
    operation: EventOperation,
    principal: CommandPrincipal,
    command: NominationCommandLike,
    lineage_id: UUID,
    payload: MemoryCreatedPayloadV2 | CandidateLifecyclePayload,
    event_id: UUID,
    correlation_id: UUID,
    created_at: datetime,
    memory_id: UUID,
    expected_revision: int | None,
    policy_input_digest: bytes,
    idempotency_key: str | None = None,
    internal_lifecycle: bool = False,
) -> MemoryEvent:
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=command.branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
    )
    del policy_input_digest
    return MemoryEvent(
        schema_version=2,
        payload_version=2,
        sequence=1,
        event_id=event_id,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=command.branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        transport_binding_id=principal.transport_binding_id,
        session_id=None if internal_lifecycle else command.logical_session_id,
        ingress_id=None if internal_lifecycle else principal.ingress_id,
        operation=operation,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key or command.idempotency_key,
        policy_version=2,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


class SelectionEngine:
    """Evaluate and atomically persist one authenticated nomination."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        resolver: NominationResolver
        | Callable[
            [CommandPrincipal, NominationCommandLike],
            Awaitable[ResolvedNominationContext],
        ],
        promotion_principal_provider: PromotionPrincipalProvider
        | Callable[[CommandPrincipal, NominationCommandLike, UUID], Awaitable[CommandPrincipal]]
        | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._resolver = resolver
        self._promotion_principal_provider = promotion_principal_provider

    async def execute(
        self, principal: CommandPrincipal, command: NominationCommandLike
    ) -> SelectionResult:
        if not self._authorized(principal):
            raise SelectionExecutionError("forbidden")
        try:
            command_digest = _command_digest(principal, command)

            async def preflight(session: AsyncSession) -> SelectionResult | None:
                receipt = await self._load_receipt(session, principal=principal, command=command)
                return (
                    _replay_from_receipt(receipt, command_digest=command_digest)
                    if receipt is not None
                    else None
                )

            replay = await run_serializable_transaction(
                self._session_factory, principal.tenant_id, preflight
            )
            if replay is not None:
                return replay

            resolved = await self._resolve(principal, command)
            request = _selection_request(command.proposal, resolved)
            decision = evaluate_selection(request)
            identifiers = _NominationIdentifiers(evidence_count=len(resolved.evidence))
            input_digest = _input_digest(principal, command, resolved)

            async def attempt(session: AsyncSession) -> SelectionResult:
                return await self._attempt(
                    session,
                    principal=principal,
                    command=command,
                    resolved=resolved,
                    policy_decision=decision,
                    command_digest=command_digest,
                    input_digest=input_digest,
                    identifiers=identifiers,
                )

            return await run_serializable_transaction(
                self._session_factory, principal.tenant_id, attempt
            )
        except SelectionExecutionError:
            raise
        except SerializableTransactionError as error:
            raise SelectionExecutionError("serialization_exhausted") from error
        except (EventStoreError, ProjectionPersistenceError, SelectionHistoryError):
            raise SelectionExecutionError("dependency_unavailable") from None
        except SQLAlchemyError:
            raise SelectionExecutionError("dependency_unavailable") from None
        except (ValidationError, ValueError, TypeError, AttributeError):
            raise SelectionExecutionError("invalid_input") from None

    @staticmethod
    async def _load_receipt(
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
    ) -> CommandReceipt | None:
        return cast(
            CommandReceipt | None,
            await session.scalar(
                select(CommandReceipt).where(
                    CommandReceipt.tenant_id == principal.tenant_id,
                    CommandReceipt.client_id == principal.client_id,
                    CommandReceipt.idempotency_key == command.idempotency_key,
                )
            ),
        )

    async def _resolve(
        self, principal: CommandPrincipal, command: NominationCommandLike
    ) -> ResolvedNominationContext:
        try:
            resolver = self._resolver
            if hasattr(resolver, "resolve"):
                resolved = await resolver.resolve(principal, command)
            else:
                resolved = await resolver(principal, command)
        except Exception:
            raise SelectionExecutionError("authority_unavailable") from None
        if not isinstance(resolved, ResolvedNominationContext):
            raise SelectionExecutionError("authority_unavailable")
        return resolved

    async def _promotion_principal(
        self,
        session: AsyncSession,
        *,
        nominator: CommandPrincipal,
        command: NominationCommandLike,
        memory_id: UUID,
    ) -> CommandPrincipal:
        """Resolve and verify the separate internal lifecycle authority.

        A nomination actor is intentionally never reused as the actor of a
        promotion event.  The provider is server-owned and its returned
        principal is pinned to an active internal-service binding in the same
        transaction so a resolver failure rolls the nomination back.
        """

        provider = self._promotion_principal_provider
        if provider is None:
            raise SelectionExecutionError("authority_unavailable")
        try:
            if hasattr(provider, "resolve"):
                principal = await provider.resolve(nominator, command, memory_id)
            else:
                principal = await provider(nominator, command, memory_id)
        except Exception:
            raise SelectionExecutionError("authority_unavailable") from None
        if (
            not isinstance(principal, CommandPrincipal)
            or principal.tenant_id != nominator.tenant_id
            or principal.ingress_id is not None
            or principal.scopes != frozenset({"memory.lifecycle.promote"})
        ):
            raise SelectionExecutionError("authority_unavailable")
        binding_kind = await session.scalar(
            select(TransportBinding.transport_kind).where(
                TransportBinding.tenant_id == principal.tenant_id,
                TransportBinding.transport_binding_id == principal.transport_binding_id,
                TransportBinding.actor_id == principal.actor_id,
                TransportBinding.client_id == principal.client_id,
            )
        )
        if binding_kind != "internal_service":
            raise SelectionExecutionError("authority_unavailable")
        return principal

    @staticmethod
    def _authorized(principal: CommandPrincipal) -> bool:
        return bool(
            {"memory.write.nominate", "memory:write"} & principal.scopes
            or ("memory:propose" in principal.scopes and principal.ingress_id is not None)
        )

    @staticmethod
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

    async def _attempt(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        resolved: ResolvedNominationContext,
        policy_decision: PolicyDecision,
        command_digest: bytes,
        input_digest: bytes,
        identifiers: _NominationIdentifiers,
    ) -> SelectionResult:
        # A committed receipt is terminal even if the mutable persona, lineage,
        # branch, subject, or resolver state later changes. Serialize this check
        # before consulting any of those resources, then keep the lock through
        # the mutation transaction to close the preflight race.
        await acquire_advisory_xact_locks(
            session,
            (
                idempotency_advisory_lock_key(
                    tenant_id=principal.tenant_id,
                    client_id=principal.client_id,
                    idempotency_key=command.idempotency_key,
                ),
            ),
        )
        receipt = await self._load_receipt(session, principal=principal, command=command)
        if receipt is not None:
            return _replay_from_receipt(receipt, command_digest=command_digest)

        identity = (
            await session.execute(
                select(Lineage.lineage_id, Lineage.sealed_at, Persona.retired_at, Branch)
                .join(
                    Persona,
                    and_(
                        Persona.tenant_id == Lineage.tenant_id,
                        Persona.persona_id == Lineage.persona_id,
                    ),
                )
                .join(
                    Branch,
                    and_(
                        Branch.tenant_id == Lineage.tenant_id,
                        Branch.lineage_id == Lineage.lineage_id,
                    ),
                )
                .where(
                    Lineage.tenant_id == principal.tenant_id,
                    Lineage.persona_id == command.persona_id,
                    Branch.branch_id == command.branch_id,
                )
            )
        ).one_or_none()
        if identity is None:
            raise SelectionExecutionError("not_found")
        lineage_id, lineage_sealed_at, persona_retired_at, branch_row = identity
        _validate_unsealed_identity(
            persona_retired_at=persona_retired_at,
            lineage_sealed_at=lineage_sealed_at,
            branch_sealed_at=branch_row.sealed_at,
        )
        if command.logical_session_id is not None:
            session_exists = await session.scalar(
                select(LogicalSession.session_id).where(
                    LogicalSession.tenant_id == principal.tenant_id,
                    LogicalSession.session_id == command.logical_session_id,
                    LogicalSession.actor_id == principal.actor_id,
                    LogicalSession.client_id == principal.client_id,
                    LogicalSession.lineage_id == lineage_id,
                    LogicalSession.branch_id == command.branch_id,
                    LogicalSession.transport_binding_id == principal.transport_binding_id,
                )
            )
            if session_exists is None:
                raise SelectionExecutionError("not_found")

        proposal = command.proposal
        subject = await session.scalar(
            select(Subject).where(
                Subject.tenant_id == principal.tenant_id,
                Subject.lineage_id == lineage_id,
                Subject.subject_id == proposal.subject_id,
                Subject.kind == proposal.subject_kind.value,
            )
        )
        if subject is None:
            raise SelectionExecutionError("not_found")
        _validate_session_scope_anchors(
            command,
            subject_origin_session_id=subject.origin_session_id,
        )

        # Serialize exact subject/fingerprint duplicates before projection
        # mutation. The idempotency lock above remains held by this transaction.
        nomination_fingerprint = exact_memory_fingerprint(
            statement=proposal.statement,
            category=proposal.category,
            ontological_status=proposal.ontological_status,
            scope=proposal.scope,
            interpretation_limits=proposal.interpretation_limits,
        ).sha256_hex
        await acquire_advisory_xact_locks(
            session,
            (
                advisory_lock_key(
                    tenant_id=principal.tenant_id,
                    lineage_id=lineage_id,
                    branch_id=command.branch_id,
                    subject_id=command.proposal.subject_id,
                    normalized_fingerprint=nomination_fingerprint,
                ),
            ),
        )

        outcome = policy_decision.outcome
        event_id: UUID | None = None
        memory_id: UUID | None = None
        revision: int | None = None
        final_policy_rule = _policy_rule_code(policy_decision)
        result_outcome = outcome.value
        result_reason_codes = tuple(code.value for code in policy_decision.reason_codes)
        result_matched_rule_ids = policy_decision.matched_rule_ids
        evidence_for_event: tuple[EvidenceState, ...] = ()
        event: MemoryEvent | None = None
        promotion_source: SelectionDecision | None = None

        if outcome in {PolicyOutcome.CANDIDATE, PolicyOutcome.ACTIVE}:
            fingerprint = nomination_fingerprint
            duplicate = await session.scalar(
                select(Memory)
                .where(
                    Memory.tenant_id == principal.tenant_id,
                    Memory.lineage_id == lineage_id,
                    Memory.branch_id == command.branch_id,
                    Memory.subject_id == proposal.subject_id,
                    Memory.normalized_fingerprint == bytes.fromhex(fingerprint),
                    Memory.status.in_((MemoryStatus.CANDIDATE.value, MemoryStatus.ACTIVE.value)),
                )
                .with_for_update()
            )
            if duplicate is not None:
                if duplicate.status == MemoryStatus.ACTIVE.value:
                    result_outcome = PolicyOutcome.OMIT.value
                    final_policy_rule = "already_covered"
                    result_reason_codes = (final_policy_rule,)
                else:
                    result_outcome = PolicyOutcome.OMIT.value
                    final_policy_rule = "already_candidate"
                    source = await session.scalar(
                        select(SelectionDecision)
                        .where(
                            SelectionDecision.tenant_id == principal.tenant_id,
                            SelectionDecision.memory_id == duplicate.memory_id,
                            SelectionDecision.outcome == "candidate",
                        )
                        .order_by(SelectionDecision.selection_sequence.desc())
                    )
                    promotion_source = source
                    evidence_rows = (
                        await session.scalars(
                            select(MemoryEvidence).where(
                                MemoryEvidence.tenant_id == principal.tenant_id,
                                MemoryEvidence.lineage_id == lineage_id,
                                MemoryEvidence.memory_id == duplicate.memory_id,
                                MemoryEvidence.status == "active",
                            )
                        )
                    ).all()
                    if source is not None:
                        stored_evidence = tuple(
                            _stored_evidence_summary(row) for row in evidence_rows
                        )
                        new_evidence = _new_candidate_evidence(stored_evidence, resolved.evidence)
                        try:
                            lifecycle = CandidateLifecycleState(
                                status=MemoryStatus.CANDIDATE,
                                selection_basis=SelectionBasis(source.selection_basis),
                                content_signals=content_signals_from_rule_ids(
                                    str(rule) for rule in source.matched_rule_ids
                                ),
                                evidence=stored_evidence + new_evidence,
                                policy_profile_version="selection-v1",
                                policy_profile_sha256=bytes(source.policy_sha256).hex(),
                            )
                        except (TypeError, ValueError):
                            raise SelectionExecutionError("authority_unavailable") from None
                        lifecycle_decision = evaluate_promotion(lifecycle)
                        if new_evidence and lifecycle_decision.action is LifecycleAction.PROMOTE:
                            event_principal = await self._promotion_principal(
                                session,
                                nominator=principal,
                                command=command,
                                memory_id=duplicate.memory_id,
                            )
                            current = MemoryStateV2.model_validate(
                                memory_row_to_state(duplicate).model_dump(mode="python")
                            )
                            evidence_for_event = tuple(
                                _evidence_state(
                                    summary=item,
                                    evidence_id=evidence_id,
                                    tenant_id=principal.tenant_id,
                                    lineage_id=lineage_id,
                                    branch_id=command.branch_id,
                                    memory_id=duplicate.memory_id,
                                    created_at=identifiers.created_at,
                                )
                                for item, evidence_id in zip(
                                    new_evidence,
                                    identifiers.evidence_ids[: len(new_evidence)],
                                    strict=True,
                                )
                            )
                            after = MemoryStateV2.model_validate(
                                {
                                    **current.model_dump(mode="python"),
                                    "revision": current.revision + 1,
                                    "status": MemoryStatus.ACTIVE,
                                    "candidate_expires_at": None,
                                    "updated_at": identifiers.created_at,
                                }
                            )
                            payload = CandidateLifecyclePayload(
                                previous_revision=current.revision,
                                memory=after,
                                selection_decision_id=identifiers.decision_id,
                                policy_rule_code=lifecycle_decision.reason_code.value,
                                evidence=evidence_for_event,
                            )
                            internal_idempotency = (
                                f"candidate-promote:{duplicate.memory_id}:{input_digest.hex()}"
                            )
                            event = await append_memory_event(
                                session,
                                lambda sequence: _event(
                                    operation=EventOperation.CANDIDATE_PROMOTED,
                                    principal=event_principal,
                                    command=command,
                                    lineage_id=lineage_id,
                                    payload=payload,
                                    event_id=identifiers.event_id,
                                    correlation_id=identifiers.correlation_id,
                                    created_at=identifiers.created_at,
                                    memory_id=duplicate.memory_id,
                                    expected_revision=current.revision,
                                    policy_input_digest=input_digest,
                                    idempotency_key=internal_idempotency,
                                    internal_lifecycle=True,
                                ).model_copy(update={"sequence": sequence}),
                            )
                            before = await load_projection_state_for_update(
                                session, event=event, branch=branch_row
                            )
                            after_projection = validate_live_event(before, event)
                            await stage_live_projection(
                                session,
                                before=before,
                                after=after_projection,
                                event=event,
                            )
                            result_outcome = "promoted"
                            final_policy_rule = lifecycle_decision.reason_code.value
                            result_reason_codes = (final_policy_rule,)
                            result_matched_rule_ids = ()
                            memory_id = duplicate.memory_id
                            event_id = event.event_id
                            revision = after.revision
                    if result_outcome == PolicyOutcome.OMIT.value:
                        result_reason_codes = (final_policy_rule,)
            else:
                memory_id = identifiers.memory_id
                status = MemoryStatus(outcome.value)
                ttl_days = policy_decision.candidate_ttl_days
                deadline = (
                    identifiers.created_at + timedelta(days=ttl_days)
                    if status is MemoryStatus.CANDIDATE and ttl_days is not None
                    else None
                )
                evidence_for_event = tuple(
                    _evidence_state(
                        summary=item,
                        evidence_id=evidence_id,
                        tenant_id=principal.tenant_id,
                        lineage_id=lineage_id,
                        branch_id=command.branch_id,
                        memory_id=memory_id,
                        created_at=identifiers.created_at,
                    )
                    for item, evidence_id in zip(
                        resolved.evidence, identifiers.evidence_ids, strict=True
                    )
                )
                state = MemoryStateV2(
                    memory_id=memory_id,
                    tenant_id=principal.tenant_id,
                    lineage_id=lineage_id,
                    branch_id=command.branch_id,
                    subject_id=proposal.subject_id,
                    subject_kind=proposal.subject_kind,
                    revision=1,
                    category=proposal.category,
                    ontological_status=proposal.ontological_status,
                    scope=proposal.scope,
                    visibility=proposal.visibility,
                    status=status,
                    statement=proposal.statement,
                    reason_to_remember=proposal.reason_to_remember,
                    interpretation_limits=proposal.interpretation_limits,
                    confidence=proposal.confidence,
                    salience=proposal.salience,
                    durability=proposal.durability,
                    sensitivity=proposal.sensitivity,
                    authority_class=resolved.effective_authority_class,
                    valid_from=proposal.valid_from,
                    valid_to=proposal.valid_to,
                    observed_at=proposal.observed_at or identifiers.created_at,
                    origin_session_id=proposal.origin_session_id,
                    publication_approved_at=None,
                    publication_approved_by_actor_id=None,
                    content_protection="plaintext",
                    content_key_id=None,
                    created_at=identifiers.created_at,
                    updated_at=identifiers.created_at,
                    fingerprint_version=1,
                    normalized_fingerprint=fingerprint,
                    metadata=proposal.metadata,
                    candidate_expires_at=deadline,
                )
                creation_payload = MemoryCreatedPayloadV2(memory=state, evidence=evidence_for_event)
                assert memory_id is not None
                new_memory_id = memory_id
                operation = (
                    EventOperation.OBSERVED
                    if status is MemoryStatus.CANDIDATE
                    else EventOperation.REMEMBERED
                )
                event = await append_memory_event(
                    session,
                    lambda sequence: _event(
                        operation=operation,
                        principal=principal,
                        command=command,
                        lineage_id=lineage_id,
                        payload=creation_payload,
                        event_id=identifiers.event_id,
                        correlation_id=identifiers.correlation_id,
                        created_at=identifiers.created_at,
                        memory_id=new_memory_id,
                        expected_revision=None,
                        policy_input_digest=input_digest,
                    ).model_copy(update={"sequence": sequence}),
                )
                before = await load_projection_state_for_update(
                    session, event=event, branch=branch_row
                )
                projection_after = validate_live_event(before, event)
                await stage_live_projection(
                    session, before=before, after=projection_after, event=event
                )
                revision = 1
                event_id = event.event_id

        if result_outcome in {PolicyOutcome.OMIT.value, PolicyOutcome.REJECT.value}:
            memory_id = None
            event_id = None
            revision = None
        result = SelectionResult(
            receipt_id=identifiers.receipt_id,
            decision_id=identifiers.decision_id,
            outcome=cast(
                Literal["omit", "reject", "candidate", "active", "promoted"], result_outcome
            ),
            policy_sha256=policy_decision.profile_sha256,
            reason_codes=result_reason_codes,
            matched_rule_ids=result_matched_rule_ids,
            event_id=event_id,
            memory_id=memory_id,
            revision=revision,
        )
        decision_row = await self._append_decision(
            session,
            principal=principal,
            command=command,
            resolved=resolved,
            policy_decision=policy_decision,
            policy_rule_code=final_policy_rule,
            input_digest=input_digest,
            lineage_id=lineage_id,
            memory_id=memory_id,
            event_id=event_id,
            outcome=result_outcome,
            decision_id=identifiers.decision_id,
            promotion_source=promotion_source if result_outcome == "promoted" else None,
            reason_codes=result_reason_codes,
            matched_rule_ids=result_matched_rule_ids,
        )
        del decision_row
        if event is not None:
            await self._enqueue_creation_jobs(
                session,
                principal=principal,
                event=event,
                memory_id=memory_id,
                revision=revision,
                candidate=result_outcome == PolicyOutcome.CANDIDATE.value,
                promotion=result_outcome == "promoted",
                deadline=(
                    identifiers.created_at + timedelta(days=policy_decision.candidate_ttl_days)
                    if result_outcome == PolicyOutcome.CANDIDATE.value
                    and policy_decision.candidate_ttl_days is not None
                    else None
                ),
                job_ids=identifiers.job_ids,
                selection_decision_id=identifiers.decision_id,
            )
        result_value = result.model_dump(mode="json")
        canonical = canonical_json_bytes(result_value)
        session.add(
            CommandReceipt(
                receipt_id=identifiers.receipt_id,
                tenant_id=principal.tenant_id,
                client_id=principal.client_id,
                idempotency_key=command.idempotency_key,
                command_sha256=command_digest,
                event_id=event_id,
                selection_decision_id=identifiers.decision_id,
                memory_id=memory_id,
                memory_revision=revision,
                result=result_value,
                result_canonical=canonical,
                result_sha256=hashlib.sha256(canonical).digest(),
                created_at=identifiers.created_at,
            )
        )
        await session.flush()
        return result

    async def _append_decision(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        resolved: ResolvedNominationContext,
        policy_decision: PolicyDecision,
        policy_rule_code: str,
        input_digest: bytes,
        lineage_id: UUID,
        memory_id: UUID | None,
        event_id: UUID | None,
        outcome: str,
        decision_id: UUID,
        promotion_source: SelectionDecision | None,
        reason_codes: tuple[str, ...],
        matched_rule_ids: tuple[str, ...],
    ) -> SelectionDecision:
        return await append_selection_decision(
            session,
            lambda sequence: SelectionDecision(
                selection_sequence=sequence,
                decision_id=decision_id,
                tenant_id=principal.tenant_id,
                lineage_id=lineage_id,
                branch_id=command.branch_id,
                persona_id=command.persona_id,
                actor_id=principal.actor_id,
                client_id=principal.client_id,
                transport_binding_id=principal.transport_binding_id,
                policy_id="scalevault-memory-selection",
                policy_version=1,
                policy_sha256=bytes.fromhex(policy_decision.profile_sha256),
                policy_rule_code=policy_rule_code,
                input_sha256=input_digest,
                source_kind=(
                    "candidate_reassessment"
                    if promotion_source is not None
                    else resolved.source_kind
                ),
                requested_operation="promote" if promotion_source is not None else "nominate",
                outcome=outcome,
                reason_codes=list(reason_codes),
                matched_rule_ids=list(matched_rule_ids),
                selection_basis=(
                    promotion_source.selection_basis
                    if promotion_source is not None
                    else command.proposal.selection_basis.value
                ),
                scope=(
                    promotion_source.scope
                    if promotion_source is not None
                    else command.proposal.scope.value
                ),
                visibility=(
                    promotion_source.visibility
                    if promotion_source is not None
                    else command.proposal.visibility.value
                ),
                sensitivity=(
                    promotion_source.sensitivity
                    if promotion_source is not None
                    else command.proposal.sensitivity
                ),
                subject_id=(
                    promotion_source.subject_id
                    if promotion_source is not None
                    else command.proposal.subject_id
                ),
                subject_kind=(
                    promotion_source.subject_kind
                    if promotion_source is not None
                    else command.proposal.subject_kind.value
                ),
                memory_id=memory_id,
                event_id=event_id,
            ),
        )

    async def _enqueue_creation_jobs(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        event: MemoryEvent,
        memory_id: UUID | None,
        revision: int | None,
        candidate: bool,
        promotion: bool,
        deadline: datetime | None,
        job_ids: tuple[UUID, ...],
        selection_decision_id: UUID,
    ) -> None:
        if memory_id is None or revision is None:
            return
        jobs: list[tuple[str, str, dict[str, OutboxReferenceValue], datetime | None]] = [
            (
                "embed_memory",
                "memory",
                {"memory_id": memory_id, "memory_version": revision, "event_id": event.event_id},
                None,
            ),
            (
                "export_git_batch",
                "event",
                {"event_id": event.event_id, "event_sequence": event.sequence},
                None,
            ),
        ]
        if not promotion:
            jobs.insert(
                1,
                (
                    "check_duplicates",
                    "memory",
                    {
                        "memory_id": memory_id,
                        "memory_version": revision,
                        "event_id": event.event_id,
                    },
                    None,
                ),
            )
        if candidate:
            jobs.append(
                (
                    "expire_candidate",
                    "memory",
                    {
                        "memory_id": memory_id,
                        "memory_version": revision,
                        "event_id": event.event_id,
                        "selection_decision_id": selection_decision_id,
                    },
                    deadline,
                )
            )
        for job_id, (job_type, aggregate_type, references, available_at) in zip(
            job_ids, jobs, strict=False
        ):
            await enqueue_outbox_job(
                session,
                tenant_id=principal.tenant_id,
                job_type=job_type,
                aggregate_type=aggregate_type,
                aggregate_id=memory_id if aggregate_type == "memory" else event.event_id,
                references=references,
                available_at=available_at,
                job_uuid=job_id,
            )
