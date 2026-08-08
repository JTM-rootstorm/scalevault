"""Immutable selection-decision persistence and authorization-filtered history."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, SubjectKind
from kivra_memory.storage.models import SelectionDecision, SelectionDecisionCounter
from kivra_memory.storage.transactions import database_sqlstate

_SELECTION_BASES = frozenset(
    {
        "routine_banter",
        "explicit_user_correction",
        "explicit_user_preference",
        "explicit_user_permission",
        "verified_project_decision",
        "assistant_observation",
        "assistant_interpretation",
        "imported_legacy",
        "meaningful_episodic_anchor",
        "explicit_user_request",
    }
)


class SelectionHistoryError(RuntimeError):
    """A bounded persistence failure that contains no nominated content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class SelectionHistoryFilters:
    """Pre-authorized history bounds for one persona and exact branch."""

    tenant_id: UUID
    persona_id: UUID
    lineage_id: UUID
    branch_id: UUID
    allowed_scopes: frozenset[MemoryScope]
    allowed_visibilities: frozenset[MemoryVisibility]
    max_sensitivity: int
    requested_subject_ids: frozenset[UUID] | None = None
    project_subject_ids: frozenset[UUID] = frozenset()
    relationship_subject_ids: frozenset[UUID] = frozenset()
    session_subject_ids: frozenset[UUID] = frozenset()
    allowed_subject_kinds: frozenset[SubjectKind] | None = None
    selection_bases: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if not self.allowed_scopes:
            raise ValueError("selection history requires at least one allowed scope")
        if not self.allowed_visibilities:
            raise ValueError("selection history requires at least one allowed visibility")
        if isinstance(self.max_sensitivity, bool) or not 0 <= self.max_sensitivity <= 4:
            raise ValueError("maximum sensitivity must be between zero and four")
        if self.selection_bases is not None and (
            not self.selection_bases or not self.selection_bases <= _SELECTION_BASES
        ):
            raise ValueError("selection bases must be a non-empty subset of the closed vocabulary")


@dataclass(frozen=True, slots=True)
class SelectionDecisionRecord:
    """Safe selection audit fields; private provenance and input hashes are omitted."""

    selection_sequence: int
    decision_id: UUID
    persona_id: UUID
    policy_id: str
    policy_version: int
    policy_sha256: str
    policy_rule_code: str
    matched_rule_ids: tuple[str, ...]
    source_kind: str
    requested_operation: str
    outcome: str
    reason_codes: tuple[str, ...]
    selection_basis: str
    scope: str
    visibility: str
    sensitivity: int
    subject_id: UUID
    subject_kind: str
    memory_id: UUID | None
    event_id: UUID | None
    decided_at: datetime


SelectionDecisionBuilder = Callable[[int], SelectionDecision]


async def append_selection_decision(
    session: AsyncSession,
    builder: SelectionDecisionBuilder,
) -> SelectionDecision:
    """Allocate and stage one decision with rollback-safe stable ordering."""

    if not session.in_transaction():
        raise SelectionHistoryError("active_transaction_required")
    try:
        counter = await session.scalar(
            select(SelectionDecisionCounter)
            .where(SelectionDecisionCounter.counter_id == 1)
            .with_for_update()
        )
        if counter is None:
            raise SelectionHistoryError("selection_counter_unavailable")
        decision = builder(counter.next_sequence)
        if decision.selection_sequence != counter.next_sequence:
            raise SelectionHistoryError("selection_sequence_mismatch")
        session.add(decision)
        counter.next_sequence += 1
        await session.flush()
        return decision
    except SelectionHistoryError:
        raise
    except SQLAlchemyError as error:
        if isinstance(error, DBAPIError) and database_sqlstate(error) == "40001":
            raise
        raise SelectionHistoryError("selection_history_unavailable") from None


class SelectionHistoryRepository:
    """Read immutable decisions without consulting mutable Memory status."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_decisions(
        self,
        filters: SelectionHistoryFilters,
        *,
        before_sequence: int | None = None,
        limit: int = 100,
    ) -> tuple[SelectionDecisionRecord, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("selection history limit must be between 1 and 500")
        if before_sequence is not None and (
            isinstance(before_sequence, bool) or before_sequence < 1
        ):
            raise ValueError("before_sequence must be positive")

        predicates = [
            SelectionDecision.tenant_id == filters.tenant_id,
            SelectionDecision.persona_id == filters.persona_id,
            SelectionDecision.lineage_id == filters.lineage_id,
            SelectionDecision.branch_id == filters.branch_id,
            SelectionDecision.scope.in_(scope.value for scope in filters.allowed_scopes),
            SelectionDecision.visibility.in_(
                visibility.value for visibility in filters.allowed_visibilities
            ),
            SelectionDecision.sensitivity <= filters.max_sensitivity,
            or_(
                SelectionDecision.scope.in_((MemoryScope.GLOBAL.value, MemoryScope.PERSONA.value)),
                and_(
                    SelectionDecision.scope == MemoryScope.PROJECT.value,
                    SelectionDecision.subject_id.in_(filters.project_subject_ids),
                ),
                and_(
                    SelectionDecision.scope == MemoryScope.RELATIONSHIP.value,
                    SelectionDecision.subject_id.in_(filters.relationship_subject_ids),
                ),
                and_(
                    SelectionDecision.scope.in_(
                        (MemoryScope.EPISODIC.value, MemoryScope.SCENE_LOCAL.value)
                    ),
                    SelectionDecision.subject_id.in_(filters.session_subject_ids),
                ),
            ),
        ]
        if filters.requested_subject_ids is not None:
            predicates.append(SelectionDecision.subject_id.in_(filters.requested_subject_ids))
        if filters.allowed_subject_kinds is not None:
            predicates.append(
                SelectionDecision.subject_kind.in_(
                    kind.value for kind in filters.allowed_subject_kinds
                )
            )
        if filters.selection_bases is not None:
            predicates.append(SelectionDecision.selection_basis.in_(filters.selection_bases))
        if before_sequence is not None:
            predicates.append(SelectionDecision.selection_sequence < before_sequence)

        try:
            rows = (
                await self._session.scalars(
                    select(SelectionDecision)
                    .where(*predicates)
                    .order_by(SelectionDecision.selection_sequence.desc())
                    .limit(limit)
                )
            ).all()
        except SQLAlchemyError:
            raise SelectionHistoryError("selection_history_unavailable") from None

        return tuple(
            SelectionDecisionRecord(
                selection_sequence=row.selection_sequence,
                decision_id=row.decision_id,
                persona_id=row.persona_id,
                policy_id=row.policy_id,
                policy_version=row.policy_version,
                policy_sha256=bytes(row.policy_sha256).hex(),
                policy_rule_code=row.policy_rule_code,
                matched_rule_ids=tuple(str(code) for code in row.matched_rule_ids),
                source_kind=row.source_kind,
                requested_operation=row.requested_operation,
                outcome=row.outcome,
                reason_codes=tuple(str(code) for code in row.reason_codes),
                selection_basis=row.selection_basis,
                scope=row.scope,
                visibility=row.visibility,
                sensitivity=row.sensitivity,
                subject_id=row.subject_id,
                subject_kind=row.subject_kind,
                memory_id=row.memory_id,
                event_id=row.event_id,
                decided_at=row.decided_at,
            )
            for row in rows
        )
