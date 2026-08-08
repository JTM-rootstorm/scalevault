"""Pure exact-branch authorization and semantic eligibility predicates."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.retrieval.contracts import (
    ContextPackQuery,
    DirectReadQuery,
    MemoryFilters,
    MemorySearchQuery,
    MemoryTimelineQuery,
    QueryPrincipal,
    ReadModel,
)

_REQUIRED_SCOPES = {
    "context_pack": "memory.read.context",
    "search": "memory.read.search",
    "get": "memory.read.get",
    "timeline": "memory.read.timeline",
    "conflicts": "memory.read.conflicts",
    "lineage": "memory.read.lineage",
    "selection_history": "memory.read.selection_history",
}
type EligibilityReason = Literal[
    "eligible",
    "unauthorized_operation",
    "tenant_mismatch",
    "lineage_mismatch",
    "branch_mismatch",
    "terminal_status",
    "candidate_not_allowed",
    "scope_not_authorized",
    "scope_not_requested",
    "visibility_not_authorized",
    "visibility_not_requested",
    "sensitivity_not_authorized",
    "subject_not_requested",
    "session_not_eligible",
    "outside_validity_window",
    "category_not_requested",
    "ontology_not_requested",
    "subject_kind_not_requested",
]


class ResolvedReadContext(ReadModel):
    """Tenant-resolved structural anchors used by the pure policy."""

    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    logical_session_id: UUID | None = None
    project_subject_id: UUID | None = None
    relationship_subject_id: UUID | None = None

    @field_validator(
        "tenant_id",
        "lineage_id",
        "branch_id",
        "logical_session_id",
        "project_subject_id",
        "relationship_subject_id",
    )
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value


class EligibilityCandidate(ReadModel):
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    memory_id: UUID
    subject_id: UUID
    subject_kind: SubjectKind
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    sensitivity: int = Field(ge=0, le=4)
    status: MemoryStatus
    origin_session_id: UUID | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None

    @field_validator(
        "tenant_id",
        "lineage_id",
        "branch_id",
        "memory_id",
        "subject_id",
        "origin_session_id",
    )
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value


class EligibilityDecision(ReadModel):
    eligible: bool
    reason: EligibilityReason


def operation_authorized(principal: QueryPrincipal, query: DirectReadQuery) -> bool:
    """Require one exact dotted read scope or the seven-read legacy alias."""

    return (
        _REQUIRED_SCOPES[query.OPERATION] in principal.scopes or "memory:read" in principal.scopes
    )


def filters_for_query(query: DirectReadQuery) -> MemoryFilters:
    """Normalize caller narrowing fields without manufacturing authority."""

    if isinstance(query, ContextPackQuery):
        return MemoryFilters(scopes=query.requested_memory_scopes)
    if isinstance(query, MemorySearchQuery | MemoryTimelineQuery):
        return query.filters
    return MemoryFilters()


def _reject(reason: EligibilityReason) -> EligibilityDecision:
    return EligibilityDecision(eligible=False, reason=reason)


def evaluate_eligibility(
    principal: QueryPrincipal,
    context: ResolvedReadContext,
    candidate: EligibilityCandidate,
    *,
    query: DirectReadQuery,
    filters: MemoryFilters,
    evaluated_at: datetime,
) -> EligibilityDecision:
    """Return one content-free decision; caller filters can only narrow authority."""

    if not operation_authorized(principal, query):
        return _reject("unauthorized_operation")
    if principal.tenant_id != context.tenant_id or candidate.tenant_id != principal.tenant_id:
        return _reject("tenant_mismatch")
    if candidate.lineage_id != context.lineage_id:
        return _reject("lineage_mismatch")
    if candidate.branch_id != context.branch_id or candidate.branch_id != query.branch_id:
        return _reject("branch_mismatch")
    if candidate.status in {
        MemoryStatus.SUPERSEDED,
        MemoryStatus.RETIRED,
        MemoryStatus.TOMBSTONED,
    }:
        return _reject("terminal_status")
    if candidate.status is MemoryStatus.CANDIDATE and not (
        principal.allow_candidates and filters.include_candidates
    ):
        return _reject("candidate_not_allowed")
    if candidate.scope not in principal.allowed_memory_scopes:
        return _reject("scope_not_authorized")
    if filters.scopes and candidate.scope not in filters.scopes:
        return _reject("scope_not_requested")
    if candidate.visibility not in principal.allowed_visibilities:
        return _reject("visibility_not_authorized")
    if filters.visibilities and candidate.visibility not in filters.visibilities:
        return _reject("visibility_not_requested")
    if candidate.sensitivity > principal.max_sensitivity:
        return _reject("sensitivity_not_authorized")
    if filters.subject_ids and candidate.subject_id not in filters.subject_ids:
        return _reject("subject_not_requested")
    if filters.subject_kinds and candidate.subject_kind not in filters.subject_kinds:
        return _reject("subject_kind_not_requested")
    if filters.categories and candidate.category not in filters.categories:
        return _reject("category_not_requested")
    if filters.ontological_statuses and (
        candidate.ontological_status not in filters.ontological_statuses
    ):
        return _reject("ontology_not_requested")
    if candidate.scope is MemoryScope.PROJECT and (
        context.project_subject_id is None or candidate.subject_id != context.project_subject_id
    ):
        return _reject("subject_not_requested")
    if candidate.scope is MemoryScope.RELATIONSHIP and (
        context.relationship_subject_id is None
        or candidate.subject_id != context.relationship_subject_id
    ):
        return _reject("subject_not_requested")
    if candidate.scope in {MemoryScope.EPISODIC, MemoryScope.SCENE_LOCAL} and (
        context.logical_session_id is None
        or candidate.origin_session_id != context.logical_session_id
    ):
        return _reject("session_not_eligible")
    valid_at = filters.valid_at or evaluated_at
    if candidate.valid_from is not None and candidate.valid_from > valid_at:
        return _reject("outside_validity_window")
    if candidate.valid_to is not None and candidate.valid_to < valid_at:
        return _reject("outside_validity_window")
    return EligibilityDecision(eligible=True, reason="eligible")


def conflict_group_eligible(decisions: tuple[EligibilityDecision, ...]) -> bool:
    """An unresolved conflict expands only when every member is eligible."""

    return len(decisions) >= 2 and all(decision.eligible for decision in decisions)
