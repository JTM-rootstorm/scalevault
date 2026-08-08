from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.retrieval.contracts import MemoryFilters, MemorySearchQuery, QueryPrincipal
from kivra_memory.retrieval.eligibility import (
    EligibilityCandidate,
    ResolvedReadContext,
    evaluate_eligibility,
)

from tests.retrieval.conftest import uid

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


def query() -> MemorySearchQuery:
    return MemorySearchQuery(
        contract_version="mcp-read-v1",
        persona_id=uid(5),
        branch_id=uid(3),
        project_ref="project:synthetic",
        query="synthetic",
    )


def principal(
    *, scopes: frozenset[MemoryScope], visibilities: frozenset[MemoryVisibility], sensitivity: int
) -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=uid(1),
        actor_id=uid(20),
        client_id=uid(21),
        transport_binding_id=uid(22),
        scopes=frozenset({"memory.read.search"}),
        allowed_memory_scopes=scopes,
        allowed_visibilities=visibilities,
        max_sensitivity=sensitivity,
    )


def candidate(**updates: object) -> EligibilityCandidate:
    values: dict[str, object] = {
        "tenant_id": uid(1),
        "lineage_id": uid(2),
        "branch_id": uid(3),
        "memory_id": uid(7),
        "subject_id": uid(6),
        "subject_kind": SubjectKind.PROJECT,
        "category": MemoryCategory.PROJECT_DECISION,
        "ontological_status": OntologicalStatus.LITERAL_TECHNICAL_FACT,
        "scope": MemoryScope.PROJECT,
        "visibility": MemoryVisibility.RESTRICTED,
        "sensitivity": 1,
        "status": MemoryStatus.ACTIVE,
    }
    values.update(updates)
    return EligibilityCandidate.model_validate(values)


def context() -> ResolvedReadContext:
    return ResolvedReadContext(
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        project_subject_id=uid(6),
    )


def test_terminal_and_tombstoned_content_is_never_eligible() -> None:
    authority = principal(
        scopes=frozenset(MemoryScope),
        visibilities=frozenset(MemoryVisibility),
        sensitivity=4,
    )
    for status in (MemoryStatus.SUPERSEDED, MemoryStatus.RETIRED, MemoryStatus.TOMBSTONED):
        decision = evaluate_eligibility(
            authority,
            context(),
            candidate(status=status),
            query=query(),
            filters=MemoryFilters(),
            evaluated_at=NOW,
        )
        assert not decision.eligible and decision.reason == "terminal_status"


def test_category_and_ontology_filters_compare_typed_candidate_fields() -> None:
    authority = principal(
        scopes=frozenset({MemoryScope.PROJECT}),
        visibilities=frozenset({MemoryVisibility.RESTRICTED}),
        sensitivity=1,
    )
    decision = evaluate_eligibility(
        authority,
        context(),
        candidate(),
        query=query(),
        filters=MemoryFilters(
            categories=frozenset({MemoryCategory.PROJECT_DECISION}),
            ontological_statuses=frozenset({OntologicalStatus.LITERAL_TECHNICAL_FACT}),
        ),
        evaluated_at=NOW,
    )
    assert decision.eligible


@given(
    allow_scope=st.booleans(),
    allow_visibility=st.booleans(),
    narrow_sensitivity=st.integers(min_value=0, max_value=4),
)
def test_narrowing_authority_never_adds_an_eligible_memory(
    allow_scope: bool, allow_visibility: bool, narrow_sensitivity: int
) -> None:
    broad = principal(
        scopes=frozenset(MemoryScope),
        visibilities=frozenset(MemoryVisibility),
        sensitivity=4,
    )
    narrow = principal(
        scopes=frozenset({MemoryScope.PROJECT}) if allow_scope else frozenset(),
        visibilities=(
            frozenset({MemoryVisibility.RESTRICTED}) if allow_visibility else frozenset()
        ),
        sensitivity=narrow_sensitivity,
    )
    broad_result = evaluate_eligibility(
        broad, context(), candidate(), query=query(), filters=MemoryFilters(), evaluated_at=NOW
    )
    narrow_result = evaluate_eligibility(
        narrow, context(), candidate(), query=query(), filters=MemoryFilters(), evaluated_at=NOW
    )
    assert not narrow_result.eligible or broad_result.eligible
