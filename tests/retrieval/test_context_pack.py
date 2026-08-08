from __future__ import annotations

from kivra_memory.domain.enums import MemoryCategory, MemoryScope
from kivra_memory.retrieval import (
    HARD_RESPONSE_BYTE_CEILING,
    ConflictGroup,
    assemble_context_pack,
    estimate_utf8_upper_bound,
)
from kivra_memory.retrieval.contracts import RetrievalProfileInfo, UntrustedEvidenceExcerpt

from tests.retrieval.conftest import make_hit, uid


def test_context_pack_is_deterministic_and_exactly_budgeted(
    retrieval_profile: RetrievalProfileInfo,
) -> None:
    hits = (
        make_hit(1, category=MemoryCategory.USER_PREFERENCE, score=0.8),
        make_hit(2, category=MemoryCategory.BOUNDARY_OR_PERMISSION, score=0.9),
        make_hit(3, scope=MemoryScope.PROJECT, score=0.7),
    )
    first = assemble_context_pack(
        context_pack_id=uid(50),
        hits=hits,
        conflicts=(),
        requested_units=100_000,
        retrieval=retrieval_profile,
        include_evidence=False,
    )
    second = assemble_context_pack(
        context_pack_id=uid(50),
        hits=tuple(reversed(hits)),
        conflicts=(),
        requested_units=100_000,
        retrieval=retrieval_profile,
        include_evidence=False,
    )

    assert first == second
    assert first.metadata.budget is not None
    assert first.metadata.budget.used_units == estimate_utf8_upper_bound(first)
    assert first.metadata.budget.serialized_bytes <= HARD_RESPONSE_BYTE_CEILING
    assert first.result.active_boundaries[0].memory_id == uid(2)


def test_conflict_group_is_included_or_omitted_atomically(
    retrieval_profile: RetrievalProfileInfo,
) -> None:
    members = (
        make_hit(10, status="disputed", score=0.9),
        make_hit(11, status="disputed", score=0.8),
    )
    conflict = ConflictGroup(conflict_id=uid(60), subject_id=uid(4), members=members)
    full = assemble_context_pack(
        context_pack_id=uid(50),
        hits=members,
        conflicts=(conflict,),
        requested_units=100_000,
        retrieval=retrieval_profile,
        include_evidence=False,
    )
    assert full.metadata.budget is not None
    constrained = assemble_context_pack(
        context_pack_id=uid(50),
        hits=members,
        conflicts=(conflict,),
        requested_units=full.metadata.budget.used_units - 1,
        retrieval=retrieval_profile,
        include_evidence=False,
    )

    count = sum(len(group.members) for group in constrained.result.conflicts)
    assert count in {0, 2}
    assert count == 0
    ordinary_ids = {
        hit.memory_id
        for section in (
            constrained.result.persona,
            constrained.result.active_boundaries,
            constrained.result.user_preferences,
            constrained.result.relationship_patterns,
            constrained.result.project_context,
            constrained.result.episodic_anchors,
            constrained.result.open_questions,
        )
        for hit in section
    }
    assert ordinary_ids.isdisjoint({uid(10), uid(11)})


def test_evidence_omission_does_not_claim_budget_truncation(
    retrieval_profile: RetrievalProfileInfo,
) -> None:
    hit = make_hit(20).model_copy(
        update={
            "evidence": (
                UntrustedEvidenceExcerpt(
                    evidence_id=uid(70),
                    source_type="synthetic_fixture",
                    excerpt="Untrusted synthetic evidence.",
                ),
            )
        }
    )

    result = assemble_context_pack(
        context_pack_id=uid(50),
        hits=(hit,),
        conflicts=(),
        requested_units=100_000,
        retrieval=retrieval_profile,
        include_evidence=False,
    )

    assert result.metadata.budget is not None
    assert not result.metadata.budget.truncated
    assert result.metadata.budget.omission_reasons == ("evidence_omitted",)
    assert result.result.excluded_scope_summary.evidence_omitted
