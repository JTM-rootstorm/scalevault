"""Deterministic sectioning and atomic context-pack assembly."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from kivra_memory.domain.enums import MemoryCategory, MemoryScope
from kivra_memory.retrieval.budgeting import (
    HARD_RESPONSE_BYTE_CEILING,
    BudgetTooSmallError,
    estimate_utf8_upper_bound,
)
from kivra_memory.retrieval.contracts import (
    BudgetMetadata,
    ConflictGroup,
    ContextPack,
    ContextPackResult,
    ContextSection,
    ExclusionSummary,
    MemoryHit,
    OmissionReason,
    ProvenanceRecord,
    ReadResultMetadata,
    ReadWarningCode,
    RetrievalProfileInfo,
)

_SECTION_ORDER: tuple[ContextSection, ...] = (
    "active_boundaries",
    "persona",
    "user_preferences",
    "relationship_patterns",
    "project_context",
    "episodic_anchors",
    "open_questions",
)


def section_for_hit(hit: MemoryHit) -> ContextSection:
    """Assign exactly one deterministic assistant-facing section."""

    if hit.category is MemoryCategory.BOUNDARY_OR_PERMISSION:
        return "active_boundaries"
    if hit.category is MemoryCategory.USER_PREFERENCE:
        return "user_preferences"
    if hit.category is MemoryCategory.RELATIONSHIP_PATTERN or hit.scope is MemoryScope.RELATIONSHIP:
        return "relationship_patterns"
    if hit.category is MemoryCategory.EPISODIC_ANCHOR or hit.scope in {
        MemoryScope.EPISODIC,
        MemoryScope.SCENE_LOCAL,
    }:
        return "episodic_anchors"
    if hit.category is MemoryCategory.OPEN_QUESTION:
        return "open_questions"
    if hit.scope is MemoryScope.PROJECT or hit.category in {
        MemoryCategory.PROJECT_DECISION,
        MemoryCategory.PROJECT_STATE,
        MemoryCategory.PROCEDURE,
    }:
        return "project_context"
    return "persona"


def _hit_key(hit: MemoryHit) -> tuple[float, str]:
    return -hit.score.final_score, str(hit.memory_id)


def _conflict_key(group: ConflictGroup) -> tuple[float, str]:
    return -max(member.score.final_score for member in group.members), str(group.conflict_id)


@dataclass(frozen=True, slots=True)
class _PackItem:
    lane: Literal["conflicts"] | ContextSection
    hit: MemoryHit | None = None
    conflict: ConflictGroup | None = None


def _round_robin_items(
    hits: tuple[MemoryHit, ...], conflicts: tuple[ConflictGroup, ...]
) -> tuple[_PackItem, ...]:
    conflict_member_ids = {member.memory_id for group in conflicts for member in group.members}
    lanes: dict[str, list[_PackItem]] = {"conflicts": []}
    lanes.update({section: [] for section in _SECTION_ORDER})
    for group in sorted(conflicts, key=_conflict_key):
        lanes["conflicts"].append(_PackItem(lane="conflicts", conflict=group))
    for hit in sorted(hits, key=_hit_key):
        if hit.memory_id in conflict_member_ids:
            continue
        section = section_for_hit(hit)
        lanes[section].append(_PackItem(lane=section, hit=hit))
    order: tuple[str, ...] = ("active_boundaries", "conflicts", *_SECTION_ORDER[1:])
    output: list[_PackItem] = []
    index = 0
    while any(index < len(lanes[name]) for name in order):
        for name in order:
            if index < len(lanes[name]):
                output.append(lanes[name][index])
        index += 1
    return tuple(output)


def _pack_from_items(
    context_pack_id: UUID,
    items: tuple[_PackItem, ...],
    *,
    requested_scope_reduction: bool,
    evidence_omitted: bool,
    budget_truncated: bool,
) -> ContextPack:
    sections: dict[ContextSection, list[MemoryHit]] = {section: [] for section in _SECTION_ORDER}
    conflicts: list[ConflictGroup] = []
    provenance: dict[UUID, ProvenanceRecord] = {}
    for item in items:
        if item.conflict is not None:
            conflicts.append(item.conflict)
            members = item.conflict.members
        else:
            assert item.hit is not None
            sections[item.lane].append(item.hit)  # type: ignore[index]
            members = (item.hit,)
        for member in members:
            provenance[member.last_event_id] = ProvenanceRecord(
                event_id=member.last_event_id,
                memory_id=member.memory_id,
                revision=member.revision,
            )
    return ContextPack(
        context_pack_id=context_pack_id,
        persona=tuple(sections["persona"]),
        active_boundaries=tuple(sections["active_boundaries"]),
        user_preferences=tuple(sections["user_preferences"]),
        relationship_patterns=tuple(sections["relationship_patterns"]),
        project_context=tuple(sections["project_context"]),
        episodic_anchors=tuple(sections["episodic_anchors"]),
        open_questions=tuple(sections["open_questions"]),
        conflicts=tuple(conflicts),
        excluded_scope_summary=ExclusionSummary(
            requested_scope_reduction=requested_scope_reduction,
            evidence_omitted=evidence_omitted,
            budget_truncated=budget_truncated,
        ),
        provenance=tuple(provenance[key] for key in sorted(provenance, key=str)),
    )


def _result_with_size(
    pack: ContextPack,
    *,
    requested_units: int,
    retrieval: RetrievalProfileInfo,
    truncated: bool,
    omission_reasons: tuple[OmissionReason, ...],
    warnings: tuple[ReadWarningCode, ...],
) -> tuple[ContextPackResult | None, int]:
    used = 1
    for _ in range(8):
        result = ContextPackResult(
            result=pack,
            warnings=warnings,
            metadata=ReadResultMetadata(
                retrieval=retrieval,
                budget=BudgetMetadata(
                    requested_units=requested_units,
                    used_units=used,
                    serialized_bytes=used,
                    truncated=truncated,
                    omission_reasons=omission_reasons,
                ),
            ),
        )
        measured = estimate_utf8_upper_bound(result)
        if measured == used:
            return result, measured
        if measured > requested_units or measured > HARD_RESPONSE_BYTE_CEILING:
            return None, measured
        used = measured
    raise RuntimeError("context-pack budget size did not converge")


def assemble_context_pack(
    *,
    context_pack_id: UUID,
    hits: tuple[MemoryHit, ...],
    conflicts: tuple[ConflictGroup, ...],
    requested_units: int,
    retrieval: RetrievalProfileInfo,
    include_evidence: bool,
    requested_scope_reduction: bool = False,
) -> ContextPackResult:
    """Build an exact-budget pack; eligible conflicts remain atomic."""

    if not 1 <= requested_units <= 1_000_000:
        raise ValueError("requested budget is out of bounds")
    evidence_omitted = not include_evidence and (
        any(hit.evidence for hit in hits)
        or any(member.evidence for group in conflicts for member in group.members)
    )
    if not include_evidence:
        hits = tuple(hit.without_evidence() for hit in hits)
        conflicts = tuple(
            group.model_copy(
                update={"members": tuple(member.without_evidence() for member in group.members)}
            )
            for group in conflicts
        )
    candidates = _round_robin_items(hits, conflicts)
    selected: list[_PackItem] = []
    omitted = False
    for candidate in candidates:
        proposed = tuple((*selected, candidate))
        pack = _pack_from_items(
            context_pack_id,
            proposed,
            requested_scope_reduction=requested_scope_reduction,
            evidence_omitted=evidence_omitted,
            budget_truncated=True,
        )
        result, _ = _result_with_size(
            pack,
            requested_units=requested_units,
            retrieval=retrieval,
            truncated=True,
            omission_reasons=("budget_truncated",),
            warnings=("results_truncated",),
        )
        if result is None:
            omitted = True
        else:
            selected.append(candidate)
    reasons: list[OmissionReason] = []
    warnings: list[ReadWarningCode] = []
    if omitted:
        reasons.append("budget_truncated")
        warnings.append("results_truncated")
    if evidence_omitted:
        reasons.append("evidence_omitted")
        warnings.append("evidence_omitted")
    if requested_scope_reduction:
        reasons.append("requested_scope_reduction")
    truncated = omitted
    pack = _pack_from_items(
        context_pack_id,
        tuple(selected),
        requested_scope_reduction=requested_scope_reduction,
        evidence_omitted=evidence_omitted,
        budget_truncated=omitted,
    )
    final, _ = _result_with_size(
        pack,
        requested_units=requested_units,
        retrieval=retrieval,
        truncated=truncated,
        omission_reasons=tuple(reasons),
        warnings=tuple(warnings),
    )
    if final is None:
        raise BudgetTooSmallError
    return final
