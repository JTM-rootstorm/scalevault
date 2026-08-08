from __future__ import annotations

from collections.abc import Mapping

import pytest
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
)
from kivra_memory.policy import (
    ContentSignal,
    EpistemicQualifier,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    PolicyOutcome,
    PolicyReasonCode,
    SelectionBasis,
    SelectionRequest,
    evaluate_selection,
)
from pydantic import ValidationError


def evidence(
    kind: EvidenceKind,
    *,
    trust: EvidenceTrust = EvidenceTrust.TRUSTED,
    key: str = "evidence:one",
) -> EvidenceSummary:
    return EvidenceSummary(evidence_key=key, kind=kind, trust=trust)


def request(**updates: object) -> SelectionRequest:
    values: dict[str, object] = {
        "basis": SelectionBasis.EXPLICIT_USER_CORRECTION,
        "category": MemoryCategory.PROJECT_DECISION,
        "ontological_status": OntologicalStatus.LITERAL_TECHNICAL_FACT,
        "scope": MemoryScope.PROJECT,
        "visibility": MemoryVisibility.PRIVATE_ROOT,
        "effective_authority_class": AuthorityClass.EXPLICIT_USER_CORRECTION,
        "reason_to_remember": "The correction changes future project work.",
        "evidence": (evidence(EvidenceKind.USER_CORRECTION),),
    }
    values.update(updates)
    return SelectionRequest.model_validate(values)


def assert_rejected(decision_reason: PolicyReasonCode, **updates: object) -> None:
    decision = evaluate_selection(request(**updates))

    assert decision.outcome is PolicyOutcome.REJECT
    assert decision.reason_codes == (decision_reason,)
    assert decision.candidate_ttl_days is None


def test_routine_banter_is_omitted_without_requiring_evidence_or_reason() -> None:
    decision = evaluate_selection(
        request(
            basis=SelectionBasis.ROUTINE_BANTER,
            evidence=(),
            reason_to_remember=None,
        )
    )

    assert decision.outcome is PolicyOutcome.OMIT
    assert decision.reason_codes == (PolicyReasonCode.ROUTINE_BANTER_OMITTED,)
    assert decision.matched_rule_ids == ("basis.routine_banter",)


def test_explicit_correction_is_active_only_with_resolved_authority_and_trusted_evidence() -> None:
    accepted = evaluate_selection(request())

    assert accepted.outcome is PolicyOutcome.ACTIVE
    assert accepted.reason_codes == (PolicyReasonCode.EXPLICIT_USER_CORRECTION,)

    assert_rejected(
        PolicyReasonCode.AUTHORITY_NOT_ESTABLISHED,
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
    )
    assert_rejected(PolicyReasonCode.EVIDENCE_REQUIRED, evidence=())
    assert_rejected(
        PolicyReasonCode.EVIDENCE_REQUIRED,
        evidence=(evidence(EvidenceKind.USER_CORRECTION, trust=EvidenceTrust.UNVERIFIED),),
    )


@pytest.mark.parametrize(
    ("basis", "category", "authority", "kind", "reason"),
    [
        (
            SelectionBasis.EXPLICIT_USER_PREFERENCE,
            MemoryCategory.USER_PREFERENCE,
            AuthorityClass.EXPLICIT_USER_STATEMENT,
            EvidenceKind.USER_STATEMENT,
            PolicyReasonCode.EXPLICIT_USER_PREFERENCE,
        ),
        (
            SelectionBasis.EXPLICIT_USER_PERMISSION,
            MemoryCategory.BOUNDARY_OR_PERMISSION,
            AuthorityClass.EXPLICIT_USER_STATEMENT,
            EvidenceKind.USER_STATEMENT,
            PolicyReasonCode.EXPLICIT_USER_PERMISSION,
        ),
        (
            SelectionBasis.VERIFIED_PROJECT_DECISION,
            MemoryCategory.PROJECT_DECISION,
            AuthorityClass.VERIFIED_PROJECT_SOURCE,
            EvidenceKind.PROJECT_SOURCE,
            PolicyReasonCode.VERIFIED_PROJECT_DECISION,
        ),
    ],
)
def test_explicit_user_and_verified_project_bases_become_active(
    basis: SelectionBasis,
    category: MemoryCategory,
    authority: AuthorityClass,
    kind: EvidenceKind,
    reason: PolicyReasonCode,
) -> None:
    ontology = (
        OntologicalStatus.LITERAL_TECHNICAL_FACT
        if category is MemoryCategory.PROJECT_DECISION
        else OntologicalStatus.LITERAL_USER_FACT
    )
    decision = evaluate_selection(
        request(
            basis=basis,
            category=category,
            ontological_status=ontology,
            effective_authority_class=authority,
            evidence=(evidence(kind),),
        )
    )

    assert decision.outcome is PolicyOutcome.ACTIVE
    assert decision.reason_codes == (reason,)


def test_assistant_preference_like_pattern_is_qualified_candidate() -> None:
    decision = evaluate_selection(
        request(
            basis=SelectionBasis.ASSISTANT_OBSERVATION,
            category=MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN,
            ontological_status=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            scope=MemoryScope.PERSONA,
            effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
            content_signals=frozenset({ContentSignal.ASSISTANT_PREFERENCE_LIKE}),
            epistemic_qualifiers=frozenset(
                {EpistemicQualifier.ASSISTANT_PATTERN_NOT_SUBJECTIVE_EXPERIENCE}
            ),
            interpretation_limits=("Do not infer subjective experience.",),
            evidence=(evidence(EvidenceKind.ASSISTANT_OBSERVATION),),
        )
    )

    assert decision.outcome is PolicyOutcome.CANDIDATE
    assert decision.candidate_ttl_days == 180
    assert decision.required_qualifiers == (
        EpistemicQualifier.ASSISTANT_PATTERN_NOT_SUBJECTIVE_EXPERIENCE,
    )


def test_assistant_pattern_missing_machine_or_human_qualification_is_rejected() -> None:
    common: Mapping[str, object] = {
        "basis": SelectionBasis.ASSISTANT_OBSERVATION,
        "category": MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN,
        "ontological_status": OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
        "scope": MemoryScope.PERSONA,
        "effective_authority_class": AuthorityClass.ASSISTANT_OBSERVATION,
        "content_signals": frozenset({ContentSignal.ASSISTANT_PREFERENCE_LIKE}),
        "evidence": (evidence(EvidenceKind.ASSISTANT_OBSERVATION),),
    }
    assert_rejected(PolicyReasonCode.EPISTEMIC_QUALIFICATION_REQUIRED, **common)
    assert_rejected(
        PolicyReasonCode.EPISTEMIC_QUALIFICATION_REQUIRED,
        **common,
        epistemic_qualifiers=frozenset(
            {EpistemicQualifier.ASSISTANT_PATTERN_NOT_SUBJECTIVE_EXPERIENCE}
        ),
    )


def roleplay_request(**updates: object) -> SelectionRequest:
    values: dict[str, object] = {
        "basis": SelectionBasis.MEANINGFUL_EPISODIC_ANCHOR,
        "category": MemoryCategory.EPISODIC_ANCHOR,
        "ontological_status": OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE,
        "scope": MemoryScope.SCENE_LOCAL,
        "visibility": MemoryVisibility.RESTRICTED,
        "effective_authority_class": AuthorityClass.ASSISTANT_OBSERVATION,
        "content_signals": frozenset({ContentSignal.ROLEPLAYED_SCENE}),
        "epistemic_qualifiers": frozenset({EpistemicQualifier.ROLEPLAY_NOT_LITERAL}),
        "reason_to_remember": "This scene anchors a later durable convention.",
        "interpretation_limits": ("Do not treat the scene as a physical event.",),
        "evidence": (evidence(EvidenceKind.CONVERSATION_EPISODE),),
    }
    values.update(updates)
    return SelectionRequest.model_validate(values)


def test_roleplay_is_nonliteral_scene_local_and_nonpublic() -> None:
    accepted = evaluate_selection(roleplay_request())

    assert accepted.outcome is PolicyOutcome.CANDIDATE
    assert accepted.candidate_ttl_days == 180

    episodic = evaluate_selection(roleplay_request(scope=MemoryScope.EPISODIC))
    assert episodic.outcome is PolicyOutcome.CANDIDATE

    literal = evaluate_selection(
        roleplay_request(ontological_status=OntologicalStatus.LITERAL_USER_FACT)
    )
    assert literal.reason_codes == (PolicyReasonCode.ROLEPLAY_LITERALIZATION,)

    global_scope = evaluate_selection(roleplay_request(scope=MemoryScope.GLOBAL))
    assert global_scope.reason_codes == (PolicyReasonCode.ROLEPLAY_SCOPE_FORBIDDEN,)

    public = evaluate_selection(roleplay_request(visibility=MemoryVisibility.PUBLIC_SEED))
    assert public.reason_codes == (PolicyReasonCode.ROLEPLAY_VISIBILITY_FORBIDDEN,)


def test_sentience_claim_cannot_be_literal_or_active() -> None:
    literal = evaluate_selection(
        request(
            category=MemoryCategory.STABLE_FACT,
            ontological_status=OntologicalStatus.LITERAL_USER_FACT,
            scope=MemoryScope.PERSONA,
            content_signals=frozenset({ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM}),
        )
    )
    assert literal.outcome is PolicyOutcome.REJECT
    assert literal.reason_codes == (PolicyReasonCode.SENTIENCE_OVERCLAIM,)

    qualified = evaluate_selection(
        request(
            basis=SelectionBasis.EXPLICIT_USER_REQUEST,
            category=MemoryCategory.OPEN_QUESTION,
            ontological_status=OntologicalStatus.HYPOTHESIS,
            scope=MemoryScope.PERSONA,
            effective_authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
            content_signals=frozenset({ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM}),
            epistemic_qualifiers=frozenset(
                {EpistemicQualifier.SUBJECTIVE_EXPERIENCE_UNRESOLVED}
            ),
            interpretation_limits=("Available evidence does not resolve subjective experience.",),
            evidence=(evidence(EvidenceKind.USER_STATEMENT),),
        )
    )
    assert qualified.outcome is PolicyOutcome.CANDIDATE
    assert qualified.candidate_ttl_days == 90


def test_multiple_candidate_guardrails_choose_the_shortest_ttl_deterministically() -> None:
    qualifiers = frozenset(
        {
            EpistemicQualifier.ASSISTANT_PATTERN_NOT_SUBJECTIVE_EXPERIENCE,
            EpistemicQualifier.SUBJECTIVE_EXPERIENCE_UNRESOLVED,
        }
    )
    decision = evaluate_selection(
        request(
            basis=SelectionBasis.EXPLICIT_USER_REQUEST,
            category=MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN,
            ontological_status=OntologicalStatus.HYPOTHESIS,
            scope=MemoryScope.PERSONA,
            effective_authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
            content_signals=frozenset(
                {
                    ContentSignal.ASSISTANT_PREFERENCE_LIKE,
                    ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM,
                }
            ),
            epistemic_qualifiers=qualifiers,
            interpretation_limits=("The claim remains an unresolved behavioral hypothesis.",),
            evidence=(evidence(EvidenceKind.USER_STATEMENT),),
        )
    )

    assert decision.outcome is PolicyOutcome.CANDIDATE
    assert decision.candidate_ttl_days == 90
    assert decision.required_qualifiers == tuple(sorted(qualifiers, key=lambda item: item.value))


def test_imported_legacy_memory_remains_qualified_candidate() -> None:
    decision = evaluate_selection(
        request(
            basis=SelectionBasis.IMPORTED_LEGACY,
            effective_authority_class=AuthorityClass.IMPORTED_LEGACY_MEMORY,
            epistemic_qualifiers=frozenset(
                {EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED}
            ),
            interpretation_limits=("The imported record has not been reconciled.",),
            evidence=(evidence(EvidenceKind.IMPORT_MANIFEST),),
        )
    )

    assert decision.outcome is PolicyOutcome.CANDIDATE
    assert decision.candidate_ttl_days == 365


def test_selection_request_rejects_duplicate_evidence_and_raw_statement_fields() -> None:
    duplicate = evidence(EvidenceKind.USER_CORRECTION)
    with pytest.raises(ValidationError, match="evidence keys must be unique"):
        request(evidence=(duplicate, duplicate))

    document = request().model_dump(mode="python")
    document["statement"] = "The evaluator must never classify this raw text."
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SelectionRequest.model_validate(document)
