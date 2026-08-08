from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from kivra_memory.domain.enums import MemoryStatus
from kivra_memory.policy import (
    SELECTION_V1,
    CandidateLifecycleState,
    ContentSignal,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    ExpiryEvaluation,
    LifecycleAction,
    LifecycleReasonCode,
    SelectionBasis,
    content_signals_from_rule_ids,
    evaluate_expiry,
    evaluate_promotion,
)


def test_content_signals_reconstruct_only_exact_canonical_guardrail_rule_ids() -> None:
    signals = content_signals_from_rule_ids(
        (
            "guardrail.roleplayed_scene",
            "guardrail.assistant_preference_like",
            "guardrail.subjective_experience_claim",
            "basis.subjective_experience_claim",
            "guardrail.roleplayish_but_not_canonical",
        )
    )

    assert signals == frozenset(
        {
            ContentSignal.ROLEPLAYED_SCENE,
            ContentSignal.ASSISTANT_PREFERENCE_LIKE,
            ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM,
        }
    )


def evidence(
    key: str,
    kind: EvidenceKind = EvidenceKind.ASSISTANT_OBSERVATION,
    trust: EvidenceTrust = EvidenceTrust.TRUSTED,
) -> EvidenceSummary:
    return EvidenceSummary(evidence_key=key, kind=kind, trust=trust)


def candidate(**updates: object) -> CandidateLifecycleState:
    values: dict[str, object] = {
        "status": MemoryStatus.CANDIDATE,
        "selection_basis": SelectionBasis.ASSISTANT_OBSERVATION,
        "policy_profile_version": SELECTION_V1.profile.profile_version,
        "policy_profile_sha256": SELECTION_V1.sha256_hex,
    }
    values.update(updates)
    return CandidateLifecycleState.model_validate(values)


def test_two_distinct_trusted_assistant_observations_promote_candidate() -> None:
    decision = evaluate_promotion(
        candidate(evidence=(evidence("observation:one"), evidence("observation:two")))
    )

    assert decision.action is LifecycleAction.PROMOTE
    assert decision.reason_code is LifecycleReasonCode.INDEPENDENT_OBSERVATIONS


def test_untrusted_or_insufficient_observation_evidence_does_not_promote() -> None:
    insufficient = evaluate_promotion(candidate(evidence=(evidence("observation:one"),)))
    untrusted = evaluate_promotion(
        candidate(
            evidence=(
                evidence("observation:one", trust=EvidenceTrust.UNVERIFIED),
                evidence("observation:two", trust=EvidenceTrust.UNVERIFIED),
            )
        )
    )

    assert insufficient.action is LifecycleAction.NO_OP
    assert insufficient.reason_code is LifecycleReasonCode.INSUFFICIENT_EVIDENCE
    assert untrusted.reason_code is LifecycleReasonCode.INSUFFICIENT_EVIDENCE


def test_trusted_user_confirmation_can_promote_without_repetition() -> None:
    decision = evaluate_promotion(
        candidate(evidence=(evidence("confirmation:one", EvidenceKind.USER_CONFIRMATION),))
    )

    assert decision.action is LifecycleAction.PROMOTE
    assert decision.reason_code is LifecycleReasonCode.TRUSTED_USER_CONFIRMATION


@pytest.mark.parametrize(
    ("basis", "signals"),
    [
        (SelectionBasis.IMPORTED_LEGACY, frozenset()),
        (SelectionBasis.MEANINGFUL_EPISODIC_ANCHOR, frozenset({ContentSignal.ROLEPLAYED_SCENE})),
        (
            SelectionBasis.ASSISTANT_INTERPRETATION,
            frozenset({ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM}),
        ),
    ],
)
def test_protected_candidates_never_auto_promote_from_repetition_alone(
    basis: SelectionBasis,
    signals: frozenset[ContentSignal],
) -> None:
    decision = evaluate_promotion(
        candidate(
            selection_basis=basis,
            content_signals=signals,
            evidence=(evidence("observation:one"), evidence("observation:two")),
        )
    )

    assert decision.action is LifecycleAction.NO_OP
    assert decision.reason_code is LifecycleReasonCode.PROTECTED_CANDIDATE


def test_non_candidate_and_stale_policy_promotion_are_safe_no_ops() -> None:
    active = evaluate_promotion(candidate(status=MemoryStatus.ACTIVE))
    stale = evaluate_promotion(candidate(policy_profile_sha256="0" * 64))
    stale_version = evaluate_promotion(candidate(policy_profile_version="selection-v2"))

    assert active.reason_code is LifecycleReasonCode.NOT_CANDIDATE
    assert stale.reason_code is LifecycleReasonCode.POLICY_PROFILE_MISMATCH
    assert stale_version.reason_code is LifecycleReasonCode.POLICY_PROFILE_MISMATCH
    assert active.action is stale.action is stale_version.action is LifecycleAction.NO_OP


def test_candidate_expires_at_deadline_but_not_before() -> None:
    now = datetime(2026, 8, 8, 18, 0, tzinfo=UTC)
    due = evaluate_expiry(ExpiryEvaluation(candidate=candidate(), deadline=now, evaluated_at=now))
    future = evaluate_expiry(
        ExpiryEvaluation(
            candidate=candidate(),
            deadline=now + timedelta(seconds=1),
            evaluated_at=now,
        )
    )

    assert due.action is LifecycleAction.RETIRE
    assert due.reason_code is LifecycleReasonCode.CANDIDATE_EXPIRED
    assert future.action is LifecycleAction.NO_OP
    assert future.reason_code is LifecycleReasonCode.EXPIRY_NOT_DUE


@pytest.mark.parametrize(
    "status",
    [
        MemoryStatus.ACTIVE,
        MemoryStatus.DISPUTED,
        MemoryStatus.SUPERSEDED,
        MemoryStatus.RETIRED,
        MemoryStatus.TOMBSTONED,
    ],
)
def test_non_candidate_expiry_is_safe_no_op(status: MemoryStatus) -> None:
    now = datetime(2026, 8, 8, 18, 0, tzinfo=UTC)
    decision = evaluate_expiry(
        ExpiryEvaluation(
            candidate=candidate(status=status),
            deadline=now - timedelta(days=1),
            evaluated_at=now,
        )
    )

    assert decision.action is LifecycleAction.NO_OP
    assert decision.reason_code is LifecycleReasonCode.NOT_CANDIDATE


def test_stale_policy_expiry_is_safe_no_op() -> None:
    now = datetime(2026, 8, 8, 18, 0, tzinfo=UTC)
    decision = evaluate_expiry(
        ExpiryEvaluation(
            candidate=candidate(policy_profile_sha256="f" * 64),
            deadline=now - timedelta(days=1),
            evaluated_at=now,
        )
    )

    assert decision.action is LifecycleAction.NO_OP
    assert decision.reason_code is LifecycleReasonCode.POLICY_PROFILE_MISMATCH
