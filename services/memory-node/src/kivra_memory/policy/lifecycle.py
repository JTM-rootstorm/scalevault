"""Pure candidate promotion and expiry decisions with pinned policy provenance."""

from __future__ import annotations

from kivra_memory.domain.enums import MemoryStatus
from kivra_memory.policy.contracts import (
    CandidateLifecycleState,
    ContentSignal,
    EvidenceKind,
    EvidenceTrust,
    ExpiryEvaluation,
    LifecycleAction,
    LifecycleDecision,
    LifecycleReasonCode,
    SelectionBasis,
)
from kivra_memory.policy.loader import SELECTION_V1, LoadedSelectionPolicy


def _decision(
    loaded: LoadedSelectionPolicy,
    action: LifecycleAction,
    reason: LifecycleReasonCode,
) -> LifecycleDecision:
    return LifecycleDecision(
        action=action,
        reason_code=reason,
        policy_profile_version=loaded.profile.profile_version,
        policy_profile_sha256=loaded.sha256_hex,
    )


def _profile_matches(
    candidate: CandidateLifecycleState,
    loaded: LoadedSelectionPolicy,
) -> bool:
    return (
        candidate.policy_profile_version == loaded.profile.profile_version
        and candidate.policy_profile_sha256 == loaded.sha256_hex
    )


def evaluate_promotion(
    candidate: CandidateLifecycleState,
    *,
    loaded: LoadedSelectionPolicy = SELECTION_V1,
) -> LifecycleDecision:
    """Promote only current-policy candidates with explicit or independent evidence."""

    if candidate.status is not MemoryStatus.CANDIDATE:
        return _decision(loaded, LifecycleAction.NO_OP, LifecycleReasonCode.NOT_CANDIDATE)
    if not _profile_matches(candidate, loaded):
        return _decision(
            loaded,
            LifecycleAction.NO_OP,
            LifecycleReasonCode.POLICY_PROFILE_MISMATCH,
        )
    if any(
        item.kind is EvidenceKind.USER_CONFIRMATION and item.trust is EvidenceTrust.TRUSTED
        for item in candidate.evidence
    ):
        return _decision(
            loaded,
            LifecycleAction.PROMOTE,
            LifecycleReasonCode.TRUSTED_USER_CONFIRMATION,
        )

    if candidate.selection_basis is SelectionBasis.IMPORTED_LEGACY or candidate.content_signals & {
        ContentSignal.ROLEPLAYED_SCENE,
        ContentSignal.SUBJECTIVE_EXPERIENCE_CLAIM,
    }:
        return _decision(
            loaded,
            LifecycleAction.NO_OP,
            LifecycleReasonCode.PROTECTED_CANDIDATE,
        )

    observation_keys = {
        item.evidence_key
        for item in candidate.evidence
        if item.kind is EvidenceKind.ASSISTANT_OBSERVATION and item.trust is EvidenceTrust.TRUSTED
    }
    if len(observation_keys) >= 2:
        return _decision(
            loaded,
            LifecycleAction.PROMOTE,
            LifecycleReasonCode.INDEPENDENT_OBSERVATIONS,
        )
    return _decision(
        loaded,
        LifecycleAction.NO_OP,
        LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
    )


def evaluate_expiry(
    evaluation: ExpiryEvaluation,
    *,
    loaded: LoadedSelectionPolicy = SELECTION_V1,
) -> LifecycleDecision:
    """Retire an unchanged current-policy candidate once its deadline is due."""

    candidate = evaluation.candidate
    if candidate.status is not MemoryStatus.CANDIDATE:
        return _decision(loaded, LifecycleAction.NO_OP, LifecycleReasonCode.NOT_CANDIDATE)
    if not _profile_matches(candidate, loaded):
        return _decision(
            loaded,
            LifecycleAction.NO_OP,
            LifecycleReasonCode.POLICY_PROFILE_MISMATCH,
        )
    if evaluation.deadline > evaluation.evaluated_at:
        return _decision(loaded, LifecycleAction.NO_OP, LifecycleReasonCode.EXPIRY_NOT_DUE)
    return _decision(loaded, LifecycleAction.RETIRE, LifecycleReasonCode.CANDIDATE_EXPIRED)
