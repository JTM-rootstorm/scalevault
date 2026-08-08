"""Pure deterministic evaluation of structured memory-selection facts."""

from __future__ import annotations

from collections.abc import Iterable

from kivra_memory.domain.constraints import CATEGORY_ONTOLOGY_COMPATIBILITY
from kivra_memory.policy.contracts import (
    BasisRule,
    ContentSignal,
    EpistemicQualifier,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    SelectionRequest,
    SignalGuardrail,
)
from kivra_memory.policy.loader import SELECTION_V1, LoadedSelectionPolicy


def _ordered_qualifiers(values: Iterable[EpistemicQualifier]) -> tuple[EpistemicQualifier, ...]:
    return tuple(sorted(set(values), key=lambda item: item.value))


def _decision(
    loaded: LoadedSelectionPolicy,
    *,
    outcome: PolicyOutcome,
    reason: PolicyReasonCode,
    matched_rule_ids: tuple[str, ...] = (),
    required_qualifiers: tuple[EpistemicQualifier, ...] = (),
    candidate_ttl_days: int | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        profile_version=loaded.profile.profile_version,
        profile_sha256=loaded.sha256_hex,
        outcome=outcome,
        reason_codes=(reason,),
        matched_rule_ids=matched_rule_ids,
        required_qualifiers=required_qualifiers,
        candidate_ttl_days=candidate_ttl_days,
    )


def _reject(
    loaded: LoadedSelectionPolicy,
    reason: PolicyReasonCode,
    matched_rule_ids: tuple[str, ...] = (),
    required_qualifiers: tuple[EpistemicQualifier, ...] = (),
) -> PolicyDecision:
    return _decision(
        loaded,
        outcome=PolicyOutcome.REJECT,
        reason=reason,
        matched_rule_ids=matched_rule_ids,
        required_qualifiers=required_qualifiers,
    )


def _basis_rule(request: SelectionRequest, loaded: LoadedSelectionPolicy) -> BasisRule | None:
    return next(
        (rule for rule in loaded.profile.basis_rules if rule.basis is request.basis),
        None,
    )


def _guardrail_violation(
    request: SelectionRequest,
    guardrail: SignalGuardrail,
) -> PolicyReasonCode | None:
    if request.category not in guardrail.allowed_categories:
        return guardrail.violation_code
    if request.ontological_status not in guardrail.allowed_ontologies:
        return guardrail.violation_code
    if request.scope not in guardrail.allowed_scopes:
        if guardrail.signal is ContentSignal.ROLEPLAYED_SCENE:
            return PolicyReasonCode.ROLEPLAY_SCOPE_FORBIDDEN
        return guardrail.violation_code
    if request.visibility not in guardrail.allowed_visibilities:
        if guardrail.signal is ContentSignal.ROLEPLAYED_SCENE:
            return PolicyReasonCode.ROLEPLAY_VISIBILITY_FORBIDDEN
        return guardrail.violation_code
    return None


def _evidence_satisfies(request: SelectionRequest, rule: BasisRule) -> bool:
    requirement = rule.evidence_requirement
    if requirement is None:
        return True
    matching_keys = {
        item.evidence_key
        for item in request.evidence
        if item.kind in requirement.kinds and item.trust in requirement.trusts
    }
    return len(matching_keys) >= requirement.minimum


def evaluate_selection(
    request: SelectionRequest,
    *,
    loaded: LoadedSelectionPolicy = SELECTION_V1,
) -> PolicyDecision:
    """Evaluate server-resolved structured facts with fixed fail-closed precedence."""

    allowed_ontologies = CATEGORY_ONTOLOGY_COMPATIBILITY.get(request.category, frozenset())
    if request.ontological_status not in allowed_ontologies:
        return _reject(loaded, PolicyReasonCode.CATEGORY_ONTOLOGY_INCOMPATIBLE)

    basis_rule = _basis_rule(request, loaded)
    if basis_rule is None:
        return _reject(loaded, loaded.profile.default_reason_code)
    matched_rule_ids: tuple[str, ...] = (basis_rule.rule_id,)

    # An omission never persists content, so evidence and qualification gates do not apply.
    if basis_rule.outcome is PolicyOutcome.OMIT:
        return _decision(
            loaded,
            outcome=PolicyOutcome.OMIT,
            reason=basis_rule.reason_code,
            matched_rule_ids=matched_rule_ids,
        )

    applicable_guardrails = tuple(
        guardrail
        for guardrail in loaded.profile.signal_guardrails
        if guardrail.signal in request.content_signals
    )
    matched_rule_ids += tuple(guardrail.rule_id for guardrail in applicable_guardrails)
    required_qualifiers = _ordered_qualifiers(
        qualifier
        for guardrail in applicable_guardrails
        for qualifier in guardrail.required_qualifiers
    )

    for guardrail in applicable_guardrails:
        violation = _guardrail_violation(request, guardrail)
        if violation is not None:
            return _reject(
                loaded,
                violation,
                matched_rule_ids,
                required_qualifiers,
            )

    if basis_rule.required_authority is not None and (
        request.effective_authority_class is not basis_rule.required_authority
    ):
        return _reject(
            loaded,
            PolicyReasonCode.AUTHORITY_NOT_ESTABLISHED,
            matched_rule_ids,
            required_qualifiers,
        )
    if not _evidence_satisfies(request, basis_rule):
        return _reject(
            loaded,
            PolicyReasonCode.EVIDENCE_REQUIRED,
            matched_rule_ids,
            required_qualifiers,
        )
    if basis_rule.allowed_categories and request.category not in basis_rule.allowed_categories:
        return _reject(
            loaded,
            PolicyReasonCode.BASIS_CATEGORY_INCOMPATIBLE,
            matched_rule_ids,
            required_qualifiers,
        )
    if request.reason_to_remember is None:
        return _reject(
            loaded,
            PolicyReasonCode.REASON_REQUIRED,
            matched_rule_ids,
            required_qualifiers,
        )

    required_qualifiers = _ordered_qualifiers(
        (*basis_rule.required_qualifiers, *required_qualifiers)
    )
    needs_limits = basis_rule.requires_interpretation_limits or any(
        guardrail.requires_interpretation_limits for guardrail in applicable_guardrails
    )
    if not set(required_qualifiers) <= request.epistemic_qualifiers or (
        needs_limits and not request.interpretation_limits
    ):
        return _reject(
            loaded,
            PolicyReasonCode.EPISTEMIC_QUALIFICATION_REQUIRED,
            matched_rule_ids,
            required_qualifiers,
        )

    forcing_guardrails = tuple(
        guardrail for guardrail in applicable_guardrails if guardrail.force_candidate
    )
    candidate_ttl_days: int | None
    if forcing_guardrails:
        outcome = PolicyOutcome.CANDIDATE
        candidate_ttl_days = min(
            guardrail.forced_candidate_ttl_days
            for guardrail in forcing_guardrails
            if guardrail.forced_candidate_ttl_days is not None
        )
    else:
        outcome = PolicyOutcome(basis_rule.outcome)
        candidate_ttl_days = basis_rule.candidate_ttl_days

    return _decision(
        loaded,
        outcome=outcome,
        reason=basis_rule.reason_code,
        matched_rule_ids=matched_rule_ids,
        required_qualifiers=required_qualifiers,
        candidate_ttl_days=candidate_ttl_days,
    )
