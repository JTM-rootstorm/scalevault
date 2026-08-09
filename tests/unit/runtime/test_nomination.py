from __future__ import annotations

from decimal import Decimal
from uuid import UUID

import pytest
from kivra_memory.api.mcp import NominationWireRequest
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import ResolvedNominationContext
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    NominationEvidenceReference,
    NominationProposal,
    PolicyOutcome,
    SelectionBasis,
    SelectionRequest,
    evaluate_selection,
)
from kivra_memory.runtime.nomination import DirectNominationResolver


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def principal() -> CommandPrincipal:
    return CommandPrincipal(
        tenant_id=uid(1),
        actor_id=uid(2),
        client_id=uid(3),
        transport_binding_id=uid(4),
        scopes=frozenset({"memory.write.nominate"}),
    )


def command(
    basis: SelectionBasis,
    *,
    category: MemoryCategory = MemoryCategory.RELATIONSHIP_PATTERN,
    ontology: OntologicalStatus = OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
    scope: MemoryScope = MemoryScope.RELATIONSHIP,
    visibility: MemoryVisibility = MemoryVisibility.PRIVATE_ROOT,
    evidence: tuple[NominationEvidenceReference, ...] = (),
) -> NominationWireRequest:
    return NominationWireRequest(
        contract_version="mcp-mutation-v2",
        idempotency_key=f"direct-nomination:{basis.value}",
        persona_id=uid(5),
        branch_id=uid(6),
        reason="Exercise conservative direct nomination authority.",
        proposal=NominationProposal(
            subject_id=uid(7),
            subject_kind=SubjectKind.RELATIONSHIP,
            category=category,
            ontological_status=ontology,
            scope=scope,
            visibility=visibility,
            statement="A bounded synthetic observation.",
            reason_to_remember="Verify candidate-only direct nomination behavior.",
            interpretation_limits=("Synthetic fixture only.",),
            confidence=Decimal("0.8"),
            salience=Decimal("0.7"),
            durability=Decimal("0.6"),
            sensitivity=0,
            metadata={},
            selection_basis=basis,
            epistemic_qualifiers=(),
            evidence_references=evidence,
        ),
    )


def policy_outcome(
    command_value: NominationWireRequest,
    context: ResolvedNominationContext,
) -> PolicyOutcome:
    request = SelectionRequest(
        basis=command_value.proposal.selection_basis,
        category=command_value.proposal.category,
        ontological_status=command_value.proposal.ontological_status,
        scope=command_value.proposal.scope,
        visibility=command_value.proposal.visibility,
        effective_authority_class=context.effective_authority_class,
        content_signals=context.content_signals,
        epistemic_qualifiers=frozenset(command_value.proposal.epistemic_qualifiers),
        reason_to_remember=command_value.proposal.reason_to_remember,
        interpretation_limits=command_value.proposal.interpretation_limits,
        evidence=context.evidence,
    )
    return evaluate_selection(request).outcome


async def test_routine_banter_is_a_content_free_deterministic_omit() -> None:
    command_value = command(SelectionBasis.ROUTINE_BANTER)

    resolved = await DirectNominationResolver().resolve(principal(), command_value)

    assert resolved.source_kind == "live_interaction"
    assert resolved.effective_authority_class is AuthorityClass.ASSISTANT_OBSERVATION
    assert resolved.evidence == ()
    assert policy_outcome(command_value, resolved) is PolicyOutcome.OMIT


async def test_assistant_observation_cannot_upgrade_caller_evidence_to_trusted() -> None:
    canary = "OPAQUE-REFERENCE-MUST-NOT-SURVIVE"
    command_value = command(
        SelectionBasis.ASSISTANT_OBSERVATION,
        evidence=(
            NominationEvidenceReference(
                evidence_key="episode:one",
                opaque_reference=canary,
            ),
        ),
    )

    resolved = await DirectNominationResolver().resolve(principal(), command_value)

    assert resolved.content_signals == frozenset()
    assert resolved.evidence == ()
    assert canary not in resolved.model_dump_json()
    assert policy_outcome(command_value, resolved) is PolicyOutcome.REJECT


@pytest.mark.parametrize(
    "basis",
    [
        SelectionBasis.EXPLICIT_USER_CORRECTION,
        SelectionBasis.EXPLICIT_USER_PREFERENCE,
        SelectionBasis.EXPLICIT_USER_PERMISSION,
        SelectionBasis.EXPLICIT_USER_REQUEST,
        SelectionBasis.VERIFIED_PROJECT_DECISION,
        SelectionBasis.IMPORTED_LEGACY,
        SelectionBasis.ASSISTANT_INTERPRETATION,
        SelectionBasis.MEANINGFUL_EPISODIC_ANCHOR,
    ],
)
async def test_untrusted_authority_claims_receive_no_evidence_and_reject(
    basis: SelectionBasis,
) -> None:
    command_value = command(
        basis,
        evidence=(
            NominationEvidenceReference(
                evidence_key="untrusted:one",
                opaque_reference="opaque:untrusted",
            ),
        ),
    )

    resolved = await DirectNominationResolver().resolve(principal(), command_value)

    assert resolved.evidence == ()
    assert policy_outcome(command_value, resolved) is PolicyOutcome.REJECT


@pytest.mark.parametrize(
    ("category", "ontology", "scope", "visibility"),
    [
        (
            MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN,
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            MemoryScope.PERSONA,
            MemoryVisibility.PRIVATE_ROOT,
        ),
        (
            MemoryCategory.RELATIONSHIP_PATTERN,
            OntologicalStatus.HYPOTHESIS,
            MemoryScope.RELATIONSHIP,
            MemoryVisibility.PRIVATE_ROOT,
        ),
        (
            MemoryCategory.RELATIONSHIP_PATTERN,
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            MemoryScope.GLOBAL,
            MemoryVisibility.PRIVATE_ROOT,
        ),
        (
            MemoryCategory.RELATIONSHIP_PATTERN,
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            MemoryScope.RELATIONSHIP,
            MemoryVisibility.SHAREABLE,
        ),
    ],
)
async def test_assistant_observation_outside_candidate_only_shape_rejects(
    category: MemoryCategory,
    ontology: OntologicalStatus,
    scope: MemoryScope,
    visibility: MemoryVisibility,
) -> None:
    command_value = command(
        SelectionBasis.ASSISTANT_OBSERVATION,
        category=category,
        ontology=ontology,
        scope=scope,
        visibility=visibility,
        evidence=(
            NominationEvidenceReference(
                evidence_key="episode:unsafe",
                opaque_reference="opaque:unsafe",
            ),
        ),
    )

    resolved = await DirectNominationResolver().resolve(principal(), command_value)

    assert resolved.evidence == ()
    assert policy_outcome(command_value, resolved) is PolicyOutcome.REJECT
