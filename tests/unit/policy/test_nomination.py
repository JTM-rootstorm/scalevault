from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    EpistemicQualifier,
    NominationEvidenceReference,
    NominationProposal,
    SelectionBasis,
)
from pydantic import ValidationError


def nomination() -> NominationProposal:
    return NominationProposal(
        subject_id=new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=1),
        subject_kind=SubjectKind.PROJECT,
        category=MemoryCategory.PROJECT_DECISION,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement="ScaleVault policy nominations resolve trust server-side.",
        reason_to_remember="This is a durable project decision.",
        interpretation_limits=(),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.9"),
        sensitivity=0,
        observed_at=datetime(2026, 8, 8, 18, 0, tzinfo=UTC),
        metadata={"source": "unit-test"},
        selection_basis=SelectionBasis.VERIFIED_PROJECT_DECISION,
        epistemic_qualifiers=(),
        evidence_references=(
            NominationEvidenceReference(
                evidence_key="project-source:one",
                opaque_reference="repository-object:one",
            ),
        ),
    )


def test_public_nomination_contains_semantics_and_only_opaque_evidence_references() -> None:
    proposal = nomination()

    assert proposal.selection_basis is SelectionBasis.VERIFIED_PROJECT_DECISION
    assert proposal.evidence_references[0].opaque_reference == "repository-object:one"
    fields = type(proposal).model_fields
    assert "effective_authority_class" not in fields
    assert "content_signals" not in fields
    assert "evidence" not in fields


@pytest.mark.parametrize(
    "forbidden",
    ["effective_authority_class", "content_signals", "evidence", "evidence_trust"],
)
def test_public_nomination_rejects_trusted_internal_facts(forbidden: str) -> None:
    document = nomination().model_dump(mode="python")
    document[forbidden] = "caller-asserted"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NominationProposal.model_validate(document)


def test_public_nomination_rejects_duplicate_opaque_evidence_keys() -> None:
    document = nomination().model_dump(mode="python")
    reference = document["evidence_references"][0]
    document["evidence_references"] = (reference, reference)

    with pytest.raises(ValidationError, match="evidence keys must be unique"):
        NominationProposal.model_validate(document)


def test_public_nomination_rejects_duplicate_epistemic_qualifiers() -> None:
    document = nomination().model_dump(mode="python")
    qualifier = EpistemicQualifier.ROLEPLAY_NOT_LITERAL
    document["epistemic_qualifiers"] = (qualifier, qualifier)

    with pytest.raises(ValidationError, match="qualifiers must be unique"):
        NominationProposal.model_validate(document)
