"""Focused tests for lossless Genesis source-to-nomination conversion."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace

import pytest
from kivra_memory.domain.enums import MemoryCategory, MemoryScope, MemoryVisibility, SubjectKind
from kivra_memory.ingress.processor import (
    AUTHORIZED_SOURCE_REPOSITORY,
    AUTHORIZED_SOURCE_SNAPSHOT,
    GenesisProcessingResult,
    IngressProcessorError,
    RelationshipBindingStatus,
    process_validated_ingress,
)
from kivra_memory.ingress.snapshot import SnapshotSourceItem, SourceContract
from kivra_memory.ingress.validator import validate_ingress
from kivra_memory.policy import EpistemicQualifier, SelectionBasis


def _checkpoint(*, version: int = 2, relationship: bool = True) -> dict[str, object]:
    checkpoint_id = "genesis-checkpoint-20260808T120000-0500-unit"
    candidate: dict[str, object] = {
        "candidate_id": "candidate-unit-001",
        "type": "project_decision" if not relationship else "relationship_memory",
        "summary": "A bounded synthetic candidate.",
        "disposition": "project_local" if not relationship else "relationship_local",
        "confidence": "explicit",
        "scope": "project" if not relationship else "relationship",
        "ontology": "hypothesis" if not relationship else "interaction_convention",
        "why_it_matters": "It exercises the import boundary.",
        "evidence": {
            "summary": "Synthetic evidence.",
            "source_messages": [
                {
                    ("speaker_actor_id" if version == 2 else "speaker"): (
                        "person:mike" if version == 2 else "user"
                    ),
                    "reference": "synthetic-reference",
                    "excerpt": None,
                }
            ],
        },
        "interpretation_limits": ["Do not treat this as endorsed."],
        "review": {
            "eligible_for_scalevault": True,
            "requires_continuant_review": True,
            "recommended_action": (
                "retain_relationship_local" if relationship else "retain_project_decision"
            ),
        },
        "supersedes": ["candidate-earlier"],
    }
    if version == 2:
        candidate["binding"] = {
            "owner_actor_id": "kivra:genesis",
            "perspective_actor_id": "kivra:genesis",
            "subject_actor_ids": ["kivra:genesis", "person:mike"],
            "participant_actor_ids": ["kivra:genesis", "person:mike"],
            "relationship_ids": ["relationship:kivra-genesis:person-mike"],
            "interaction_id": "interaction:synthetic-001",
            "visibility": "relationship_local" if relationship else "project_local",
        }
    exclusion: dict[str, object] = {
        "exclusion_id": "exclusion-unit-001",
        "claim": "A forbidden inference.",
        "reason": "The source does not establish it.",
        "scope": "relationship" if relationship else "project",
        "supersedes": ["exclusion-earlier"],
    }
    if version == 2:
        exclusion.update(
            {
                "applies_to_actor_ids": ["kivra:genesis", "person:mike"],
                "applies_to_relationship_ids": ["relationship:kivra-genesis:person-mike"],
            }
        )
    return {
        "schema_version": f"genesis-checkpoint-v{version}",
        "checkpoint": {
            "id": checkpoint_id,
            "origin_actor": "kivra:genesis",
            "origin_runtime": "chatgpt-web",
            "triggered_by": "person:mike",
            "created_at": "2026-08-08T12:00:00-05:00",
            "previous_checkpoint": "genesis-checkpoint-earlier",
            "status": "staged",
            "idempotency_key": "synthetic:checkpoint:001",
            "source_conversation": {
                "platform": "chatgpt",
                "project": "Synthetic project",
                "conversation_reference": "conversation:synthetic",
                "reviewed_range": "Synthetic bounded range.",
                "raw_transcript_preserved_elsewhere": True,
            },
        },
        "candidates": [candidate],
        "exclusions": [exclusion],
        "notes": ["Synthetic checkpoint."],
    }


def _processed(payload: dict[str, object], *, version: int = 2) -> GenesisProcessingResult:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    checkpoint_id = str(payload["checkpoint"]["id"])  # type: ignore[index]
    source_path = f"ingress/checkpoints/v{version}/genesis/2026/08/{checkpoint_id}.json"
    validated = validate_ingress(raw, source_path)
    blob_sha = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()
    source = SnapshotSourceItem(
        source_repository=AUTHORIZED_SOURCE_REPOSITORY,
        source_snapshot_commit=AUTHORIZED_SOURCE_SNAPSHOT,
        source_path=source_path,
        source_git_blob_sha=blob_sha,
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=(
            SourceContract.CHECKPOINT_V2 if version == 2 else SourceContract.CHECKPOINT_V1
        ),
        source_id=checkpoint_id,
        raw_bytes=raw,
    )
    return process_validated_ingress(validated, source)


def test_v2_mapping_is_lossless_and_uses_unreconciled_policy_posture() -> None:
    result = _processed(_checkpoint())
    candidate = result.provenance.candidates[0]
    binding = candidate.binding
    exclusion = result.provenance.exclusions[0]
    nomination = result.nominations[0]

    assert result.provenance.checkpoint is not None
    assert result.provenance.checkpoint.triggered_by == "person:mike"
    assert binding.owner_actor_id == "kivra:genesis"
    assert binding.perspective_actor_id == "kivra:genesis"
    assert binding.subject_actor_ids == ("kivra:genesis", "person:mike")
    assert binding.participant_actor_ids == ("kivra:genesis", "person:mike")
    assert binding.relationship_ids == ("relationship:kivra-genesis:person-mike",)
    assert binding.interaction_id == "interaction:synthetic-001"
    assert binding.original_visibility == "relationship_local"
    assert candidate.supersedes == ("candidate-earlier",)
    assert exclusion.applies_to_actor_ids == ("kivra:genesis", "person:mike")
    assert exclusion.applies_to_relationship_ids == ("relationship:kivra-genesis:person-mike",)
    assert exclusion.supersedes == ("exclusion-earlier",)
    assert nomination.selection_basis is SelectionBasis.IMPORTED_LEGACY
    assert nomination.epistemic_qualifiers == (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,)
    assert nomination.semantics.visibility is MemoryVisibility.PRIVATE_ROOT
    assert nomination.review_controls.automatic_promotion_allowed is False
    assert nomination.review_controls.relationship_retrieval_allowed is True


def test_source_confidence_and_disposition_do_not_confer_nomination_authority() -> None:
    authoritative_words = _checkpoint(relationship=False)
    conservative_words = deepcopy(authoritative_words)
    conservative_candidate = conservative_words["candidates"][0]  # type: ignore[index]
    conservative_candidate["confidence"] = "uncertain"
    conservative_candidate["disposition"] = "defer"
    conservative_candidate["review"]["recommended_action"] = "defer"
    conservative_candidate["binding"]["visibility"] = "review_only"

    first = _processed(authoritative_words).nominations[0]
    second = _processed(conservative_words).nominations[0]

    assert first.selection_basis == second.selection_basis == SelectionBasis.IMPORTED_LEGACY
    assert first.semantics.confidence == second.semantics.confidence
    assert first.semantics.salience == second.semantics.salience
    assert first.semantics.durability == second.semantics.durability
    assert (
        first.semantics.visibility == second.semantics.visibility == MemoryVisibility.PRIVATE_ROOT
    )


def test_incompatible_source_pair_uses_explicit_safe_fallback_without_source_loss() -> None:
    result = _processed(_checkpoint(relationship=False))

    assert result.provenance.candidates[0].candidate_type == "project_decision"
    assert result.provenance.candidates[0].source_ontology == "hypothesis"
    assert result.nominations[0].semantics.category is MemoryCategory.INTERPRETATION
    assert result.nominations[0].semantics.scope is MemoryScope.PROJECT


def test_scene_local_scope_is_not_broadened_and_remains_symbolic() -> None:
    payload = _checkpoint(relationship=False)
    candidate = payload["candidates"][0]  # type: ignore[index]
    candidate["type"] = "episodic_anchor"
    candidate["scope"] = "scene_local"
    candidate["ontology"] = "fictional_or_roleplayed_scene"

    result = _processed(payload)
    semantics = result.nominations[0].semantics

    assert semantics.scope is MemoryScope.SCENE_LOCAL
    assert semantics.subject.subject_kind is SubjectKind.SCENE
    assert semantics.subject.source_reference == "interaction:synthetic-001"


def test_federation_scope_requires_the_exact_validator_compatibility_marker() -> None:
    payload = _checkpoint(relationship=False)
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    checkpoint_id = str(payload["checkpoint"]["id"])  # type: ignore[index]
    path = f"ingress/checkpoints/v2/genesis/2026/08/{checkpoint_id}.json"
    validated = validate_ingress(raw, path)
    forged_payload = deepcopy(validated.payload)
    forged_candidates = forged_payload["candidates"]
    assert isinstance(forged_candidates, list)
    forged_candidate = forged_candidates[0]
    assert isinstance(forged_candidate, dict)
    forged_candidate["scope"] = "federation"
    forged = replace(validated, payload=forged_payload)
    source = SnapshotSourceItem(
        source_repository=AUTHORIZED_SOURCE_REPOSITORY,
        source_snapshot_commit=AUTHORIZED_SOURCE_SNAPSHOT,
        source_path=path,
        source_git_blob_sha=hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest(),
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=SourceContract.CHECKPOINT_V2,
        source_id=checkpoint_id,
        raw_bytes=raw,
    )

    with pytest.raises(
        IngressProcessorError,
        match="federation_scope_without_compatibility_marker",
    ):
        process_validated_ingress(forged, source)


def test_v1_relationship_binding_remains_unresolved_and_trigger_is_not_inferred() -> None:
    result = _processed(_checkpoint(version=1), version=1)
    binding = result.provenance.candidates[0].binding
    controls = result.nominations[0].review_controls

    assert binding.owner_actor_id == "kivra:genesis"
    assert binding.perspective_actor_id == "kivra:genesis"
    assert binding.subject_actor_ids == ()
    assert binding.participant_actor_ids == ()
    assert binding.relationship_ids == ()
    assert (
        binding.relationship_binding_status is RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
    )
    assert result.nominations[0].semantics.subject.source_reference is None
    assert controls.relationship_retrieval_allowed is False
    assert controls.automatic_promotion_allowed is False


def test_legacy_proposal_is_preserved_without_treating_verified_as_authority() -> None:
    installation_id = "cfcdd788-6eba-4ba7-ab89-27536d8892a1"
    proposal_id = "5ea3ecf3-355e-4ac7-a902-81b09906e09a"
    payload = {
        "schema_version": 1,
        "proposal_id": proposal_id,
        "installation_id": installation_id,
        "idempotency_key": "legacy-proposal-unit",
        "operation": "remember",
        "category": "project_state",
        "scope": "project",
        "statement": "A synthetic legacy project state.",
        "reason_to_remember": "It exercises the legacy proposal mapping.",
        "confidence": "verified",
        "ontology": "literal_technical_fact",
        "interpretation_limits": [],
        "evidence_summary": "",
        "created_at": "2026-08-04T00:55:00Z",
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    path = f"ingress/v1/{installation_id}/2026/08/{proposal_id}.json"
    validated = validate_ingress(raw, path)
    source = SnapshotSourceItem(
        source_repository=AUTHORIZED_SOURCE_REPOSITORY,
        source_snapshot_commit=AUTHORIZED_SOURCE_SNAPSHOT,
        source_path=path,
        source_git_blob_sha=hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest(),
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=SourceContract.PROPOSAL_V1,
        source_id=proposal_id,
        raw_bytes=raw,
    )

    result = process_validated_ingress(validated, source)

    assert result.provenance.proposal is not None
    assert result.provenance.proposal.source_confidence == "verified"
    assert result.provenance.proposal.operation == "remember"
    assert result.nominations[0].selection_basis is SelectionBasis.IMPORTED_LEGACY
    assert result.nominations[0].semantics.confidence == result.nominations[0].semantics.salience
    assert result.nominations[0].review_controls.automatic_promotion_allowed is False


def test_mapping_is_deterministic_and_rejects_source_identity_mismatch() -> None:
    payload = _checkpoint()
    first = _processed(payload)
    second = _processed(payload)
    assert first == second

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    checkpoint_id = str(payload["checkpoint"]["id"])  # type: ignore[index]
    path = f"ingress/checkpoints/v2/genesis/2026/08/{checkpoint_id}.json"
    validated = validate_ingress(raw, path)
    source = SnapshotSourceItem(
        source_repository=AUTHORIZED_SOURCE_REPOSITORY,
        source_snapshot_commit="0" * 40,
        source_path=path,
        source_git_blob_sha="1" * 40,
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=SourceContract.CHECKPOINT_V2,
        source_id=checkpoint_id,
        raw_bytes=raw,
    )
    with pytest.raises(IngressProcessorError, match="source_snapshot_not_authorized"):
        process_validated_ingress(validated, source)
