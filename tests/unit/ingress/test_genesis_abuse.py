"""Synthetic adversarial coverage for the pinned Genesis ingress boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any, cast

import pytest
from kivra_memory.domain.enums import MemoryVisibility
from kivra_memory.ingress.processor import (
    GenesisProcessingResult,
    IngressProcessorError,
    RelationshipBindingStatus,
    process_validated_ingress,
)
from kivra_memory.ingress.snapshot import (
    GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT,
    GENESIS_SOURCE_SNAPSHOT_COMMIT,
    GenesisSnapshotSource,
    GitTreeEntry,
    ImportPlanManifest,
    ManifestError,
    SnapshotError,
    SnapshotSourceItem,
    SourceContract,
    build_import_plan_manifest,
)
from kivra_memory.ingress.validator import (
    FROZEN_FEDERATION_COMPAT_PATH,
    IngressValidationError,
    ValidationCode,
    validate_ingress,
)
from kivra_memory.policy import EpistemicQualifier, SelectionBasis

_SOURCE_PATH = "ingress/checkpoints/v2/genesis/2026/08/synthetic-checkpoint.json"
_V1_SOURCE_PATH = "ingress/checkpoints/v1/genesis/2026/08/synthetic-v1.json"
_GENESIS = "kivra:genesis"
_PERSPECTIVE = "kivra:archivist"
_TRIGGER = "human:requester"


def _blob_sha(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()


@dataclass
class _Reader:
    raw: bytes
    resolved: str = GENESIS_SOURCE_SNAPSHOT_COMMIT
    tree: tuple[GitTreeEntry, ...] = ()
    resolve_calls: list[str] = field(default_factory=list)
    list_calls: list[str] = field(default_factory=list)
    blob_calls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.tree:
            self.tree = (GitTreeEntry(path=_SOURCE_PATH, blob_sha=_blob_sha(self.raw)),)

    def resolve_commit(self, commit: str) -> str:
        self.resolve_calls.append(commit)
        return self.resolved

    def list_tree(self, commit: str) -> tuple[GitTreeEntry, ...]:
        self.list_calls.append(commit)
        return self.tree

    def read_blob(self, blob_sha: str) -> bytes:
        self.blob_calls.append(blob_sha)
        return self.raw


def _item(raw: bytes) -> SnapshotSourceItem:
    return SnapshotSourceItem(
        source_repository="JTM-rootstorm/scalevault-memory-ingress",
        source_snapshot_commit=GENESIS_SOURCE_SNAPSHOT_COMMIT,
        source_path=_SOURCE_PATH,
        source_git_blob_sha=_blob_sha(raw),
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=SourceContract.CHECKPOINT_V2,
        source_id="synthetic-checkpoint",
        raw_bytes=raw,
    )


def _manifest(item: SnapshotSourceItem) -> ImportPlanManifest:
    return build_import_plan_manifest(
        (item,),
        (),
        parser_schema_versions={SourceContract.CHECKPOINT_V2: "genesis-v2"},
        mapping_version="genesis-import-v1",
        selection_policy_version="selection-v1",
        selection_policy_sha256="a" * 64,
    )


def _checkpoint_v2(*, relationship: bool = False) -> dict[str, object]:
    scope = "relationship" if relationship else "persona"
    visibility = "relationship_local" if relationship else "owner_private"
    disposition = "relationship_local" if relationship else "endorse_for_staging"
    participants = [_GENESIS, _PERSPECTIVE] if relationship else []
    relationship_ids = ["relationship:synthetic"] if relationship else []
    return {
        "schema_version": "genesis-checkpoint-v2",
        "checkpoint": {
            "id": "synthetic-checkpoint",
            "origin_actor": _GENESIS,
            "origin_runtime": "synthetic-runtime",
            "triggered_by": _TRIGGER,
            "created_at": "2026-08-08T12:00:00Z",
            "previous_checkpoint": None,
            "status": "staged",
            "idempotency_key": "synthetic-checkpoint-import",
            "source_conversation": {
                "platform": "synthetic",
                "project": None,
                "conversation_reference": None,
                "reviewed_range": "synthetic-range",
                "raw_transcript_preserved_elsewhere": True,
            },
        },
        "candidates": [
            {
                "candidate_id": "candidate:synthetic",
                "type": "relationship_memory" if relationship else "lineage_record",
                "summary": "synthetic summary",
                "disposition": disposition,
                "confidence": "explicit",
                "scope": scope,
                "ontology": "assistant_self_description",
                "why_it_matters": "synthetic reason",
                "binding": {
                    "owner_actor_id": _GENESIS,
                    "perspective_actor_id": _PERSPECTIVE,
                    "subject_actor_ids": [_GENESIS],
                    "participant_actor_ids": participants,
                    "relationship_ids": relationship_ids,
                    "interaction_id": "interaction:synthetic",
                    "visibility": visibility,
                },
                "evidence": {
                    "summary": "synthetic evidence",
                    "source_messages": [
                        {
                            "speaker_actor_id": _GENESIS,
                            "reference": "synthetic:message",
                            "excerpt": None,
                        }
                    ],
                },
                "interpretation_limits": ["synthetic limit"],
                "review": {
                    "eligible_for_scalevault": True,
                    "requires_continuant_review": True,
                    "recommended_action": "review_and_scope",
                },
                "supersedes": ["candidate:prior"],
            }
        ],
        "exclusions": [
            {
                "exclusion_id": "exclusion:synthetic",
                "claim": "synthetic exclusion",
                "reason": "synthetic reason",
                "scope": scope,
                "applies_to_actor_ids": [_GENESIS],
                "applies_to_relationship_ids": relationship_ids,
                "supersedes": ["exclusion:prior"],
            }
        ],
        "notes": ["synthetic only"],
    }


def _checkpoint_v1_relationship() -> dict[str, object]:
    checkpoint = _checkpoint_v2()
    checkpoint["schema_version"] = "genesis-checkpoint-v1"
    checkpoint_value = checkpoint["checkpoint"]
    assert isinstance(checkpoint_value, dict)
    checkpoint_value["id"] = "synthetic-v1"
    candidate = checkpoint["candidates"]
    assert isinstance(candidate, list) and isinstance(candidate[0], dict)
    candidate[0].pop("binding")
    candidate[0]["scope"] = "relationship"
    candidate[0]["type"] = "relationship_memory"
    candidate[0]["disposition"] = "relationship_local"
    evidence = candidate[0]["evidence"]
    assert isinstance(evidence, dict)
    evidence["source_messages"] = [
        {"speaker": "assistant", "reference": "synthetic:message", "excerpt": None}
    ]
    exclusion = checkpoint["exclusions"]
    assert isinstance(exclusion, list) and isinstance(exclusion[0], dict)
    exclusion[0].pop("applies_to_actor_ids")
    exclusion[0].pop("applies_to_relationship_ids")
    return checkpoint


def _federation_compatibility_shaped_payload() -> dict[str, object]:
    """Synthetic special vocabulary; it lacks the authorized raw/blob hashes."""

    payload = _checkpoint_v2()
    checkpoint = cast(dict[str, Any], payload["checkpoint"])
    checkpoint["id"] = FROZEN_FEDERATION_COMPAT_PATH.rsplit("/", 1)[1].removesuffix(".json")
    candidates = cast(list[dict[str, Any]], payload["candidates"])
    special = json.loads(json.dumps(candidates[0]))
    special["candidate_id"] = "candidate-0b388348-39d8-46da-b78c-956dbe1e02e5"
    special["disposition"] = "federation_shared_candidate"
    special["scope"] = "federation"
    special["binding"]["visibility"] = "federation_shared_candidate"
    candidates.append(special)
    exclusions = cast(list[dict[str, Any]], payload["exclusions"])
    exclusions[0]["exclusion_id"] = "exclusion-dca9d34c-7b22-4ce2-885d-e3ba8f1c4f54"
    exclusions[0]["scope"] = "federation"
    extra_exclusion = json.loads(json.dumps(exclusions[0]))
    extra_exclusion["exclusion_id"] = "exclusion-087d1403-46ed-43d3-93e2-14e5bbf3794c"
    exclusions.append(extra_exclusion)
    return payload


def _processed_v2(*, relationship: bool = False) -> GenesisProcessingResult:
    raw = json.dumps(_checkpoint_v2(relationship=relationship), sort_keys=True).encode()
    source = _item(raw)
    validated = validate_ingress(
        raw,
        _SOURCE_PATH,
        known_actor_ids={_GENESIS, _PERSPECTIVE, _TRIGGER},
        relationship_participants=(
            {"relationship:synthetic": {_GENESIS, _PERSPECTIVE}} if relationship else None
        ),
    )
    return process_validated_ingress(validated, source)


def test_snapshot_enumerator_uses_only_literal_authorized_pin_never_post_freeze_commit() -> None:
    reader = _Reader(raw=b'{"synthetic":true}')

    items = GenesisSnapshotSource(reader).enumerate()

    assert len(items) == 1
    assert reader.resolve_calls == [GENESIS_SOURCE_SNAPSHOT_COMMIT]
    assert reader.list_calls == [GENESIS_SOURCE_SNAPSHOT_COMMIT]
    assert GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT not in (
        *reader.resolve_calls,
        *reader.list_calls,
    )


def test_snapshot_rejects_pin_widening_to_post_freeze_authorization_commit() -> None:
    reader = _Reader(raw=b"{}", resolved=GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT)

    with pytest.raises(SnapshotError, match="authorized pin"):
        GenesisSnapshotSource(reader).enumerate()

    assert reader.list_calls == []


def test_snapshot_rejects_blob_bytes_that_do_not_match_pinned_git_object() -> None:
    expected = b'{"synthetic":true}'
    reader = _Reader(
        raw=b'{"synthetic":false}',
        tree=(GitTreeEntry(path=_SOURCE_PATH, blob_sha=_blob_sha(expected)),),
    )

    with pytest.raises(SnapshotError, match="did not match Git provenance"):
        GenesisSnapshotSource(reader).enumerate()


def test_manifest_rejects_local_byte_mutation_even_when_metadata_was_retained() -> None:
    original = _item(b'{"synthetic":true}')
    private_marker = b"synthetic-private-marker"
    mutated = SnapshotSourceItem(
        source_repository=original.source_repository,
        source_snapshot_commit=original.source_snapshot_commit,
        source_path=original.source_path,
        source_git_blob_sha=original.source_git_blob_sha,
        source_raw_sha256=original.source_raw_sha256,
        source_contract=original.source_contract,
        source_id=original.source_id,
        raw_bytes=private_marker,
    )

    with pytest.raises(ManifestError, match="raw bytes") as caught:
        _manifest(mutated)

    assert private_marker.decode() not in str(caught.value)


def test_manifest_digest_changes_for_a_different_derived_plan() -> None:
    item = _item(b'{"synthetic":true}')
    baseline = _manifest(item)
    changed = build_import_plan_manifest(
        (item,),
        (),
        parser_schema_versions={SourceContract.CHECKPOINT_V2: "genesis-v2"},
        mapping_version="genesis-import-v2",
        selection_policy_version="selection-v1",
        selection_policy_sha256="a" * 64,
    )

    assert baseline.digest != changed.digest


def test_triggered_by_is_not_inferred_as_subject_participant_or_relationship_binding() -> None:
    raw = json.dumps(_checkpoint_v2(), sort_keys=True).encode()

    validated = validate_ingress(
        raw,
        _SOURCE_PATH,
        known_actor_ids={_GENESIS, _PERSPECTIVE, _TRIGGER},
    )

    payload = cast(dict[str, Any], validated.payload)
    candidate = cast(list[dict[str, Any]], payload["candidates"])[0]
    assert candidate["binding"]["subject_actor_ids"] == [_GENESIS]
    assert candidate["binding"]["participant_actor_ids"] == []
    assert candidate["binding"]["relationship_ids"] == []
    assert cast(dict[str, Any], payload["checkpoint"])["triggered_by"] == _TRIGGER


def test_validator_preserves_distinct_owner_and_perspective_without_conflation() -> None:
    raw = json.dumps(_checkpoint_v2(), sort_keys=True).encode()

    validated = validate_ingress(
        raw,
        _SOURCE_PATH,
        known_actor_ids={_GENESIS, _PERSPECTIVE, _TRIGGER},
    )

    payload = cast(dict[str, Any], validated.payload)
    candidate = cast(list[dict[str, Any]], payload["candidates"])[0]
    binding = cast(dict[str, Any], candidate["binding"])
    assert binding["owner_actor_id"] == _GENESIS
    assert binding["perspective_actor_id"] == _PERSPECTIVE
    assert binding["owner_actor_id"] != binding["perspective_actor_id"]


def test_v1_relationship_candidate_without_explicit_binding_is_marked_unresolved() -> None:
    raw = json.dumps(_checkpoint_v1_relationship(), sort_keys=True).encode()

    validated = validate_ingress(raw, _V1_SOURCE_PATH)

    assert validated.unresolved_legacy_binding_candidate_ids == ("candidate:synthetic",)


def test_federation_compatibility_vocabulary_rejects_synthetic_or_path_only_replays() -> None:
    payload = _federation_compatibility_shaped_payload()
    raw = json.dumps(payload, sort_keys=True).encode()

    for source_path in (_SOURCE_PATH, FROZEN_FEDERATION_COMPAT_PATH):
        with pytest.raises(IngressValidationError) as caught:
            validate_ingress(raw, source_path)
        assert caught.value.code is ValidationCode.SCHEMA_INVALID
        assert "federation_shared_candidate" not in str(caught.value)


def test_processor_preserves_v2_bindings_exclusions_and_supersession_losslessly() -> None:
    processed = _processed_v2()
    candidate = processed.provenance.candidates[0]
    exclusion = processed.provenance.exclusions[0]

    assert candidate.binding.owner_actor_id == _GENESIS
    assert candidate.binding.perspective_actor_id == _PERSPECTIVE
    assert candidate.binding.subject_actor_ids == (_GENESIS,)
    assert candidate.binding.participant_actor_ids == ()
    assert candidate.binding.interaction_id == "interaction:synthetic"
    assert candidate.supersedes == ("candidate:prior",)
    assert exclusion.exclusion_id == "exclusion:synthetic"
    assert exclusion.applies_to_actor_ids == (_GENESIS,)
    assert exclusion.supersedes == ("exclusion:prior",)


def test_processor_never_widens_relationship_visibility_or_launders_source_confidence() -> None:
    processed = _processed_v2(relationship=True)
    candidate = processed.provenance.candidates[0]
    nomination = processed.nominations[0]

    assert candidate.binding.original_visibility == "relationship_local"
    assert candidate.binding.relationship_ids == ("relationship:synthetic",)
    assert nomination.semantics.visibility is MemoryVisibility.PRIVATE_ROOT
    assert nomination.selection_basis is SelectionBasis.IMPORTED_LEGACY
    assert nomination.epistemic_qualifiers == (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,)
    assert nomination.semantics.confidence == Decimal("0.5")
    assert nomination.semantics.salience == Decimal("0.5")
    assert nomination.semantics.durability == Decimal("0.5")
    assert (
        nomination.review_controls.relationship_binding_status is RelationshipBindingStatus.EXPLICIT
    )
    assert nomination.review_controls.automatic_promotion_allowed is False
    assert nomination.review_controls.promotion_block_reasons == (
        "source_requires_continuant_review",
        "source_exclusions_require_review",
    )


def test_processor_replay_is_deterministic_and_source_byte_mismatch_is_content_free() -> None:
    payload = _checkpoint_v2()
    raw = json.dumps(payload, sort_keys=True).encode()
    source = _item(raw)
    validated = validate_ingress(
        raw,
        _SOURCE_PATH,
        known_actor_ids={_GENESIS, _PERSPECTIVE, _TRIGGER},
    )

    first = process_validated_ingress(validated, source)
    replay = process_validated_ingress(validated, source)

    assert first == replay
    assert first.nominations[0].idempotency_key == replay.nominations[0].idempotency_key

    mismatched = replace(source, raw_bytes=b'{"not":"the validated bytes"}')
    with pytest.raises(IngressProcessorError) as caught:
        process_validated_ingress(validated, mismatched)

    assert str(caught.value) == "validated_source_bytes_mismatch"
    assert "not" not in str(caught.value)
