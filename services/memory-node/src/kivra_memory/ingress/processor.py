"""Lossless conversion from validated Genesis ingress to nomination inputs.

This module deliberately stops before canonical identifier resolution and before
calling the selection service.  The Git repository carries symbolic actor,
relationship, project, and interaction identifiers; inventing UUIDs here would
turn transport metadata into canonical authority.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kivra_memory.domain.canonical_json import JsonValue, canonical_json_bytes
from kivra_memory.domain.constraints import CATEGORY_ONTOLOGY_COMPATIBILITY
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.ingress.snapshot import SnapshotSourceItem
from kivra_memory.ingress.validator import ValidatedIngress
from kivra_memory.policy import (
    EpistemicQualifier,
    NominationEvidenceReference,
    SelectionBasis,
)

AUTHORIZED_SOURCE_REPOSITORY = "JTM-rootstorm/scalevault-memory-ingress"
AUTHORIZED_SOURCE_SNAPSHOT = "7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9"
GENESIS_MAPPING_VERSION = "genesis-import-mapping-v1"

_IDEMPOTENCY_DOMAIN = b"scalevault.genesis-import.idempotency.v1\x00"
_NOMINATION_DOMAIN = b"scalevault.genesis-import.nomination.v1\x00"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_OPAQUE_TEXT = Annotated[str, Field(min_length=1, max_length=4096)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class IngressProcessorError(RuntimeError):
    """Safe, content-free conversion failure."""


class RelationshipBindingStatus(StrEnum):
    EXPLICIT = "explicit"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED_LEGACY_BINDING = "unresolved_legacy_binding"


class ImportSourceProvenance(_Contract):
    source_repository: Annotated[str, Field(min_length=1, max_length=255)]
    source_snapshot_commit: Annotated[str, Field(pattern=_GIT_SHA_PATTERN)]
    source_path: Annotated[str, Field(min_length=1, max_length=2048)]
    source_git_blob_sha: Annotated[str, Field(pattern=_GIT_SHA_PATTERN)]
    source_raw_sha256: Annotated[str, Field(pattern=_DIGEST_PATTERN)]
    source_contract: Annotated[str, Field(min_length=1, max_length=128)]
    source_id: Annotated[str, Field(min_length=1, max_length=255)]
    compatibility_codes: Annotated[tuple[str, ...], Field(max_length=8)]
    mapping_version: Literal["genesis-import-mapping-v1"] = "genesis-import-mapping-v1"


class SourceConversationProvenance(_Contract):
    platform: Annotated[str, Field(min_length=1, max_length=128)]
    project: Annotated[str | None, Field(max_length=255)]
    conversation_reference: Annotated[str | None, Field(max_length=2048)]
    reviewed_range: _OPAQUE_TEXT
    raw_transcript_preserved_elsewhere: bool


class CheckpointProvenance(_Contract):
    checkpoint_id: Annotated[str, Field(min_length=1, max_length=255)]
    origin_actor: Annotated[str, Field(min_length=1, max_length=255)]
    origin_runtime: Annotated[str, Field(min_length=1, max_length=255)]
    triggered_by: Annotated[str, Field(min_length=1, max_length=255)]
    created_at: Annotated[str, Field(min_length=1, max_length=64)]
    previous_checkpoint: Annotated[str | None, Field(max_length=255)]
    status: Annotated[str, Field(min_length=1, max_length=64)]
    idempotency_key: Annotated[str, Field(min_length=1, max_length=512)]
    source_conversation: SourceConversationProvenance
    notes: Annotated[tuple[_OPAQUE_TEXT, ...], Field(max_length=32)]


class CandidateBindingProvenance(_Contract):
    owner_actor_id: Annotated[str | None, Field(max_length=255)]
    perspective_actor_id: Annotated[str | None, Field(max_length=255)]
    subject_actor_ids: Annotated[tuple[str, ...], Field(max_length=32)]
    participant_actor_ids: Annotated[tuple[str, ...], Field(max_length=32)]
    relationship_ids: Annotated[tuple[str, ...], Field(max_length=16)]
    interaction_id: Annotated[str | None, Field(max_length=255)]
    original_visibility: Annotated[str | None, Field(max_length=64)]
    relationship_binding_status: RelationshipBindingStatus


class EvidenceMessageProvenance(_Contract):
    speaker_actor_id: Annotated[str | None, Field(max_length=255)] = None
    legacy_speaker: Annotated[str | None, Field(max_length=64)] = None
    reference: Annotated[str, Field(min_length=1, max_length=2048)]
    excerpt: Annotated[str | None, Field(max_length=1024)]

    @model_validator(mode="after")
    def require_exact_speaker_form(self) -> EvidenceMessageProvenance:
        if (self.speaker_actor_id is None) == (self.legacy_speaker is None):
            raise ValueError("evidence message requires exactly one speaker form")
        return self


class CandidateEvidenceProvenance(_Contract):
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    source_messages: Annotated[tuple[EvidenceMessageProvenance, ...], Field(max_length=32)]


class CandidateReviewProvenance(_Contract):
    eligible_for_scalevault: bool
    requires_continuant_review: bool
    recommended_action: Annotated[str, Field(min_length=1, max_length=64)]


class CandidateProvenance(_Contract):
    candidate_id: Annotated[str, Field(min_length=1, max_length=255)]
    candidate_type: Annotated[str, Field(min_length=1, max_length=64)]
    summary: Annotated[str, Field(min_length=1, max_length=8192)]
    disposition: Annotated[str, Field(min_length=1, max_length=64)]
    source_confidence: Annotated[str, Field(min_length=1, max_length=64)]
    source_scope: Annotated[str, Field(min_length=1, max_length=64)]
    source_ontology: Annotated[str, Field(min_length=1, max_length=64)]
    why_it_matters: Annotated[str, Field(min_length=1, max_length=4096)]
    binding: CandidateBindingProvenance
    evidence: CandidateEvidenceProvenance
    interpretation_limits: Annotated[tuple[_OPAQUE_TEXT, ...], Field(max_length=32)]
    review: CandidateReviewProvenance
    supersedes: Annotated[tuple[str, ...], Field(max_length=32)]


class ExclusionProvenance(_Contract):
    exclusion_id: Annotated[str, Field(min_length=1, max_length=255)]
    claim: Annotated[str, Field(min_length=1, max_length=4096)]
    reason: Annotated[str, Field(min_length=1, max_length=4096)]
    scope: Annotated[str, Field(min_length=1, max_length=64)]
    applies_to_actor_ids: Annotated[tuple[str, ...], Field(max_length=32)]
    applies_to_relationship_ids: Annotated[tuple[str, ...], Field(max_length=16)]
    supersedes: Annotated[tuple[str, ...], Field(max_length=32)]


class LegacyProposalProvenance(_Contract):
    schema_version: Literal[1]
    proposal_id: Annotated[str, Field(min_length=1, max_length=255)]
    installation_id: Annotated[str, Field(min_length=1, max_length=255)]
    idempotency_key: Annotated[str, Field(min_length=1, max_length=255)]
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    category: Annotated[str, Field(min_length=1, max_length=64)]
    scope: Annotated[str, Field(min_length=1, max_length=64)]
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: Annotated[str, Field(min_length=1, max_length=4096)]
    source_confidence: Annotated[str, Field(min_length=1, max_length=64)]
    source_ontology: Annotated[str, Field(min_length=1, max_length=64)]
    interpretation_limits: Annotated[tuple[_OPAQUE_TEXT, ...], Field(max_length=32)]
    evidence_summary: Annotated[str, Field(max_length=4096)]
    created_at: Annotated[str, Field(min_length=1, max_length=64)]


class ImportRecordProvenance(_Contract):
    source: ImportSourceProvenance
    checkpoint: CheckpointProvenance | None
    candidates: Annotated[tuple[CandidateProvenance, ...], Field(max_length=64)]
    exclusions: Annotated[tuple[ExclusionProvenance, ...], Field(max_length=64)]
    proposal: LegacyProposalProvenance | None

    @model_validator(mode="after")
    def require_one_source_shape(self) -> ImportRecordProvenance:
        is_proposal = self.proposal is not None
        if is_proposal == (self.checkpoint is not None):
            raise ValueError("import provenance requires exactly one source shape")
        if is_proposal and (self.candidates or self.exclusions):
            raise ValueError("legacy proposal provenance cannot contain checkpoint records")
        return self


class SymbolicSubjectSelector(_Contract):
    """A source reference which only a trusted resolver may bind to a UUID."""

    subject_kind: SubjectKind
    source_reference: Annotated[str | None, Field(max_length=2048)]


class MappedNominationSemantics(_Contract):
    """Canonical-compatible semantics, still lacking canonical identifiers."""

    subject: SymbolicSubjectSelector
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: Literal[MemoryVisibility.PRIVATE_ROOT] = MemoryVisibility.PRIVATE_ROOT
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: Annotated[str, Field(min_length=1, max_length=4096)]
    interpretation_limits: Annotated[tuple[_OPAQUE_TEXT, ...], Field(min_length=1, max_length=32)]
    confidence: Decimal = Decimal("0.5")
    salience: Decimal = Decimal("0.5")
    durability: Decimal = Decimal("0.5")
    sensitivity: Literal[4] = 4

    @model_validator(mode="after")
    def require_compatible_semantics(self) -> MappedNominationSemantics:
        if {self.confidence, self.salience, self.durability} != {Decimal("0.5")}:
            raise ValueError("imported semantic scores must use the conservative mapping")
        if self.ontological_status not in CATEGORY_ONTOLOGY_COMPATIBILITY[self.category]:
            raise ValueError("mapped category and ontology are incompatible")
        expected_kind = {
            MemoryScope.GLOBAL: SubjectKind.GLOBAL,
            MemoryScope.PERSONA: SubjectKind.PERSONA,
            MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
            MemoryScope.PROJECT: SubjectKind.PROJECT,
            MemoryScope.EPISODIC: SubjectKind.EPISODE,
            MemoryScope.SCENE_LOCAL: SubjectKind.SCENE,
        }[self.scope]
        if self.subject.subject_kind is not expected_kind:
            raise ValueError("mapped scope does not match symbolic subject kind")
        return self


class NominationReviewControls(_Contract):
    relationship_binding_status: RelationshipBindingStatus
    relationship_retrieval_allowed: bool
    automatic_promotion_allowed: Literal[False] = False
    promotion_block_reasons: Annotated[tuple[str, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def enforce_unresolved_legacy_holds(self) -> NominationReviewControls:
        unresolved = (
            self.relationship_binding_status is RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
        )
        if unresolved and (self.relationship_retrieval_allowed or self.automatic_promotion_allowed):
            raise ValueError("unresolved legacy bindings must remain held")
        return self


class GenesisNominationInput(_Contract):
    """Lossless, transport-neutral intermediate consumed by the trusted import service."""

    contract_version: Literal["scalevault-genesis-nomination-v1"]
    idempotency_key: Annotated[str, Field(pattern=r"^genesis-import-v1:[0-9a-f]{64}$")]
    nomination_sha256: Annotated[str, Field(pattern=_DIGEST_PATTERN)]
    source_record_id: Annotated[str, Field(min_length=1, max_length=255)]
    semantics: MappedNominationSemantics
    selection_basis: Literal[SelectionBasis.IMPORTED_LEGACY] = SelectionBasis.IMPORTED_LEGACY
    epistemic_qualifiers: tuple[EpistemicQualifier, ...] = (
        EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,
    )
    evidence_references: tuple[NominationEvidenceReference, ...]
    review_controls: NominationReviewControls

    @model_validator(mode="after")
    def enforce_imported_policy_posture(self) -> GenesisNominationInput:
        if self.epistemic_qualifiers != (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,):
            raise ValueError("Genesis nominations require the unreconciled qualifier")
        return self


class GenesisProcessingResult(_Contract):
    contract_version: Literal["scalevault-genesis-processor-result-v1"]
    provenance: ImportRecordProvenance
    nominations: Annotated[tuple[GenesisNominationInput, ...], Field(max_length=64)]


_TYPE_CATEGORY = {
    "identity_observation": MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN,
    "lineage_record": MemoryCategory.INTERPRETATION,
    "relationship_memory": MemoryCategory.RELATIONSHIP_PATTERN,
    "relationship_state": MemoryCategory.RELATIONSHIP_PATTERN,
    "interaction_convention": MemoryCategory.INTERACTION_CONVENTION,
    "boundary_or_permission": MemoryCategory.BOUNDARY_OR_PERMISSION,
    "episodic_anchor": MemoryCategory.EPISODIC_ANCHOR,
    "project_decision": MemoryCategory.PROJECT_DECISION,
    "project_state": MemoryCategory.PROJECT_STATE,
    "procedure": MemoryCategory.PROCEDURE,
    "open_question": MemoryCategory.OPEN_QUESTION,
    "emergent_tendency": MemoryCategory.EMERGENT_TENDENCY,
    "external_fact": MemoryCategory.EXTERNAL_FACT,
    "interpretation": MemoryCategory.INTERPRETATION,
}


def _string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str):
        raise IngressProcessorError(f"invalid_validated_{field}")
    return value


def _optional_string(value: JsonValue, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _object(value: JsonValue, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise IngressProcessorError(f"invalid_validated_{field}")
    return value


def _array(value: JsonValue, field: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise IngressProcessorError(f"invalid_validated_{field}")
    return value


def _strings(value: JsonValue, field: str) -> tuple[str, ...]:
    return tuple(_string(item, field) for item in _array(value, field))


def _enum_value(value: object) -> str:
    member = getattr(value, "value", value)
    if not isinstance(member, str):
        raise IngressProcessorError("invalid_validated_source_contract")
    return member


def _source_provenance(
    source: SnapshotSourceItem,
    compatibility_codes: Sequence[object],
) -> ImportSourceProvenance:
    if source.source_repository != AUTHORIZED_SOURCE_REPOSITORY:
        raise IngressProcessorError("source_repository_not_authorized")
    if source.source_snapshot_commit != AUTHORIZED_SOURCE_SNAPSHOT:
        raise IngressProcessorError("source_snapshot_not_authorized")
    if hashlib.sha256(source.raw_bytes).hexdigest() != source.source_raw_sha256:
        raise IngressProcessorError("source_raw_sha256_mismatch")
    actual_blob_sha = hashlib.sha1(
        f"blob {len(source.raw_bytes)}\0".encode() + source.raw_bytes,
        usedforsecurity=False,
    ).hexdigest()
    if actual_blob_sha != source.source_git_blob_sha:
        raise IngressProcessorError("source_git_blob_sha_mismatch")
    return ImportSourceProvenance(
        source_repository=source.source_repository,
        source_snapshot_commit=source.source_snapshot_commit,
        source_path=source.source_path,
        source_git_blob_sha=source.source_git_blob_sha,
        source_raw_sha256=source.source_raw_sha256,
        source_contract=_enum_value(source.source_contract),
        source_id=source.source_id,
        compatibility_codes=tuple(_enum_value(code) for code in compatibility_codes),
    )


def _checkpoint(value: Mapping[str, JsonValue], notes: JsonValue) -> CheckpointProvenance:
    conversation = _object(value["source_conversation"], "source_conversation")
    return CheckpointProvenance(
        checkpoint_id=_string(value["id"], "checkpoint_id"),
        origin_actor=_string(value["origin_actor"], "origin_actor"),
        origin_runtime=_string(value["origin_runtime"], "origin_runtime"),
        triggered_by=_string(value["triggered_by"], "triggered_by"),
        created_at=_string(value["created_at"], "created_at"),
        previous_checkpoint=_optional_string(value["previous_checkpoint"], "previous_checkpoint"),
        status=_string(value["status"], "status"),
        idempotency_key=_string(value["idempotency_key"], "checkpoint_idempotency_key"),
        source_conversation=SourceConversationProvenance(
            platform=_string(conversation["platform"], "source_platform"),
            project=_optional_string(conversation["project"], "source_project"),
            conversation_reference=_optional_string(
                conversation["conversation_reference"], "conversation_reference"
            ),
            reviewed_range=_string(conversation["reviewed_range"], "reviewed_range"),
            raw_transcript_preserved_elsewhere=cast(
                bool, conversation["raw_transcript_preserved_elsewhere"]
            ),
        ),
        notes=_strings(notes, "notes"),
    )


def _binding(
    candidate: Mapping[str, JsonValue],
    *,
    origin_actor: str,
    unresolved: bool,
) -> CandidateBindingProvenance:
    raw = candidate.get("binding")
    if raw is None:
        return CandidateBindingProvenance(
            owner_actor_id=origin_actor,
            perspective_actor_id=origin_actor,
            subject_actor_ids=(),
            participant_actor_ids=(),
            relationship_ids=(),
            interaction_id=None,
            original_visibility=None,
            relationship_binding_status=(
                RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
                if unresolved
                else RelationshipBindingStatus.NOT_APPLICABLE
            ),
        )
    value = _object(raw, "binding")
    return CandidateBindingProvenance(
        owner_actor_id=_string(value["owner_actor_id"], "owner_actor_id"),
        perspective_actor_id=_string(value["perspective_actor_id"], "perspective_actor_id"),
        subject_actor_ids=_strings(value["subject_actor_ids"], "subject_actor_ids"),
        participant_actor_ids=_strings(value["participant_actor_ids"], "participant_actor_ids"),
        relationship_ids=_strings(value["relationship_ids"], "relationship_ids"),
        interaction_id=_optional_string(value["interaction_id"], "interaction_id"),
        original_visibility=_string(value["visibility"], "visibility"),
        relationship_binding_status=(
            RelationshipBindingStatus.EXPLICIT
            if _strings(value["relationship_ids"], "relationship_ids")
            else RelationshipBindingStatus.NOT_APPLICABLE
        ),
    )


def _evidence(value: JsonValue) -> CandidateEvidenceProvenance:
    evidence = _object(value, "evidence")
    messages: list[EvidenceMessageProvenance] = []
    for raw_message in _array(evidence["source_messages"], "source_messages"):
        message = _object(raw_message, "source_message")
        if "speaker_actor_id" in message:
            messages.append(
                EvidenceMessageProvenance(
                    speaker_actor_id=_string(message["speaker_actor_id"], "speaker_actor_id"),
                    reference=_string(message["reference"], "evidence_reference"),
                    excerpt=_optional_string(message["excerpt"], "evidence_excerpt"),
                )
            )
        else:
            messages.append(
                EvidenceMessageProvenance(
                    legacy_speaker=_string(message["speaker"], "legacy_speaker"),
                    reference=_string(message["reference"], "evidence_reference"),
                    excerpt=_optional_string(message["excerpt"], "evidence_excerpt"),
                )
            )
    return CandidateEvidenceProvenance(
        summary=_string(evidence["summary"], "evidence_summary"),
        source_messages=tuple(messages),
    )


def _candidate(
    value: Mapping[str, JsonValue],
    *,
    origin_actor: str,
    unresolved_ids: frozenset[str],
) -> CandidateProvenance:
    candidate_id = _string(value["candidate_id"], "candidate_id")
    review = _object(value["review"], "review")
    return CandidateProvenance(
        candidate_id=candidate_id,
        candidate_type=_string(value["type"], "candidate_type"),
        summary=_string(value["summary"], "summary"),
        disposition=_string(value["disposition"], "disposition"),
        source_confidence=_string(value["confidence"], "confidence"),
        source_scope=_string(value["scope"], "scope"),
        source_ontology=_string(value["ontology"], "ontology"),
        why_it_matters=_string(value["why_it_matters"], "why_it_matters"),
        binding=_binding(
            value,
            origin_actor=origin_actor,
            unresolved=candidate_id in unresolved_ids,
        ),
        evidence=_evidence(value["evidence"]),
        interpretation_limits=_strings(value["interpretation_limits"], "interpretation_limits"),
        review=CandidateReviewProvenance(
            eligible_for_scalevault=cast(bool, review["eligible_for_scalevault"]),
            requires_continuant_review=cast(bool, review["requires_continuant_review"]),
            recommended_action=_string(review["recommended_action"], "recommended_action"),
        ),
        supersedes=_strings(value["supersedes"], "supersedes"),
    )


def _exclusion(value: Mapping[str, JsonValue], *, is_v2: bool) -> ExclusionProvenance:
    return ExclusionProvenance(
        exclusion_id=_string(value["exclusion_id"], "exclusion_id"),
        claim=_string(value["claim"], "exclusion_claim"),
        reason=_string(value["reason"], "exclusion_reason"),
        scope=_string(value["scope"], "exclusion_scope"),
        applies_to_actor_ids=(
            _strings(value["applies_to_actor_ids"], "exclusion_actor_ids") if is_v2 else ()
        ),
        applies_to_relationship_ids=(
            _strings(value["applies_to_relationship_ids"], "exclusion_relationship_ids")
            if is_v2
            else ()
        ),
        supersedes=_strings(value["supersedes"], "exclusion_supersedes"),
    )


def _safe_category(candidate_type: str, ontology: OntologicalStatus) -> MemoryCategory:
    preferred = _TYPE_CATEGORY.get(candidate_type)
    if preferred is None:
        raise IngressProcessorError("candidate_type_not_mappable")
    if ontology in CATEGORY_ONTOLOGY_COMPATIBILITY[preferred]:
        return preferred
    fallbacks = {
        OntologicalStatus.LITERAL_USER_FACT: MemoryCategory.STABLE_FACT,
        OntologicalStatus.LITERAL_TECHNICAL_FACT: MemoryCategory.STABLE_FACT,
        OntologicalStatus.ASSISTANT_SELF_DESCRIPTION: (
            MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN
        ),
        OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR: MemoryCategory.EMERGENT_TENDENCY,
        OntologicalStatus.INTERACTION_CONVENTION: MemoryCategory.INTERACTION_CONVENTION,
        OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE: MemoryCategory.EPISODIC_ANCHOR,
        OntologicalStatus.HYPOTHESIS: MemoryCategory.INTERPRETATION,
        OntologicalStatus.UNCERTAIN: MemoryCategory.INTERPRETATION,
    }
    return fallbacks[ontology]


def _mapped_scope(
    source_scope: str,
    *,
    compatibility_codes: Sequence[str],
) -> MemoryScope:
    if source_scope == "federation":
        if "frozen_federation_vocabulary" not in compatibility_codes:
            raise IngressProcessorError("federation_scope_without_compatibility_marker")
        return MemoryScope.PERSONA
    if source_scope == "lineage":
        return MemoryScope.PERSONA
    try:
        return MemoryScope(source_scope)
    except ValueError:
        raise IngressProcessorError("source_scope_not_mappable") from None


def _subject(
    scope: MemoryScope,
    binding: CandidateBindingProvenance,
    *,
    candidate_id: str,
    project_reference: str | None,
) -> SymbolicSubjectSelector:
    if scope is MemoryScope.GLOBAL:
        return SymbolicSubjectSelector(subject_kind=SubjectKind.GLOBAL, source_reference="global")
    if scope is MemoryScope.PERSONA:
        return SymbolicSubjectSelector(
            subject_kind=SubjectKind.PERSONA, source_reference=binding.owner_actor_id
        )
    if scope is MemoryScope.RELATIONSHIP:
        reference = binding.relationship_ids[0] if binding.relationship_ids else None
        return SymbolicSubjectSelector(
            subject_kind=SubjectKind.RELATIONSHIP, source_reference=reference
        )
    if scope is MemoryScope.PROJECT:
        return SymbolicSubjectSelector(
            subject_kind=SubjectKind.PROJECT, source_reference=project_reference
        )
    if scope is MemoryScope.EPISODIC:
        return SymbolicSubjectSelector(
            subject_kind=SubjectKind.EPISODE,
            source_reference=binding.interaction_id or candidate_id,
        )
    if scope is MemoryScope.SCENE_LOCAL:
        return SymbolicSubjectSelector(
            subject_kind=SubjectKind.SCENE,
            source_reference=binding.interaction_id or candidate_id,
        )
    raise IngressProcessorError("source_scope_not_mappable")


def _limits(values: tuple[str, ...]) -> tuple[str, ...]:
    if values:
        return values
    return ("Imported source remains unreconciled and requires authorized review.",)


def _evidence_reference(source: ImportSourceProvenance) -> tuple[NominationEvidenceReference, ...]:
    return (
        NominationEvidenceReference(
            evidence_key=f"import-manifest:{source.source_raw_sha256}",
            opaque_reference=(
                f"genesis-import:{source.source_snapshot_commit}:"
                f"{source.source_raw_sha256}:{source.source_id}"
            ),
        ),
    )


def _nomination(
    *,
    source: ImportSourceProvenance,
    candidate: CandidateProvenance,
    exclusions: Sequence[ExclusionProvenance],
    project_reference: str | None,
) -> GenesisNominationInput:
    try:
        ontology = OntologicalStatus(candidate.source_ontology)
    except ValueError:
        raise IngressProcessorError("source_ontology_not_mappable") from None
    scope = _mapped_scope(
        candidate.source_scope,
        compatibility_codes=source.compatibility_codes,
    )
    semantics = MappedNominationSemantics(
        subject=_subject(
            scope,
            candidate.binding,
            candidate_id=candidate.candidate_id,
            project_reference=project_reference,
        ),
        category=_safe_category(candidate.candidate_type, ontology),
        ontological_status=ontology,
        scope=scope,
        statement=candidate.summary,
        reason_to_remember=candidate.why_it_matters,
        interpretation_limits=_limits(candidate.interpretation_limits),
    )
    unresolved = (
        candidate.binding.relationship_binding_status
        is RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
    )
    reasons = tuple(
        reason
        for reason, applies in (
            ("source_requires_continuant_review", candidate.review.requires_continuant_review),
            ("unresolved_legacy_binding", unresolved),
            ("source_exclusions_require_review", bool(exclusions)),
        )
        if applies
    )
    material = {
        "mapping_version": GENESIS_MAPPING_VERSION,
        "source_repository": source.source_repository,
        "source_snapshot_commit": source.source_snapshot_commit,
        "source_path": source.source_path,
        "source_raw_sha256": source.source_raw_sha256,
        "source_record_id": candidate.candidate_id,
        "semantics": semantics.model_dump(mode="python"),
        "selection_basis": SelectionBasis.IMPORTED_LEGACY,
        "epistemic_qualifiers": (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
    }
    idempotency_sha = hashlib.sha256(
        _IDEMPOTENCY_DOMAIN + canonical_json_bytes(material)
    ).hexdigest()
    nomination_sha = hashlib.sha256(_NOMINATION_DOMAIN + canonical_json_bytes(material)).hexdigest()
    return GenesisNominationInput(
        contract_version="scalevault-genesis-nomination-v1",
        idempotency_key=f"genesis-import-v1:{idempotency_sha}",
        nomination_sha256=nomination_sha,
        source_record_id=candidate.candidate_id,
        semantics=semantics,
        evidence_references=_evidence_reference(source),
        review_controls=NominationReviewControls(
            relationship_binding_status=candidate.binding.relationship_binding_status,
            relationship_retrieval_allowed=not unresolved,
            automatic_promotion_allowed=False,
            promotion_block_reasons=reasons,
        ),
    )


def _legacy_proposal(payload: Mapping[str, JsonValue]) -> LegacyProposalProvenance:
    schema_version = payload["schema_version"]
    if isinstance(schema_version, bool) or schema_version != 1:
        raise IngressProcessorError("invalid_validated_schema_version")
    return LegacyProposalProvenance(
        schema_version=1,
        proposal_id=_string(payload["proposal_id"], "proposal_id"),
        installation_id=_string(payload["installation_id"], "installation_id"),
        idempotency_key=_string(payload["idempotency_key"], "proposal_idempotency_key"),
        operation=_string(payload["operation"], "operation"),
        category=_string(payload["category"], "category"),
        scope=_string(payload["scope"], "scope"),
        statement=_string(payload["statement"], "statement"),
        reason_to_remember=_string(payload["reason_to_remember"], "reason_to_remember"),
        source_confidence=_string(payload["confidence"], "confidence"),
        source_ontology=_string(payload["ontology"], "ontology"),
        interpretation_limits=_strings(payload["interpretation_limits"], "interpretation_limits"),
        evidence_summary=_string(payload["evidence_summary"], "evidence_summary"),
        created_at=_string(payload["created_at"], "created_at"),
    )


def _proposal_candidate(proposal: LegacyProposalProvenance) -> CandidateProvenance:
    return CandidateProvenance(
        candidate_id=proposal.proposal_id,
        candidate_type=proposal.category,
        summary=proposal.statement,
        disposition=proposal.operation,
        source_confidence=proposal.source_confidence,
        source_scope=proposal.scope,
        source_ontology=proposal.source_ontology,
        why_it_matters=proposal.reason_to_remember,
        binding=CandidateBindingProvenance(
            owner_actor_id=None,
            perspective_actor_id=None,
            subject_actor_ids=(),
            participant_actor_ids=(),
            relationship_ids=(),
            interaction_id=None,
            original_visibility=None,
            relationship_binding_status=(
                RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
                if proposal.scope == "relationship"
                else RelationshipBindingStatus.NOT_APPLICABLE
            ),
        ),
        evidence=CandidateEvidenceProvenance(
            summary=proposal.evidence_summary or "Legacy proposal evidence summary was empty.",
            source_messages=(),
        ),
        interpretation_limits=proposal.interpretation_limits,
        review=CandidateReviewProvenance(
            eligible_for_scalevault=True,
            requires_continuant_review=True,
            recommended_action="review_and_scope",
        ),
        supersedes=(),
    )


def process_validated_ingress(
    validated: ValidatedIngress,
    source_item: SnapshotSourceItem,
) -> GenesisProcessingResult:
    """Map one validated, pinned source item without applying canonical state."""

    if (
        validated.source_path != source_item.source_path
        or validated.source_id != source_item.source_id
    ):
        raise IngressProcessorError("validated_source_identity_mismatch")
    if validated.raw_bytes != source_item.raw_bytes:
        raise IngressProcessorError("validated_source_bytes_mismatch")
    source = _source_provenance(source_item, validated.compatibility_codes)
    payload = validated.payload
    format_value = _enum_value(validated.format)

    if format_value in {"proposal_v1", "proposal-v1", "scalevault.ingress.proposal.v1"}:
        if source.source_contract != "scalevault.ingress.proposal.v1":
            raise IngressProcessorError("validated_source_contract_mismatch")
        proposal = _legacy_proposal(payload)
        derived = _proposal_candidate(proposal)
        provenance = ImportRecordProvenance(
            source=source,
            checkpoint=None,
            candidates=(),
            exclusions=(),
            proposal=proposal,
        )
        return GenesisProcessingResult(
            contract_version="scalevault-genesis-processor-result-v1",
            provenance=provenance,
            nominations=(
                _nomination(
                    source=source,
                    candidate=derived,
                    exclusions=(),
                    project_reference=None,
                ),
            ),
        )

    is_v2 = format_value in {
        "genesis_checkpoint_v2",
        "genesis-checkpoint-v2",
        "scalevault.ingress.genesis-checkpoint.v2",
    }
    if not is_v2 and format_value not in {
        "genesis_checkpoint_v1",
        "genesis-checkpoint-v1",
        "scalevault.ingress.genesis-checkpoint.v1",
    }:
        raise IngressProcessorError("validated_format_not_supported")
    expected_contract = (
        "scalevault.ingress.genesis-checkpoint.v2"
        if is_v2
        else "scalevault.ingress.genesis-checkpoint.v1"
    )
    if source.source_contract != expected_contract:
        raise IngressProcessorError("validated_source_contract_mismatch")
    raw_checkpoint = _object(payload["checkpoint"], "checkpoint")
    checkpoint = _checkpoint(raw_checkpoint, payload["notes"])
    unresolved_ids = frozenset(validated.unresolved_legacy_binding_candidate_ids)
    candidates = tuple(
        _candidate(
            _object(item, "candidate"),
            origin_actor=checkpoint.origin_actor,
            unresolved_ids=unresolved_ids,
        )
        for item in _array(payload["candidates"], "candidates")
    )
    exclusions = tuple(
        _exclusion(_object(item, "exclusion"), is_v2=is_v2)
        for item in _array(payload["exclusions"], "exclusions")
    )
    provenance = ImportRecordProvenance(
        source=source,
        checkpoint=checkpoint,
        candidates=candidates,
        exclusions=exclusions,
        proposal=None,
    )
    return GenesisProcessingResult(
        contract_version="scalevault-genesis-processor-result-v1",
        provenance=provenance,
        nominations=tuple(
            _nomination(
                source=source,
                candidate=candidate,
                exclusions=exclusions,
                project_reference=checkpoint.source_conversation.project,
            )
            for candidate in candidates
        ),
    )


__all__ = [
    "AUTHORIZED_SOURCE_REPOSITORY",
    "AUTHORIZED_SOURCE_SNAPSHOT",
    "GENESIS_MAPPING_VERSION",
    "CandidateProvenance",
    "ExclusionProvenance",
    "GenesisNominationInput",
    "GenesisProcessingResult",
    "ImportRecordProvenance",
    "IngressProcessorError",
    "RelationshipBindingStatus",
    "process_validated_ingress",
]
