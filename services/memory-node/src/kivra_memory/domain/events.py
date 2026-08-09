"""Versioned immutable domain-event contracts.

The models in this module describe accepted semantic facts.  They deliberately
contain complete after-images so replay never depends on current policy,
defaults, clocks, identifier generators, or external services.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from typing import Annotated, ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kivra_memory.domain.canonical_json import canonical_json_bytes, normalize_json_value
from kivra_memory.domain.constraints import validate_category_ontology
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import UnitScore, normalize_utc_datetime

HexDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CanonicalBase64 = Annotated[
    str, Field(pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
]
SafePositiveInteger = Annotated[int, Field(ge=1, le=(1 << 53) - 1)]
PositiveRevision = SafePositiveInteger


class EventContractError(ValueError):
    """An immutable event does not satisfy the accepted event contract."""


def _utc(value: datetime, field_name: str) -> datetime:
    try:
        return normalize_utc_datetime(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be timezone-aware") from error


def _uuid7(value: UUID | None, field_name: str) -> UUID | None:
    if value is not None:
        require_uuid7(value, field_name=field_name)
    return value


class ContractModel(BaseModel):
    """Strict, immutable base for payload and after-image models."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    def canonical_value(self) -> object:
        return normalize_json_value(self.model_dump(mode="python"))


class MemoryState(ContractModel):
    """Complete canonical memory projection after an event."""

    memory_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    subject_id: UUID
    subject_kind: SubjectKind
    revision: PositiveRevision
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    status: MemoryStatus
    statement: Annotated[str | None, Field(max_length=8192)]
    reason_to_remember: Annotated[str | None, Field(max_length=4096)]
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...], Field(max_length=32)
    ]
    confidence: UnitScore
    salience: UnitScore
    durability: UnitScore
    sensitivity: Annotated[int, Field(ge=0, le=4)]
    authority_class: AuthorityClass
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    observed_at: datetime | None = None
    origin_session_id: UUID | None = None
    publication_approved_at: datetime | None = None
    publication_approved_by_actor_id: UUID | None = None
    content_protection: Literal["plaintext", "envelope_encrypted", "cryptographically_erased"]
    content_key_id: UUID | None = None
    created_at: datetime
    updated_at: datetime
    fingerprint_version: SafePositiveInteger
    normalized_fingerprint: HexDigest | None
    metadata: dict[str, object]

    @field_validator(
        "memory_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "subject_id",
        "origin_session_id",
        "publication_approved_by_actor_id",
        "content_key_id",
    )
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        field_name = getattr(info, "field_name", "identifier")
        return _uuid7(value, str(field_name))

    @field_validator(
        "valid_from",
        "valid_to",
        "observed_at",
        "publication_approved_at",
        "created_at",
        "updated_at",
    )
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        return _utc(value, str(getattr(info, "field_name", "datetime")))

    @model_validator(mode="after")
    def validate_state_shape(self) -> MemoryState:
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("valid_to must not precede valid_from")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        validate_category_ontology(self.category, self.ontological_status)
        expected_subject = {
            MemoryScope.GLOBAL: SubjectKind.GLOBAL,
            MemoryScope.PERSONA: SubjectKind.PERSONA,
            MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
            MemoryScope.PROJECT: SubjectKind.PROJECT,
            MemoryScope.EPISODIC: SubjectKind.EPISODE,
            MemoryScope.SCENE_LOCAL: SubjectKind.SCENE,
        }[self.scope]
        if self.subject_kind is not expected_subject:
            raise ValueError("memory scope does not match subject kind")
        if (
            self.scope is MemoryScope.GLOBAL
            and self.ontological_status is OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE
        ):
            raise ValueError("global memory cannot represent a roleplayed scene")
        if (
            self.scope is MemoryScope.EPISODIC
            and self.origin_session_id is None
            and self.authority_class is not AuthorityClass.IMPORTED_LEGACY_MEMORY
        ):
            raise ValueError("episodic memory requires an origin session or imported provenance")
        if self.scope is MemoryScope.SCENE_LOCAL:
            if self.origin_session_id is None:
                raise ValueError("scene-local memory requires an origin session")
            if self.visibility in {MemoryVisibility.SHAREABLE, MemoryVisibility.PUBLIC_SEED}:
                raise ValueError("scene-local visibility exceeds its structural boundary")
        if self.visibility is MemoryVisibility.PUBLIC_SEED:
            if self.status is not MemoryStatus.ACTIVE or self.sensitivity != 0:
                raise ValueError("public-seed memory must be active and non-sensitive")
            if self.publication_approved_at is None:
                raise ValueError("public-seed memory requires publication approval")
        if self.visibility is MemoryVisibility.SHAREABLE and self.sensitivity > 1:
            raise ValueError("shareable memory sensitivity cannot exceed one")
        tombstoned = self.status == MemoryStatus.TOMBSTONED
        if tombstoned:
            if self.statement is not None or self.reason_to_remember is not None:
                raise ValueError("tombstoned memory content must be sanitized")
            if self.interpretation_limits or self.normalized_fingerprint is not None:
                raise ValueError("tombstoned memory derivatives must be sanitized")
        elif not self.statement or not self.reason_to_remember:
            raise ValueError("non-tombstoned memories require statement and reason")
        if (self.publication_approved_at is None) != (
            self.publication_approved_by_actor_id is None
        ):
            raise ValueError("publication approval time and actor must be supplied together")
        if self.content_protection == "plaintext" and self.content_key_id is not None:
            raise ValueError("plaintext memory cannot reference a content key")
        if self.content_protection != "plaintext" and self.content_key_id is None:
            raise ValueError("protected memory requires content-key metadata")
        if self.content_protection == "cryptographically_erased" and not tombstoned:
            raise ValueError("cryptographic erasure requires a tombstoned memory")
        if len(self.interpretation_limits) > 32 or len(set(self.interpretation_limits)) != len(
            self.interpretation_limits
        ):
            raise ValueError("interpretation limits must contain at most 32 unique entries")
        if len(self.metadata) > 128:
            raise ValueError("memory metadata cannot exceed 128 properties")
        return self


class MemoryStateV2(MemoryState):
    """V2 after-image carrying a candidate expiry deadline.

    Keeping this field out of :class:`MemoryState` preserves the exact canonical
    bytes of accepted v1 events. New candidate lifecycle events use payload v2.
    """

    candidate_expires_at: datetime | None

    @field_validator("candidate_expires_at")
    @classmethod
    def normalize_candidate_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc(value, "candidate_expires_at")

    @model_validator(mode="after")
    def validate_candidate_expiry(self) -> MemoryStateV2:
        if self.status is MemoryStatus.CANDIDATE:
            if self.candidate_expires_at is None:
                raise ValueError("candidate memories require an expiry deadline in v2")
            if self.candidate_expires_at <= self.created_at:
                raise ValueError("candidate expiry deadline must follow memory creation")
        elif self.candidate_expires_at is not None:
            raise ValueError("only candidate memories may have a candidate expiry deadline")
        return self


class SealedContentEnvelopeState(ContractModel):
    """Canonical JSON-boundary form of one authenticated sealed envelope."""

    contract_version: Literal["scalevault.sealed-content-envelope.v1"]
    envelope_version: Literal[1]
    algorithm: Literal["AES-256-GCM"]
    content_key_id: UUID
    nonce: CanonicalBase64
    ciphertext: CanonicalBase64
    aad_sha256: HexDigest
    safe_summary: Annotated[str, Field(min_length=1, max_length=1024)]

    @field_validator("content_key_id")
    @classmethod
    def validate_content_key_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "content_key_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_envelope_bounds(self) -> SealedContentEnvelopeState:
        try:
            nonce = base64.b64decode(self.nonce, validate=True)
            ciphertext = base64.b64decode(self.ciphertext, validate=True)
        except ValueError as error:
            raise ValueError("sealed envelope encoding is invalid") from error
        if base64.b64encode(nonce).decode("ascii") != self.nonce or len(nonce) != 12:
            raise ValueError("sealed envelope nonce is invalid")
        if (
            base64.b64encode(ciphertext).decode("ascii") != self.ciphertext
            or not 17 <= len(ciphertext) <= 716_816
        ):
            raise ValueError("sealed envelope ciphertext is invalid")
        if not self.safe_summary.strip() or len(self.safe_summary.encode("utf-8")) > 4096:
            raise ValueError("sealed envelope safe summary is invalid")
        return self


class MemoryStateV3(MemoryStateV2):
    """Sealed-only v3 after-image with no plaintext semantic content."""

    statement: None
    reason_to_remember: None
    interpretation_limits: tuple[()] = ()
    normalized_fingerprint: None
    content_protection: Literal["envelope_encrypted", "cryptographically_erased"]
    content_key_id: UUID
    sealed_content: SealedContentEnvelopeState

    @model_validator(mode="after")
    def validate_state_shape(self) -> MemoryStateV3:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("valid_to must not precede valid_from")
        validate_category_ontology(self.category, self.ontological_status)
        expected_subject = {
            MemoryScope.GLOBAL: SubjectKind.GLOBAL,
            MemoryScope.PERSONA: SubjectKind.PERSONA,
            MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
            MemoryScope.PROJECT: SubjectKind.PROJECT,
            MemoryScope.EPISODIC: SubjectKind.EPISODE,
            MemoryScope.SCENE_LOCAL: SubjectKind.SCENE,
        }[self.scope]
        if self.subject_kind is not expected_subject:
            raise ValueError("memory scope does not match subject kind")
        if (
            self.scope is MemoryScope.GLOBAL
            and self.ontological_status is OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE
        ):
            raise ValueError("global memory cannot represent a roleplayed scene")
        if (
            self.scope is MemoryScope.EPISODIC
            and self.origin_session_id is None
            and self.authority_class is not AuthorityClass.IMPORTED_LEGACY_MEMORY
        ):
            raise ValueError("episodic memory requires an origin session or imported provenance")
        if self.scope is MemoryScope.SCENE_LOCAL:
            if self.origin_session_id is None:
                raise ValueError("scene-local memory requires an origin session")
            if self.visibility in {MemoryVisibility.SHAREABLE, MemoryVisibility.PUBLIC_SEED}:
                raise ValueError("scene-local visibility exceeds its structural boundary")
        if self.visibility is MemoryVisibility.PUBLIC_SEED:
            raise ValueError("sealed memory cannot be a public seed")
        if self.visibility is MemoryVisibility.SHAREABLE and self.sensitivity > 1:
            raise ValueError("shareable memory sensitivity cannot exceed one")
        if self.sensitivity == 4 and self.content_protection == "cryptographically_erased":
            if self.status is not MemoryStatus.TOMBSTONED:
                raise ValueError("cryptographic erasure requires a tombstoned memory")
        elif (
            self.content_protection == "cryptographically_erased"
            and self.status is not MemoryStatus.TOMBSTONED
        ):
            raise ValueError("cryptographic erasure requires a tombstoned memory")
        if self.content_key_id != self.sealed_content.content_key_id:
            raise ValueError("sealed envelope content key differs from memory")
        if self.interpretation_limits or self.normalized_fingerprint is not None or self.metadata:
            raise ValueError("sealed memory plaintext derivatives must be absent")
        if (self.publication_approved_at is None) != (
            self.publication_approved_by_actor_id is None
        ):
            raise ValueError("publication approval time and actor must be supplied together")
        return self


class EvidenceState(ContractModel):
    """Complete evidence projection, including redaction state."""

    evidence_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    memory_id: UUID
    source_type: Annotated[str, Field(min_length=1, max_length=64)]
    source_reference: dict[str, object]
    excerpt: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    occurred_at: datetime | None = None
    content_sha256: HexDigest | None = None
    trust_classification: Annotated[str, Field(min_length=1, max_length=64)]
    status: Literal["active"] = "active"
    created_at: datetime
    metadata: dict[str, object]

    @field_validator("evidence_id", "tenant_id", "lineage_id", "branch_id", "memory_id")
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("occurred_at", "created_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        return _utc(value, str(getattr(info, "field_name", "datetime")))

    @model_validator(mode="after")
    def validate_object_bounds(self) -> EvidenceState:
        if len(self.source_reference) > 64:
            raise ValueError("evidence source reference cannot exceed 64 properties")
        if len(self.metadata) > 128:
            raise ValueError("evidence metadata cannot exceed 128 properties")
        return self


class LinkState(ContractModel):
    """Complete typed relationship projection."""

    link_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    source_memory_id: UUID
    target_memory_id: UUID
    link_type: LinkType
    status: Literal["active", "unlinked"]
    created_at: datetime
    unlinked_at: datetime | None = None
    metadata: dict[str, object]

    @field_validator(
        "link_id", "tenant_id", "lineage_id", "branch_id", "source_memory_id", "target_memory_id"
    )
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("created_at", "unlinked_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        return _utc(value, str(getattr(info, "field_name", "datetime")))

    @model_validator(mode="after")
    def validate_link(self) -> LinkState:
        if self.source_memory_id == self.target_memory_id:
            raise ValueError("memory links cannot be self-referential")
        if (self.status == "unlinked") != (self.unlinked_at is not None):
            raise ValueError("unlinked status and timestamp must agree")
        if len(self.metadata) > 128:
            raise ValueError("link metadata cannot exceed 128 properties")
        return self


class ConflictMemberState(ContractModel):
    conflict_id: UUID
    memory_id: UUID
    disposition: Annotated[str, Field(min_length=1, max_length=64)]
    joined_at: datetime

    @field_validator("conflict_id", "memory_id")
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("joined_at")
    @classmethod
    def normalize_joined_at(cls, value: datetime) -> datetime:
        return _utc(value, "joined_at")


class ConflictState(ContractModel):
    """Complete conflict projection and member dispositions."""

    conflict_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    subject_id: UUID
    status: Literal["open", "resolved"]
    reason: Annotated[str, Field(min_length=1, max_length=4096)]
    resolution_kind: Annotated[str | None, Field(min_length=1, max_length=64)] = None
    resolution_rationale: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    opened_at: datetime
    resolved_at: datetime | None = None
    metadata: dict[str, object]

    @field_validator("conflict_id", "tenant_id", "lineage_id", "branch_id", "subject_id")
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("opened_at", "resolved_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        return _utc(value, str(getattr(info, "field_name", "datetime")))

    @model_validator(mode="after")
    def validate_conflict(self) -> ConflictState:
        if self.status == "resolved":
            if self.resolved_at is None or not self.resolution_kind:
                raise ValueError("resolved conflicts require resolution details")
        elif any(
            value is not None
            for value in (self.resolved_at, self.resolution_kind, self.resolution_rationale)
        ):
            raise ValueError("open conflicts cannot contain resolution details")
        if len(self.metadata) > 128:
            raise ValueError("conflict metadata cannot exceed 128 properties")
        return self


class BranchState(ContractModel):
    """Complete event-sourced branch projection."""

    branch_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    parent_branch_id: UUID | None = None
    fork_event_sequence: Annotated[int | None, Field(ge=1, le=(1 << 53) - 1)] = None
    name: Annotated[str, Field(min_length=1, max_length=255)]
    visibility_ceiling: MemoryVisibility
    created_at: datetime
    sealed_at: datetime | None = None

    @field_validator("branch_id", "tenant_id", "lineage_id", "parent_branch_id")
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("created_at", "sealed_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        return _utc(value, str(getattr(info, "field_name", "datetime")))

    @model_validator(mode="after")
    def validate_parent_shape(self) -> BranchState:
        if (self.parent_branch_id is None) != (self.fork_event_sequence is None):
            raise ValueError("parent branch and fork sequence must be supplied together")
        if self.parent_branch_id == self.branch_id:
            raise ValueError("a branch cannot parent itself")
        return self


class MemoryCreatedPayload(ContractModel):
    memory: MemoryState
    evidence: tuple[EvidenceState, ...] = ()


class MemoryCreatedPayloadV2(MemoryCreatedPayload):
    memory: MemoryStateV2


class MemoryCreatedPayloadV3(MemoryCreatedPayload):
    memory: MemoryStateV3
    evidence: tuple[()] = ()


class MemoryTransitionPayload(ContractModel):
    previous_revision: PositiveRevision
    memory: MemoryState


class MemoryTransitionPayloadV3(MemoryTransitionPayload):
    memory: MemoryStateV3


class CandidateLifecyclePayload(MemoryTransitionPayload):
    """Immutable policy decision for one candidate lifecycle transition."""

    memory: MemoryStateV2
    selection_decision_id: UUID
    policy_rule_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
    evidence: Annotated[tuple[EvidenceState, ...], Field(max_length=32)] = ()

    @field_validator("selection_decision_id")
    @classmethod
    def validate_selection_decision_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "selection_decision_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_evidence_ids(self) -> CandidateLifecyclePayload:
        if len({item.evidence_id for item in self.evidence}) != len(self.evidence):
            raise ValueError("candidate lifecycle evidence IDs must be unique")
        return self


class CandidateLifecyclePayloadV3(CandidateLifecyclePayload):
    memory: MemoryStateV3
    evidence: tuple[()] = ()


class SupersededPayload(MemoryTransitionPayload):
    link: LinkState


class TombstonedPayload(MemoryTransitionPayload):
    forget_mode: Literal["logical", "hard"]


class TombstonedPayloadV3(TombstonedPayload):
    memory: MemoryStateV3


class EvidenceAttachedPayload(ContractModel):
    evidence: EvidenceState


class EvidenceRedactedPayload(ContractModel):
    evidence_id: UUID
    memory_id: UUID
    redacted_at: datetime
    reason_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]

    @field_validator("evidence_id", "memory_id")
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("redacted_at")
    @classmethod
    def normalize_redacted_at(cls, value: datetime) -> datetime:
        return _utc(value, "redacted_at")


class LinkedPayload(ContractModel):
    link: LinkState


class UnlinkedPayload(ContractModel):
    link: LinkState


class AffectedMemory(ContractModel):
    previous_revision: PositiveRevision
    memory: MemoryState


class ConflictOpenedPayload(ContractModel):
    conflict: ConflictState
    members: tuple[ConflictMemberState, ...]
    affected_memories: tuple[AffectedMemory, ...]

    @model_validator(mode="after")
    def validate_members(self) -> ConflictOpenedPayload:
        _validate_conflict_members(self.conflict, self.members)
        return self


class ConflictResolvedPayload(ContractModel):
    conflict: ConflictState
    members: tuple[ConflictMemberState, ...]
    affected_memories: tuple[AffectedMemory, ...]

    @model_validator(mode="after")
    def validate_members(self) -> ConflictResolvedPayload:
        _validate_conflict_members(self.conflict, self.members)
        return self


def _validate_conflict_members(
    conflict: ConflictState, members: tuple[ConflictMemberState, ...]
) -> None:
    ids = [member.memory_id for member in members]
    if len(ids) < 2 or len(set(ids)) != len(ids):
        raise ValueError("conflicts require at least two unique members")
    if any(member.conflict_id != conflict.conflict_id for member in members):
        raise ValueError("conflict members must reference their conflict")


class BranchCreatedPayload(ContractModel):
    branch: BranchState


class PayloadPurgeCompletedPayload(MemoryTransitionPayload):
    content_key_id: UUID
    key_destroyed_at: datetime
    destruction_receipt_sha256: HexDigest

    @field_validator("content_key_id")
    @classmethod
    def validate_uuid7(cls, value: UUID) -> UUID:
        return _uuid7(value, "content_key_id")  # type: ignore[return-value]

    @field_validator("key_destroyed_at")
    @classmethod
    def normalize_destroyed_at(cls, value: datetime) -> datetime:
        return _utc(value, "key_destroyed_at")


class PayloadPurgeCompletedPayloadV3(PayloadPurgeCompletedPayload):
    memory: MemoryStateV3


type OperationPayload = (
    MemoryCreatedPayload
    | MemoryCreatedPayloadV2
    | MemoryCreatedPayloadV3
    | MemoryTransitionPayload
    | MemoryTransitionPayloadV3
    | CandidateLifecyclePayload
    | CandidateLifecyclePayloadV3
    | SupersededPayload
    | EvidenceAttachedPayload
    | EvidenceRedactedPayload
    | TombstonedPayload
    | TombstonedPayloadV3
    | LinkedPayload
    | UnlinkedPayload
    | ConflictOpenedPayload
    | ConflictResolvedPayload
    | BranchCreatedPayload
    | PayloadPurgeCompletedPayload
    | PayloadPurgeCompletedPayloadV3
)


PAYLOAD_MODELS: dict[tuple[EventOperation, int, int], type[ContractModel]] = {
    (EventOperation.OBSERVED, 1, 1): MemoryCreatedPayload,
    (EventOperation.OBSERVED, 2, 2): MemoryCreatedPayloadV2,
    (EventOperation.OBSERVED, 3, 3): MemoryCreatedPayloadV3,
    (EventOperation.REMEMBERED, 1, 1): MemoryCreatedPayload,
    (EventOperation.REMEMBERED, 2, 2): MemoryCreatedPayloadV2,
    (EventOperation.REMEMBERED, 3, 3): MemoryCreatedPayloadV3,
    (EventOperation.CANDIDATE_PROMOTED, 2, 2): CandidateLifecyclePayload,
    (EventOperation.CANDIDATE_EXPIRED, 2, 2): CandidateLifecyclePayload,
    (EventOperation.REVISED, 1, 1): MemoryTransitionPayload,
    (EventOperation.LINKED, 1, 1): LinkedPayload,
    (EventOperation.EVIDENCE_ATTACHED, 1, 1): EvidenceAttachedPayload,
    (EventOperation.EVIDENCE_REDACTED, 1, 1): EvidenceRedactedPayload,
    (EventOperation.UNLINKED, 1, 1): UnlinkedPayload,
    (EventOperation.CONFLICT_OPENED, 1, 1): ConflictOpenedPayload,
    (EventOperation.CONFLICT_RESOLVED, 1, 1): ConflictResolvedPayload,
    (EventOperation.SUPERSEDED, 1, 1): SupersededPayload,
    (EventOperation.RETIRED, 1, 1): MemoryTransitionPayload,
    (EventOperation.TOMBSTONED, 1, 1): TombstonedPayload,
    (EventOperation.TOMBSTONED, 3, 3): TombstonedPayloadV3,
    (EventOperation.BRANCH_CREATED, 1, 1): BranchCreatedPayload,
    (EventOperation.VISIBILITY_CHANGED, 1, 1): MemoryTransitionPayload,
    (EventOperation.PAYLOAD_PURGE_COMPLETED, 1, 1): PayloadPurgeCompletedPayload,
    (EventOperation.PAYLOAD_PURGE_COMPLETED, 3, 3): PayloadPurgeCompletedPayloadV3,
}


_CREATE_OPERATIONS = frozenset({EventOperation.OBSERVED, EventOperation.REMEMBERED})
_TRANSITION_OPERATIONS = frozenset(
    {
        EventOperation.CANDIDATE_PROMOTED,
        EventOperation.CANDIDATE_EXPIRED,
        EventOperation.REVISED,
        EventOperation.SUPERSEDED,
        EventOperation.RETIRED,
        EventOperation.TOMBSTONED,
        EventOperation.VISIBILITY_CHANGED,
        EventOperation.PAYLOAD_PURGE_COMPLETED,
    }
)
_EVIDENCE_OPERATIONS = frozenset(
    {EventOperation.EVIDENCE_ATTACHED, EventOperation.EVIDENCE_REDACTED}
)
_AGGREGATE_OPERATIONS = frozenset(
    {
        EventOperation.LINKED,
        EventOperation.UNLINKED,
        EventOperation.CONFLICT_OPENED,
        EventOperation.CONFLICT_RESOLVED,
        EventOperation.BRANCH_CREATED,
    }
)


def validate_event_envelope_shape(event: MemoryEvent) -> None:
    """Validate the operation-specific target/revision shape of an event envelope."""

    if event.operation in _CREATE_OPERATIONS:
        valid = event.memory_id is not None and event.expected_revision is None
    elif event.operation in _TRANSITION_OPERATIONS:
        valid = event.memory_id is not None and event.expected_revision is not None
    elif event.operation in _EVIDENCE_OPERATIONS:
        valid = event.memory_id is not None and event.expected_revision is None
    elif event.operation in _AGGREGATE_OPERATIONS:
        valid = event.memory_id is None and event.expected_revision is None
    else:
        valid = False
    if not valid:
        raise EventContractError(
            f"invalid envelope target shape for operation {event.operation.value}"
        )


class MemoryEvent(ContractModel):
    """Immutable accepted event envelope with verified canonical payload bytes."""

    EVENT_SCHEMA_VERSIONS: ClassVar[frozenset[int]] = frozenset({1, 2, 3})
    PAYLOAD_VERSIONS: ClassVar[frozenset[int]] = frozenset({1, 2, 3})

    schema_version: Literal[1, 2, 3]
    payload_version: Literal[1, 2, 3]
    sequence: SafePositiveInteger
    event_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    session_id: UUID | None
    ingress_id: UUID | None
    operation: EventOperation
    memory_id: UUID | None
    expected_revision: PositiveRevision | None
    causation_event_id: UUID | None
    correlation_id: UUID
    idempotency_key: Annotated[str, Field(min_length=1, max_length=255)]
    policy_version: SafePositiveInteger
    normalization_version: SafePositiveInteger
    payload: dict[str, object]
    payload_canonical: Annotated[str, Field(min_length=4, max_length=1_398_104)]
    payload_sha256: HexDigest
    command_sha256: HexDigest
    created_at: datetime

    @field_validator(
        "event_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "session_id",
        "ingress_id",
        "memory_id",
        "causation_event_id",
        "correlation_id",
    )
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return _utc(value, "created_at")

    @model_validator(mode="after")
    def validate_canonical_contract(self) -> MemoryEvent:
        validate_event_envelope_shape(self)
        self.typed_payload()
        self.verify_hashes()
        return self

    def typed_payload(self) -> OperationPayload:
        model = PAYLOAD_MODELS.get((self.operation, self.schema_version, self.payload_version))
        if (
            self.schema_version not in self.EVENT_SCHEMA_VERSIONS
            or self.payload_version not in self.PAYLOAD_VERSIONS
            or model is None
        ):
            raise EventContractError(
                f"unsupported event payload: {self.operation.value} v{self.payload_version}"
            )
        return model.model_validate(self.payload, strict=False)  # type: ignore[return-value]

    def command_material(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "lineage_id": self.lineage_id,
            "branch_id": self.branch_id,
            "actor_id": self.actor_id,
            "client_id": self.client_id,
            "operation": self.operation.value,
            "payload_version": self.payload_version,
            "memory_id": self.memory_id,
            "expected_revision": self.expected_revision,
            "causation_event_id": self.causation_event_id,
            "payload": self.payload,
        }

    def verify_hashes(self) -> None:
        typed = self.typed_payload()
        canonical = canonical_json_bytes(typed.canonical_value())
        try:
            recorded = base64.b64decode(self.payload_canonical, validate=True)
        except ValueError as error:
            raise EventContractError("payload_canonical is not valid base64") from error
        if recorded != canonical:
            raise EventContractError("payload canonical bytes do not match parsed payload")
        if hashlib.sha256(canonical).hexdigest() != self.payload_sha256:
            raise EventContractError("payload SHA-256 mismatch")
        command = canonical_json_bytes(normalize_json_value(self.command_material()))
        if hashlib.sha256(command).hexdigest() != self.command_sha256:
            raise EventContractError("command SHA-256 mismatch")


def event_hash_fields(
    *,
    operation: EventOperation,
    payload: OperationPayload,
    tenant_id: UUID,
    lineage_id: UUID,
    branch_id: UUID,
    actor_id: UUID,
    client_id: UUID,
    memory_id: UUID | None,
    expected_revision: int | None,
    causation_event_id: UUID | None,
    payload_version: int = 1,
) -> tuple[dict[str, object], str, str, str]:
    """Return parsed payload, base64 canonical bytes, payload hash, and command hash."""

    payload_value = payload.canonical_value()
    if not isinstance(payload_value, dict):
        raise EventContractError("event payload must normalize to an object")
    payload_bytes = canonical_json_bytes(payload_value)
    command_material = normalize_json_value(
        {
            "tenant_id": tenant_id,
            "lineage_id": lineage_id,
            "branch_id": branch_id,
            "actor_id": actor_id,
            "client_id": client_id,
            "operation": operation.value,
            "payload_version": payload_version,
            "memory_id": memory_id,
            "expected_revision": expected_revision,
            "causation_event_id": causation_event_id,
            "payload": payload_value,
        }
    )
    return (
        payload_value,
        base64.b64encode(payload_bytes).decode("ascii"),
        hashlib.sha256(payload_bytes).hexdigest(),
        hashlib.sha256(canonical_json_bytes(command_material)).hexdigest(),
    )
