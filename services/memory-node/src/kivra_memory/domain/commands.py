"""Strict transport-neutral contracts for memory mutation commands.

Commands contain caller-supplied semantic intent only.  Tenant, actor, client,
installation, and transport provenance are deliberately absent and must be
resolved from authenticated context by the application layer.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kivra_memory.domain.canonical_json import canonical_json_bytes, normalize_json_value
from kivra_memory.domain.constraints import validate_category_ontology
from kivra_memory.domain.enums import (
    AuthorityClass,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import UnitScore, normalize_utc_datetime

SafePositiveInteger = Annotated[int, Field(ge=1, le=(1 << 53) - 1)]
BoundedReason = Annotated[str, Field(min_length=1, max_length=4096)]
BoundedMetadata = Annotated[dict[str, object], Field(max_length=128)]
ContractVersion = Literal["mcp-mutation-v1"]


def _uuid7(value: UUID | None, field_name: str) -> UUID | None:
    if value is not None:
        require_uuid7(value, field_name=field_name)
    return value


def _validate_bounded_json(value: object, *, depth: int = 0) -> None:
    """Bound command maps beyond Pydantic's top-level property limit."""

    if depth > 8:
        raise ValueError("command metadata exceeds the maximum nesting depth")
    if isinstance(value, dict):
        if len(value) > 128:
            raise ValueError("command metadata object exceeds 128 properties")
        for key, member in value.items():
            if len(key) > 255:
                raise ValueError("command metadata key exceeds 255 characters")
            _validate_bounded_json(member, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 128:
            raise ValueError("command metadata array exceeds 128 items")
        for member in value:
            _validate_bounded_json(member, depth=depth + 1)
    elif isinstance(value, str) and len(value) > 4096:
        raise ValueError("command metadata string exceeds 4096 characters")
    normalize_json_value(value)


class CommandModel(BaseModel):
    """Strict immutable base for all command-side contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    def canonical_value(self) -> object:
        return normalize_json_value(self.model_dump(mode="python"))


class MemoryInput(CommandModel):
    """Complete caller-controlled fields for constructing a memory after-image.

    Canonical identifiers, revisions, fingerprints, approval provenance, and
    server timestamps are filled by the command handler, not accepted here.
    """

    subject_id: UUID
    subject_kind: SubjectKind
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: BoundedReason
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...],
        Field(max_length=32),
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
    metadata: BoundedMetadata

    @field_validator("subject_id", "origin_session_id")
    @classmethod
    def validate_memory_uuid(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("valid_from", "valid_to", "observed_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        try:
            return normalize_utc_datetime(value)
        except ValueError as error:
            field_name = getattr(info, "field_name", "datetime")
            raise ValueError(f"{field_name} must be timezone-aware") from error

    @model_validator(mode="after")
    def validate_memory_input(self) -> MemoryInput:
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
        if self.visibility is MemoryVisibility.PUBLIC_SEED:
            raise ValueError("public-seed publication requires an administrative command")
        if self.scope is MemoryScope.SCENE_LOCAL and self.visibility in {
            MemoryVisibility.SHAREABLE,
            MemoryVisibility.PUBLIC_SEED,
        }:
            raise ValueError("scene-local visibility exceeds its structural boundary")
        if self.visibility is MemoryVisibility.SHAREABLE and self.sensitivity > 1:
            raise ValueError("shareable memory sensitivity cannot exceed one")
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("valid_to must not precede valid_from")
        if len(set(self.interpretation_limits)) != len(self.interpretation_limits):
            raise ValueError("interpretation limits must be unique")
        _validate_bounded_json(self.metadata)
        return self


class MemoryChanges(CommandModel):
    """A strict, non-empty patch of caller-controlled memory fields."""

    category: MemoryCategory | None = None
    ontological_status: OntologicalStatus | None = None
    visibility: MemoryVisibility | None = None
    statement: Annotated[str | None, Field(min_length=1, max_length=8192)] = None
    reason_to_remember: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...] | None,
        Field(max_length=32),
    ] = None
    confidence: UnitScore | None = None
    salience: UnitScore | None = None
    durability: UnitScore | None = None
    sensitivity: Annotated[int | None, Field(ge=0, le=4)] = None
    authority_class: AuthorityClass | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    observed_at: datetime | None = None
    metadata: BoundedMetadata | None = None

    @field_validator("valid_from", "valid_to", "observed_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        try:
            return normalize_utc_datetime(value)
        except ValueError as error:
            field_name = getattr(info, "field_name", "datetime")
            raise ValueError(f"{field_name} must be timezone-aware") from error

    @model_validator(mode="after")
    def validate_changes(self) -> MemoryChanges:
        if not self.model_fields_set:
            raise ValueError("memory changes must contain at least one field")
        non_nullable = self.model_fields_set - {"valid_from", "valid_to", "observed_at"}
        if any(getattr(self, field_name) is None for field_name in non_nullable):
            raise ValueError("non-nullable memory changes cannot be null")
        if self.interpretation_limits is not None and len(set(self.interpretation_limits)) != len(
            self.interpretation_limits
        ):
            raise ValueError("interpretation limits must be unique")
        if self.metadata is not None:
            _validate_bounded_json(self.metadata)
        return self

    def canonical_value(self) -> object:
        return normalize_json_value(self.model_dump(mode="python", exclude_unset=True))


class CommandHashBinding(CommandModel):
    """Authenticated context used internally to bind command material."""

    tenant_id: UUID
    lineage_id: UUID
    actor_id: UUID
    client_id: UUID

    @field_validator("tenant_id", "lineage_id", "actor_id", "client_id")
    @classmethod
    def validate_uuid7(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]


class MutationCommand(CommandModel):
    """Common mutation envelope shared by all direct write operations."""

    OPERATION: ClassVar[str]
    COMMAND_VERSION: ClassVar[int] = 1

    contract_version: ContractVersion
    idempotency_key: Annotated[str, Field(min_length=1, max_length=255)]
    logical_session_id: UUID | None
    persona_id: UUID
    branch_id: UUID
    reason: BoundedReason
    causation_event_id: UUID | None = None

    @field_validator("logical_session_id", "persona_id", "branch_id", "causation_event_id")
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    def semantic_payload(self) -> dict[str, object]:
        value = self.model_dump(
            mode="python",
            exclude={
                "idempotency_key",
                "logical_session_id",
                "persona_id",
                "branch_id",
                "contract_version",
                "causation_event_id",
            },
        )
        changes = getattr(self, "changes", None)
        if isinstance(changes, MemoryChanges):
            value["changes"] = changes.model_dump(mode="python", exclude_unset=True)
        normalized = normalize_json_value(value)
        if not isinstance(normalized, dict):  # pragma: no cover - model dumps are objects
            raise TypeError("command payload must normalize to an object")
        return dict(normalized)

    def canonical_material(self) -> dict[str, object]:
        """Return stable semantic request material, excluding replay/transport data."""

        return {
            "command_version": self.COMMAND_VERSION,
            "operation": self.OPERATION,
            "persona_id": str(self.persona_id),
            "branch_id": str(self.branch_id),
            "causation_event_id": (
                str(self.causation_event_id) if self.causation_event_id is not None else None
            ),
            "payload": self.semantic_payload(),
        }

    def canonical_hash(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.canonical_material())).hexdigest()

    def bound_canonical_material(self, binding: CommandHashBinding) -> dict[str, object]:
        """Bind semantic bytes to trusted identity without adding transport provenance."""

        return {
            "tenant_id": str(binding.tenant_id),
            "lineage_id": str(binding.lineage_id),
            "actor_id": str(binding.actor_id),
            "client_id": str(binding.client_id),
            **self.canonical_material(),
        }

    def bound_canonical_hash(self, binding: CommandHashBinding) -> str:
        material = canonical_json_bytes(self.bound_canonical_material(binding))
        return hashlib.sha256(material).hexdigest()


class ObserveCommand(MutationCommand):
    OPERATION: ClassVar[str] = "observe"
    memory: MemoryInput


class RememberCommand(MutationCommand):
    OPERATION: ClassVar[str] = "remember"
    memory: MemoryInput


class ReviseCommand(MutationCommand):
    OPERATION: ClassVar[str] = "revise"
    memory_id: UUID
    expected_revision: SafePositiveInteger
    changes: MemoryChanges

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class LinkCommand(MutationCommand):
    OPERATION: ClassVar[str] = "link"
    source_memory_id: UUID
    source_expected_revision: SafePositiveInteger
    target_memory_id: UUID
    target_expected_revision: SafePositiveInteger
    link_type: LinkType
    metadata: BoundedMetadata = Field(default_factory=dict)

    @field_validator("source_memory_id", "target_memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "memory_id")))  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_link(self) -> LinkCommand:
        if self.source_memory_id == self.target_memory_id:
            raise ValueError("memory links cannot be self-referential")
        _validate_bounded_json(self.metadata)
        return self


class MemoryRevisionExpectation(CommandModel):
    memory_id: UUID
    expected_revision: SafePositiveInteger

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class OpenConflictCommand(MutationCommand):
    OPERATION: ClassVar[str] = "open_conflict"
    subject_id: UUID
    members: Annotated[tuple[MemoryRevisionExpectation, ...], Field(min_length=2, max_length=32)]
    conflict_reason: BoundedReason
    metadata: BoundedMetadata = Field(default_factory=dict)

    @field_validator("subject_id")
    @classmethod
    def validate_subject_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "subject_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_members(self) -> OpenConflictCommand:
        ids = [member.memory_id for member in self.members]
        if len(ids) != len(set(ids)):
            raise ValueError("conflict members must be unique")
        _validate_bounded_json(self.metadata)
        return self


class ConflictResolution(CommandModel):
    memory_id: UUID
    expected_revision: SafePositiveInteger
    disposition: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
    resulting_status: Literal["active", "superseded", "retired"]

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class ResolveConflictCommand(MutationCommand):
    OPERATION: ClassVar[str] = "resolve_conflict"
    conflict_id: UUID
    members: Annotated[tuple[ConflictResolution, ...], Field(min_length=2, max_length=32)]
    resolution_kind: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
    resolution_rationale: BoundedReason
    user_confirmed: bool = False

    @field_validator("conflict_id")
    @classmethod
    def validate_conflict_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "conflict_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_resolutions(self) -> ResolveConflictCommand:
        ids = [resolution.memory_id for resolution in self.members]
        if len(ids) != len(set(ids)):
            raise ValueError("conflict resolutions must identify unique memories")
        return self


class RetireCommand(MutationCommand):
    OPERATION: ClassVar[str] = "retire"
    memory_id: UUID
    expected_revision: SafePositiveInteger

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class ForgetCommand(MutationCommand):
    OPERATION: ClassVar[str] = "forget"
    memory_id: UUID
    expected_revision: SafePositiveInteger
    mode: Literal["logical", "hard"]
    confirmation: Literal["confirm_logical_forget", "confirm_hard_forget"]

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_confirmation(self) -> ForgetCommand:
        expected = f"confirm_{self.mode}_forget"
        if self.confirmation != expected:
            raise ValueError("forget confirmation must match the selected mode")
        return self


class CandidateLifecycleCommand(CommandModel):
    """Internal-only, content-free candidate lifecycle instruction.

    This DTO is intentionally not an MCP mutation command. The policy worker
    obtains the current memory under lock and constructs the immutable event
    after-image itself.
    """

    OPERATION: ClassVar[str]

    memory_id: UUID
    expected_revision: SafePositiveInteger
    selection_decision_id: UUID
    policy_rule_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]

    @field_validator("memory_id", "selection_decision_id")
    @classmethod
    def validate_lifecycle_identifier(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]


class CandidatePromotionCommand(CandidateLifecycleCommand):
    """Internal policy instruction to promote one exact candidate revision."""

    OPERATION: ClassVar[str] = "candidate_promote"


class CandidateExpiryCommand(CandidateLifecycleCommand):
    """Internal policy instruction to expire one exact candidate revision."""

    OPERATION: ClassVar[str] = "candidate_expire"


type DirectMutationCommand = (
    ObserveCommand
    | RememberCommand
    | ReviseCommand
    | LinkCommand
    | OpenConflictCommand
    | ResolveConflictCommand
    | RetireCommand
    | ForgetCommand
)


class StaleRevisionDetails(CommandModel):
    memory_id: UUID
    expected_revision: SafePositiveInteger
    current_revision: SafePositiveInteger
    suggested_action: Literal["read_then_retry_or_open_conflict"] = (
        "read_then_retry_or_open_conflict"
    )

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class ConflictErrorDetails(CommandModel):
    conflict_id: UUID
    memory_ids: Annotated[tuple[UUID, ...], Field(min_length=2, max_length=32)]
    suggested_action: Literal["inspect_conflict"] = "inspect_conflict"

    @field_validator("conflict_id", "memory_ids")
    @classmethod
    def validate_ids(cls, value: UUID | tuple[UUID, ...], info: object) -> UUID | tuple[UUID, ...]:
        field_name = str(getattr(info, "field_name", "identifier"))
        if isinstance(value, tuple):
            return tuple(_uuid7(item, field_name) for item in value)  # type: ignore[misc]
        return _uuid7(value, field_name)  # type: ignore[return-value]

    @model_validator(mode="after")
    def unique_memory_ids(self) -> ConflictErrorDetails:
        if len(set(self.memory_ids)) != len(self.memory_ids):
            raise ValueError("conflict error memory identifiers must be unique")
        return self


class MutationResult(CommandModel):
    """Payload-safe successful mutation receipt."""

    ok: Literal[True] = True
    contract_version: ContractVersion
    operation: Literal[
        "observe",
        "remember",
        "revise",
        "link",
        "open_conflict",
        "resolve_conflict",
        "retire",
        "forget",
    ]
    receipt_id: UUID
    event_id: UUID
    memory_id: UUID | None = None
    revision: SafePositiveInteger | None = None
    conflict_id: UUID | None = None
    conflict_state: Literal["open", "resolved"] | None = None
    forget_state: Literal["logically_forgotten", "purge_pending"] | None = None
    idempotent_replay: bool = False
    warnings: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)], ...],
        Field(max_length=16),
    ] = ()

    @field_validator("receipt_id", "event_id", "memory_id", "conflict_id")
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @model_validator(mode="after")
    def validate_receipt(self) -> MutationResult:
        if (self.memory_id is None) != (self.revision is None):
            raise ValueError("memory identifier and revision must be supplied together")
        if self.operation == "open_conflict":
            if self.conflict_id is None or self.conflict_state != "open":
                raise ValueError("open-conflict receipts require an open conflict state")
        elif self.operation == "resolve_conflict":
            if self.conflict_id is None or self.conflict_state != "resolved":
                raise ValueError("resolve-conflict receipts require a resolved conflict state")
        elif self.conflict_id is not None or self.conflict_state is not None:
            raise ValueError("conflict receipt fields only apply to conflict operations")
        if self.operation == "forget":
            if self.forget_state is None:
                raise ValueError("forget receipts require a forget state")
        elif self.forget_state is not None:
            raise ValueError("forget state only applies to forget operations")
        if len(set(self.warnings)) != len(self.warnings):
            raise ValueError("mutation warning codes must be unique")
        return self


class MutationErrorBody(CommandModel):
    """Allowlisted payload-safe failure body."""

    SAFE_MESSAGES: ClassVar[dict[str, str]] = {
        "invalid_input": "The mutation input is invalid.",
        "unauthenticated": "Authentication is required.",
        "forbidden": "The authenticated caller is not permitted to perform this mutation.",
        "not_found": "The requested resource was not found.",
        "stale_revision": "The target changed after the supplied revision.",
        "idempotency_key_reused": "The idempotency key was already used for another command.",
        "conflict_state_changed": "The conflict state changed before this mutation completed.",
        "hard_forget_unavailable": "Hard forget is unavailable for this memory.",
        "serialization_exhausted": "The mutation could not complete after bounded retries.",
        "dependency_unavailable": "A required dependency is unavailable.",
        "internal_error": "The mutation could not be completed.",
    }

    code: Literal[
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "not_found",
        "stale_revision",
        "idempotency_key_reused",
        "conflict_state_changed",
        "hard_forget_unavailable",
        "serialization_exhausted",
        "dependency_unavailable",
        "internal_error",
    ]
    message: Annotated[str, Field(min_length=1, max_length=512)]
    retryable: bool = False
    retry_after_ms: Annotated[int | None, Field(ge=0, le=60_000)] = None
    details: StaleRevisionDetails | ConflictErrorDetails | None = None

    @model_validator(mode="after")
    def validate_safe_error(self) -> MutationErrorBody:
        if self.message != self.SAFE_MESSAGES[self.code]:
            raise ValueError("mutation error message must use the safe message for its code")
        if self.code == "stale_revision":
            if not isinstance(self.details, StaleRevisionDetails):
                raise ValueError("stale revision errors require stale revision details")
        elif self.code == "conflict_state_changed":
            if self.details is not None and not isinstance(self.details, ConflictErrorDetails):
                raise ValueError("conflict-state details have an invalid shape")
        elif self.details is not None:
            raise ValueError("error details are not allowed for this code")
        if self.retry_after_ms is not None and not self.retryable:
            raise ValueError("retry timing is only valid for retryable errors")
        return self


class MutationError(CommandModel):
    """Closed failure envelope; arbitrary diagnostics cannot be attached."""

    ok: Literal[False] = False
    contract_version: ContractVersion
    error: MutationErrorBody


type MutationResponse = MutationResult | MutationError
