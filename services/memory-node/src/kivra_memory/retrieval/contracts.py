"""Strict transport-neutral contracts for semantic memory reads."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, ClassVar, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import format_utc_datetime, normalize_utc_datetime
from kivra_memory.policy import SelectionBasis

ReadContractVersion = Literal["mcp-read-v1"]
ReadContractVersionV2 = Literal["mcp-read-v2"]
SafePositiveInteger = Annotated[int, Field(ge=1, le=(1 << 53) - 1)]
BoundedQuery = Annotated[str, Field(min_length=1, max_length=8192)]
UnitFloat = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
ContextSection = Literal[
    "persona",
    "active_boundaries",
    "user_preferences",
    "relationship_patterns",
    "project_context",
    "episodic_anchors",
    "open_questions",
]
ReadOperation = Literal[
    "context_pack",
    "search",
    "get",
    "timeline",
    "conflicts",
    "lineage",
    "selection_history",
]
OpaqueCursor = Annotated[str, Field(min_length=1, max_length=4096)]
ReadWarningCode = Literal[
    "embeddings_unavailable",
    "embeddings_warming",
    "embeddings_stale",
    "results_truncated",
    "evidence_omitted",
]
OmissionReason = Literal[
    "budget_truncated",
    "item_budget_reached",
    "evidence_omitted",
    "requested_scope_reduction",
]
ExplanationCode = Literal[
    "lexical_match",
    "trigram_match",
    "semantic_match",
    "scope_exact",
    "authority_weighted",
    "confidence_weighted",
    "salience_weighted",
    "recency_weighted",
    "conflict_expanded",
]


def _uuid7(value: UUID | None, field_name: str) -> UUID | None:
    if value is not None:
        require_uuid7(value, field_name=field_name)
    return value


class ReadModel(BaseModel):
    """Strict immutable base shared by read queries and results."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class QueryPrincipal(ReadModel):
    """Authenticated authority supplied by an adapter, never tool input."""

    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    scopes: Annotated[
        frozenset[Annotated[str, Field(min_length=1, max_length=255)]], Field(max_length=64)
    ]
    allowed_memory_scopes: frozenset[MemoryScope]
    allowed_visibilities: frozenset[MemoryVisibility]
    max_sensitivity: Annotated[int, Field(ge=0, le=4)]
    allow_candidates: bool = False
    ingress_id: UUID | None = None

    @field_validator("tenant_id", "actor_id", "client_id", "transport_binding_id", "ingress_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))


class ReadContext(ReadModel):
    persona_id: UUID
    branch_id: UUID
    logical_session_id: UUID | None = None
    project_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None
    relationship_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None

    @field_validator("persona_id", "branch_id", "logical_session_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))


class MemoryFilters(ReadModel):
    subject_ids: Annotated[tuple[UUID, ...], Field(max_length=128)] = ()
    subject_kinds: frozenset[SubjectKind] = frozenset()
    categories: frozenset[MemoryCategory] = frozenset()
    ontological_statuses: frozenset[OntologicalStatus] = frozenset()
    scopes: frozenset[MemoryScope] = frozenset()
    visibilities: frozenset[MemoryVisibility] = frozenset()
    include_candidates: bool = False
    valid_at: datetime | None = None

    @field_validator("subject_ids")
    @classmethod
    def validate_subject_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("subject identifiers must be unique")
        return tuple(_uuid7(item, "subject_id") for item in value)  # type: ignore[misc]

    @field_validator("valid_at")
    @classmethod
    def normalize_valid_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return normalize_utc_datetime(value)


class SemanticReadQuery(ReadModel):
    OPERATION: ClassVar[ReadOperation]

    contract_version: ReadContractVersion
    persona_id: UUID
    branch_id: UUID
    logical_session_id: UUID | None = None
    project_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None
    relationship_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None

    @field_validator("persona_id", "branch_id", "logical_session_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))


class ContextPackQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "context_pack"

    query: BoundedQuery
    requested_memory_scopes: frozenset[MemoryScope] = frozenset()
    token_budget: Annotated[int, Field(ge=256, le=1_000_000)]


class MemorySearchQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "search"

    query: BoundedQuery
    filters: MemoryFilters = MemoryFilters()
    limit: Annotated[int, Field(ge=1, le=100)] = 20
    explain: bool = True


class MemoryGetQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "get"

    memory_id: UUID
    include_conflicts: bool = False

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "memory_id")  # type: ignore[return-value]


class TimeWindow(ReadModel):
    starts_at: datetime
    ends_at: datetime

    @field_validator("starts_at", "ends_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return normalize_utc_datetime(value)

    @model_validator(mode="after")
    def validate_window(self) -> TimeWindow:
        if self.ends_at < self.starts_at:
            raise ValueError("timeline end must not precede its start")
        return self


class MemoryTimelineQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "timeline"

    window: TimeWindow
    filters: MemoryFilters = MemoryFilters()
    limit: Annotated[int, Field(ge=1, le=200)] = 50


class MemoryConflictsQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "conflicts"

    query: BoundedQuery | None = None
    subject_id: UUID | None = None
    state: Literal["open"] = "open"
    limit: Annotated[int, Field(ge=1, le=100)] = 20

    @field_validator("subject_id")
    @classmethod
    def validate_subject_id(cls, value: UUID | None) -> UUID | None:
        return _uuid7(value, "subject_id")

    @model_validator(mode="after")
    def require_selector(self) -> MemoryConflictsQuery:
        if self.query is None and self.subject_id is None:
            raise ValueError("conflict reads require a query or subject")
        return self


class MemoryLineageQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "lineage"


class MemorySelectionHistoryQuery(SemanticReadQuery):
    OPERATION: ClassVar[ReadOperation] = "selection_history"

    limit: Annotated[int, Field(ge=1, le=200)] = 50


class MemorySelectionDecisionsQuery(ReadModel):
    """Authorized audit query over immutable selection decisions."""

    OPERATION: ClassVar[ReadOperation] = "selection_history"

    contract_version: ReadContractVersionV2
    persona_id: UUID
    branch_id: UUID
    logical_session_id: UUID | None = None
    project_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None
    relationship_ref: Annotated[str | None, Field(min_length=1, max_length=1024)] = None
    selection_bases: Annotated[frozenset[SelectionBasis], Field(max_length=10)] = frozenset()
    requested_memory_scopes: Annotated[frozenset[MemoryScope], Field(max_length=6)] = frozenset()
    requested_visibilities: Annotated[frozenset[MemoryVisibility], Field(max_length=4)] = (
        frozenset()
    )
    requested_subject_ids: Annotated[tuple[UUID, ...], Field(max_length=128)] = ()
    requested_subject_kinds: Annotated[frozenset[SubjectKind], Field(max_length=7)] = frozenset()
    max_sensitivity: Annotated[int | None, Field(ge=0, le=4)] = None
    cursor: OpaqueCursor | None = None
    limit: Annotated[int, Field(ge=1, le=200)] = 50

    @field_validator("persona_id", "branch_id", "logical_session_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("requested_subject_ids")
    @classmethod
    def validate_subject_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("requested subject identifiers must be unique")
        return tuple(_uuid7(item, "requested_subject_id") for item in value)  # type: ignore[misc]


type ReadQueryV2 = MemorySelectionDecisionsQuery


type SemanticReadRequest = (
    ContextPackQuery
    | MemorySearchQuery
    | MemoryGetQuery
    | MemoryTimelineQuery
    | MemoryConflictsQuery
    | MemoryLineageQuery
    | MemorySelectionHistoryQuery
)

type DirectReadQuery = SemanticReadRequest


class SourceContribution(ReadModel):
    source: Literal["lexical", "trigram", "semantic"]
    rank: SafePositiveInteger
    contribution: UnitFloat


class ScoreModifiers(ReadModel):
    scope_match: UnitFloat = 0.0
    authority: UnitFloat = 0.0
    confidence: UnitFloat = 0.0
    salience: UnitFloat = 0.0
    recency: UnitFloat = 0.0


class ModifierContribution(ReadModel):
    modifier: Literal["scope_match", "authority", "confidence", "salience", "recency"]
    value: UnitFloat
    contribution: UnitFloat


class MemoryScore(ReadModel):
    profile: Literal["rrf-v1"] = "rrf-v1"
    sources: Annotated[tuple[SourceContribution, ...], Field(max_length=3)]
    rrf_score: UnitFloat
    modifiers: ScoreModifiers
    modifier_contributions: Annotated[tuple[ModifierContribution, ...], Field(max_length=5)]
    final_score: UnitFloat

    @model_validator(mode="after")
    def validate_unique_components(self) -> MemoryScore:
        if len({item.source for item in self.sources}) != len(self.sources):
            raise ValueError("score sources must be unique")
        if len({item.modifier for item in self.modifier_contributions}) != len(
            self.modifier_contributions
        ):
            raise ValueError("score modifiers must be unique")
        return self


class UntrustedEvidenceExcerpt(ReadModel):
    trust: Literal["untrusted_evidence"] = "untrusted_evidence"
    evidence_id: UUID
    source_type: Annotated[str, Field(min_length=1, max_length=64)]
    excerpt: Annotated[str, Field(min_length=1, max_length=4096)]
    occurred_at: datetime | None = None

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "evidence_id")  # type: ignore[return-value]

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return normalize_utc_datetime(value)

    @field_serializer("occurred_at", when_used="json")
    def serialize_occurred_at(self, value: datetime | None) -> str | None:
        return format_utc_datetime(value) if value is not None else None


class MemoryHit(ReadModel):
    memory_id: UUID
    revision: SafePositiveInteger
    last_event_id: UUID
    branch_id: UUID
    subject_id: UUID
    subject_kind: SubjectKind
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    status: Literal["candidate", "active", "disputed"]
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...], Field(max_length=32)
    ]
    authority_class: AuthorityClass
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    observed_at: datetime | None = None
    score: MemoryScore
    explanation_codes: Annotated[tuple[ExplanationCode, ...], Field(max_length=9)] = ()
    evidence: Annotated[tuple[UntrustedEvidenceExcerpt, ...], Field(max_length=32)] = ()

    @field_validator("memory_id", "last_event_id", "branch_id", "subject_id")
    @classmethod
    def validate_identifier(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @field_validator("valid_from", "valid_to", "observed_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return normalize_utc_datetime(value)

    @field_serializer("valid_from", "valid_to", "observed_at", when_used="json")
    def serialize_time(self, value: datetime | None) -> str | None:
        return format_utc_datetime(value) if value is not None else None

    @model_validator(mode="after")
    def validate_hit(self) -> MemoryHit:
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("memory validity end must not precede its start")
        if len(set(self.interpretation_limits)) != len(self.interpretation_limits):
            raise ValueError("interpretation limits must be unique")
        if len(set(self.explanation_codes)) != len(self.explanation_codes):
            raise ValueError("explanation codes must be unique")
        return self

    def without_evidence(self) -> MemoryHit:
        return self if not self.evidence else self.model_copy(update={"evidence": ()})


class ConflictGroup(ReadModel):
    conflict_id: UUID
    subject_id: UUID
    state: Literal["open"] = "open"
    members: Annotated[tuple[MemoryHit, ...], Field(min_length=2, max_length=32)]

    @field_validator("conflict_id", "subject_id")
    @classmethod
    def validate_identifier(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_group(self) -> ConflictGroup:
        ids = [member.memory_id for member in self.members]
        if len(ids) != len(set(ids)):
            raise ValueError("conflict members must be unique")
        if any(member.status != "disputed" for member in self.members):
            raise ValueError("open conflict members must be disputed")
        if any(member.subject_id != self.subject_id for member in self.members):
            raise ValueError("conflict members must share the conflict subject")
        return self


class ExclusionSummary(ReadModel):
    requested_scope_reduction: bool = False
    evidence_omitted: bool = False
    budget_truncated: bool = False


class ProvenanceRecord(ReadModel):
    event_id: UUID
    memory_id: UUID
    revision: SafePositiveInteger

    @field_validator("event_id", "memory_id")
    @classmethod
    def validate_identifier(cls, value: UUID, info: object) -> UUID:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))  # type: ignore[return-value]


class ContextPack(ReadModel):
    schema_version: Literal[1] = 1
    contract_version: ReadContractVersion = "mcp-read-v1"
    context_pack_id: UUID
    persona: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    active_boundaries: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    user_preferences: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    relationship_patterns: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    project_context: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    episodic_anchors: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    open_questions: Annotated[tuple[MemoryHit, ...], Field(max_length=64)] = ()
    conflicts: Annotated[tuple[ConflictGroup, ...], Field(max_length=32)] = ()
    excluded_scope_summary: ExclusionSummary = ExclusionSummary()
    provenance: Annotated[tuple[ProvenanceRecord, ...], Field(max_length=512)] = ()

    @field_validator("context_pack_id")
    @classmethod
    def validate_context_pack_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "context_pack_id")  # type: ignore[return-value]

    @model_validator(mode="after")
    def validate_ids(self) -> ContextPack:
        memory_ids = [
            hit.memory_id
            for section in (
                self.persona,
                self.active_boundaries,
                self.user_preferences,
                self.relationship_patterns,
                self.project_context,
                self.episodic_anchors,
                self.open_questions,
            )
            for hit in section
        ]
        conflict_ids = [member.memory_id for group in self.conflicts for member in group.members]
        if len(memory_ids + conflict_ids) != len(set(memory_ids + conflict_ids)):
            raise ValueError("a memory may appear only once in a context pack")
        return self


class TimelineEvent(ReadModel):
    event_id: UUID
    sequence: SafePositiveInteger
    operation: EventOperation
    memory_id: UUID | None = None
    created_at: datetime

    @field_validator("event_id", "memory_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return normalize_utc_datetime(value)

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, value: datetime) -> str:
        return format_utc_datetime(value)


class BranchView(ReadModel):
    branch_id: UUID
    parent_branch_id: UUID | None
    fork_event_sequence: SafePositiveInteger | None
    name: Annotated[str, Field(min_length=1, max_length=255)]
    visibility_ceiling: MemoryVisibility
    sealed: bool

    @field_validator("branch_id", "parent_branch_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @model_validator(mode="after")
    def validate_parent(self) -> BranchView:
        if (self.parent_branch_id is None) != (self.fork_event_sequence is None):
            raise ValueError("branch parent and fork sequence must be supplied together")
        return self


class SelectionEventRecord(ReadModel):
    """Event-only selection history; current memory payloads do not belong here."""

    event_id: UUID
    sequence: SafePositiveInteger
    operation: EventOperation
    memory_id: UUID | None = None
    created_at: datetime

    @field_validator("event_id", "memory_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return normalize_utc_datetime(value)

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, value: datetime) -> str:
        return format_utc_datetime(value)


class SelectionDecisionView(ReadModel):
    """Content-free, authorization-filtered selection policy audit record."""

    selection_sequence: SafePositiveInteger
    decision_id: UUID
    profile_version: Literal["selection-v1"] = "selection-v1"
    profile_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    matched_rule_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=128)], ...],
        Field(max_length=16),
    ]
    outcome: Literal["omit", "reject", "candidate", "active", "promoted", "expired"]
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)], ...],
        Field(max_length=8),
    ]
    memory_id: UUID | None
    event_id: UUID | None
    decided_at: datetime

    @field_validator("decision_id", "memory_id", "event_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        return _uuid7(value, str(getattr(info, "field_name", "identifier")))

    @field_validator("decided_at")
    @classmethod
    def normalize_decided_at(cls, value: datetime) -> datetime:
        return normalize_utc_datetime(value)

    @field_serializer("decided_at", when_used="json")
    def serialize_decided_at(self, value: datetime) -> str:
        return format_utc_datetime(value)

    @model_validator(mode="after")
    def validate_codes(self) -> SelectionDecisionView:
        if len(self.matched_rule_ids) != len(set(self.matched_rule_ids)):
            raise ValueError("matched selection rules must be unique")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("selection reason codes must be unique")
        return self


class ChannelState(ReadModel):
    availability: Literal["available", "unavailable", "warming", "stale"]
    reason: (
        Literal[
            "not_applicable",
            "no_active_model",
            "embedding_missing",
            "embedding_stale",
            "backfill_in_progress",
            "dependency_unavailable",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def validate_reason(self) -> ChannelState:
        if (self.availability == "available") != (self.reason is None):
            raise ValueError("available channels have no reason; unavailable channels require one")
        return self


class ChannelAvailability(ReadModel):
    lexical: ChannelState
    trigram: ChannelState
    semantic: ChannelState


class RetrievalProfileInfo(ReadModel):
    name: Literal["rrf-v1"] = "rrf-v1"
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    active_embedding_model_id: UUID | None = None
    channels: ChannelAvailability

    @field_validator("active_embedding_model_id")
    @classmethod
    def validate_model_id(cls, value: UUID | None) -> UUID | None:
        return _uuid7(value, "active_embedding_model_id")


class BudgetMetadata(ReadModel):
    estimator: Literal["utf8-bytes-upper-bound-v1"] = "utf8-bytes-upper-bound-v1"
    requested_units: Annotated[int, Field(ge=1, le=1_000_000)]
    used_units: Annotated[int, Field(ge=1, le=262_144)]
    serialized_bytes: Annotated[int, Field(ge=1, le=262_144)]
    byte_ceiling: Literal[262144] = 262_144
    truncated: bool
    omission_reasons: Annotated[tuple[OmissionReason, ...], Field(max_length=4)] = ()

    @model_validator(mode="after")
    def validate_budget(self) -> BudgetMetadata:
        if len(set(self.omission_reasons)) != len(self.omission_reasons):
            raise ValueError("budget omission reasons must be unique")
        if self.used_units > self.requested_units:
            raise ValueError("read result exceeds its requested budget")
        if self.used_units != self.serialized_bytes:
            raise ValueError("v1 estimator units must equal serialized UTF-8 bytes")
        budget_truncated = any(
            reason in {"budget_truncated", "item_budget_reached"}
            for reason in self.omission_reasons
        )
        if budget_truncated != self.truncated:
            raise ValueError("budget truncation flag and reasons must agree")
        return self


class PaginationMetadata(ReadModel):
    next_cursor: OpaqueCursor | None = None
    has_more: bool = False

    @model_validator(mode="after")
    def validate_cursor(self) -> PaginationMetadata:
        if self.has_more != (self.next_cursor is not None):
            raise ValueError("pagination cursor and has_more must agree")
        return self


class ReadResultMetadata(ReadModel):
    pagination: PaginationMetadata | None = None
    retrieval: RetrievalProfileInfo | None = None
    budget: BudgetMetadata | None = None


class ContextPackMetadata(ReadResultMetadata):
    pagination: None
    retrieval: RetrievalProfileInfo
    budget: BudgetMetadata


class MemorySearchPage(ReadModel):
    query_id: UUID
    hits: Annotated[tuple[MemoryHit, ...], Field(max_length=100)]

    @field_validator("query_id")
    @classmethod
    def validate_query_id(cls, value: UUID) -> UUID:
        return _uuid7(value, "query_id")  # type: ignore[return-value]


class MemoryGetPayload(ReadModel):
    memory: MemoryHit
    conflicts: Annotated[tuple[ConflictGroup, ...], Field(max_length=100)] = ()


class MemoryTimelinePayload(ReadModel):
    events: Annotated[tuple[TimelineEvent, ...], Field(max_length=200)]


class MemoryConflictsPayload(ReadModel):
    conflicts: Annotated[tuple[ConflictGroup, ...], Field(max_length=100)]


class MemoryLineagePayload(ReadModel):
    branch: BranchView


class MemorySelectionHistoryPayload(ReadModel):
    events: Annotated[tuple[SelectionEventRecord, ...], Field(max_length=200)]


class MemorySelectionDecisionsPayload(ReadModel):
    decisions: Annotated[tuple[SelectionDecisionView, ...], Field(max_length=200)]


class ReadResultBase(ReadModel):
    ok: Literal[True] = True
    contract_version: ReadContractVersion = "mcp-read-v1"
    tool: Literal[
        "memory_context_pack",
        "memory_search",
        "memory_get",
        "memory_timeline",
        "memory_conflicts",
        "memory_lineage",
        "memory_selection_history",
    ]
    warnings: Annotated[tuple[ReadWarningCode, ...], Field(max_length=8)] = ()
    metadata: ReadResultMetadata

    @field_validator("warnings")
    @classmethod
    def validate_warnings(cls, value: tuple[ReadWarningCode, ...]) -> tuple[ReadWarningCode, ...]:
        if len(set(value)) != len(value):
            raise ValueError("read warnings must be unique")
        return value


class ContextPackResult(ReadResultBase):
    tool: Literal["memory_context_pack"] = "memory_context_pack"
    result: ContextPack
    metadata: ContextPackMetadata


class MemorySearchResult(ReadResultBase):
    tool: Literal["memory_search"] = "memory_search"
    result: MemorySearchPage


class MemoryGetResult(ReadResultBase):
    tool: Literal["memory_get"] = "memory_get"
    result: MemoryGetPayload


class MemoryTimelineResult(ReadResultBase):
    tool: Literal["memory_timeline"] = "memory_timeline"
    result: MemoryTimelinePayload


class MemoryConflictsResult(ReadResultBase):
    tool: Literal["memory_conflicts"] = "memory_conflicts"
    result: MemoryConflictsPayload


class MemoryLineageResult(ReadResultBase):
    tool: Literal["memory_lineage"] = "memory_lineage"
    result: MemoryLineagePayload


class MemorySelectionHistoryResult(ReadResultBase):
    tool: Literal["memory_selection_history"] = "memory_selection_history"
    result: MemorySelectionHistoryPayload


class MemorySelectionDecisionsResult(ReadModel):
    ok: Literal[True] = True
    contract_version: ReadContractVersionV2 = "mcp-read-v2"
    tool: Literal["memory_selection_decisions"] = "memory_selection_decisions"
    result: MemorySelectionDecisionsPayload
    warnings: tuple[()] = ()
    metadata: ReadResultMetadata


class ReadErrorBody(ReadModel):
    SAFE_MESSAGES: ClassVar[dict[str, str]] = {
        "invalid_input": "The read input is invalid.",
        "unauthenticated": "Authentication is required.",
        "forbidden": "The authenticated caller is not permitted to perform this read.",
        "not_found": "The requested resource was not found.",
        "invalid_cursor": "The pagination cursor is invalid for this read.",
        "budget_too_small": "The requested budget cannot fit a valid result.",
        "dependency_unavailable": "A required dependency is unavailable.",
        "internal_error": "The read could not be completed.",
    }

    code: Literal[
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "not_found",
        "invalid_cursor",
        "budget_too_small",
        "dependency_unavailable",
        "internal_error",
    ]
    message: Annotated[str, Field(min_length=1, max_length=512)]
    retryable: bool = False
    retry_after_ms: Annotated[int | None, Field(ge=0, le=60_000)] = None
    details: None = None

    @model_validator(mode="after")
    def validate_safe_message(self) -> ReadErrorBody:
        if self.message != self.SAFE_MESSAGES[self.code]:
            raise ValueError("read error must use its safe message")
        if self.retry_after_ms is not None and not self.retryable:
            raise ValueError("retry timing requires a retryable error")
        return self


class ReadError(ReadModel):
    ok: Literal[False] = False
    contract_version: ReadContractVersion = "mcp-read-v1"
    error: ReadErrorBody


class ReadErrorV2(ReadModel):
    ok: Literal[False] = False
    contract_version: ReadContractVersionV2 = "mcp-read-v2"
    error: ReadErrorBody


type ReadResponseV2 = MemorySelectionDecisionsResult | ReadErrorV2


type SemanticReadResult = (
    ContextPackResult
    | MemorySearchResult
    | MemoryGetResult
    | MemoryTimelineResult
    | MemoryConflictsResult
    | MemoryLineageResult
    | MemorySelectionHistoryResult
    | ReadError
)

type ReadSuccess = (
    ContextPackResult
    | MemorySearchResult
    | MemoryGetResult
    | MemoryTimelineResult
    | MemoryConflictsResult
    | MemoryLineageResult
    | MemorySelectionHistoryResult
)
type ReadResponse = ReadSuccess | ReadError
