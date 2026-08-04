"""Closed v1 category, scope, visibility, and transport constraints."""

from dataclasses import dataclass
from uuid import UUID

from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
    TransportKind,
)
from kivra_memory.domain.errors import DomainConstraintError
from kivra_memory.domain.identifiers import require_uuid7

ALL_ONTOLOGICAL_STATUSES = frozenset(OntologicalStatus)
CATEGORY_ONTOLOGY_COMPATIBILITY: dict[MemoryCategory, frozenset[OntologicalStatus]] = {
    MemoryCategory.STABLE_FACT: frozenset(
        {OntologicalStatus.LITERAL_USER_FACT, OntologicalStatus.LITERAL_TECHNICAL_FACT}
    ),
    MemoryCategory.USER_PREFERENCE: frozenset(
        {OntologicalStatus.LITERAL_USER_FACT, OntologicalStatus.UNCERTAIN}
    ),
    MemoryCategory.ASSISTANT_PREFERENCE_LIKE_PATTERN: frozenset(
        {
            OntologicalStatus.ASSISTANT_SELF_DESCRIPTION,
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            OntologicalStatus.HYPOTHESIS,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.BOUNDARY_OR_PERMISSION: frozenset(
        {
            OntologicalStatus.LITERAL_USER_FACT,
            OntologicalStatus.INTERACTION_CONVENTION,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.INTERACTION_CONVENTION: frozenset(
        {
            OntologicalStatus.INTERACTION_CONVENTION,
            OntologicalStatus.LITERAL_USER_FACT,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.RELATIONSHIP_PATTERN: frozenset(
        {
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            OntologicalStatus.INTERACTION_CONVENTION,
            OntologicalStatus.HYPOTHESIS,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.EMERGENT_TENDENCY: frozenset(
        {
            OntologicalStatus.ASSISTANT_SELF_DESCRIPTION,
            OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            OntologicalStatus.HYPOTHESIS,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.EPISODIC_ANCHOR: ALL_ONTOLOGICAL_STATUSES - {OntologicalStatus.HYPOTHESIS},
    MemoryCategory.PROJECT_DECISION: frozenset(
        {OntologicalStatus.LITERAL_TECHNICAL_FACT, OntologicalStatus.UNCERTAIN}
    ),
    MemoryCategory.PROJECT_STATE: frozenset(
        {OntologicalStatus.LITERAL_TECHNICAL_FACT, OntologicalStatus.UNCERTAIN}
    ),
    MemoryCategory.PROCEDURE: frozenset(
        {
            OntologicalStatus.LITERAL_TECHNICAL_FACT,
            OntologicalStatus.INTERACTION_CONVENTION,
            OntologicalStatus.UNCERTAIN,
        }
    ),
    MemoryCategory.OPEN_QUESTION: frozenset(
        {OntologicalStatus.HYPOTHESIS, OntologicalStatus.UNCERTAIN}
    ),
    MemoryCategory.INTERPRETATION: frozenset(
        {OntologicalStatus.HYPOTHESIS, OntologicalStatus.UNCERTAIN}
    ),
    MemoryCategory.EXTERNAL_FACT: frozenset(
        {
            OntologicalStatus.LITERAL_TECHNICAL_FACT,
            OntologicalStatus.HYPOTHESIS,
            OntologicalStatus.UNCERTAIN,
        }
    ),
}

SCOPED_SUBJECT_KINDS: dict[MemoryScope, SubjectKind] = {
    MemoryScope.PERSONA: SubjectKind.PERSONA,
    MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
    MemoryScope.PROJECT: SubjectKind.PROJECT,
    MemoryScope.EPISODIC: SubjectKind.EPISODE,
}


@dataclass(frozen=True, slots=True)
class MemoryConstraintContext:
    """Non-content facts required to validate a memory after-image."""

    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    status: MemoryStatus
    sensitivity: int
    subject_kind: SubjectKind
    origin_session_id: UUID | None
    origin_session_matches: bool
    structural_anchor_matches: bool
    imported_provenance: bool
    publication_approved: bool
    branch_allows_visibility: bool
    transport_kind: TransportKind


def _reject(code: str, message: str) -> None:
    raise DomainConstraintError(code, message)


def validate_category_ontology(
    category: MemoryCategory,
    ontological_status: OntologicalStatus,
) -> None:
    """Reject any category/status pair outside ADR 0008's closed v1 matrix."""

    allowed = CATEGORY_ONTOLOGY_COMPATIBILITY.get(category)
    if allowed is None or ontological_status not in allowed:
        _reject(
            "category_ontology_incompatible",
            "memory category and ontological status are incompatible",
        )


def validate_memory_constraints(context: MemoryConstraintContext) -> None:
    """Validate the stable structural semantic rules accepted in ADR 0008."""

    enum_fields = (
        (context.category, MemoryCategory),
        (context.ontological_status, OntologicalStatus),
        (context.scope, MemoryScope),
        (context.visibility, MemoryVisibility),
        (context.status, MemoryStatus),
        (context.subject_kind, SubjectKind),
        (context.transport_kind, TransportKind),
    )
    if any(not isinstance(value, expected_type) for value, expected_type in enum_fields):
        _reject("invalid_contract_enum", "memory constraint context contains an invalid enum")
    boolean_fields = (
        context.origin_session_matches,
        context.structural_anchor_matches,
        context.imported_provenance,
        context.publication_approved,
        context.branch_allows_visibility,
    )
    if any(type(value) is not bool for value in boolean_fields):
        _reject("invalid_context_flag", "memory constraint flags must be boolean")
    if context.origin_session_id is not None:
        try:
            require_uuid7(context.origin_session_id, field_name="origin_session_id")
        except ValueError:
            _reject("invalid_origin_session", "origin session must be an RFC 9562 UUIDv7")

    validate_category_ontology(context.category, context.ontological_status)
    if isinstance(context.sensitivity, bool) or not 0 <= context.sensitivity <= 4:
        _reject("sensitivity_out_of_range", "memory sensitivity must be between zero and four")
    if not context.branch_allows_visibility:
        _reject("branch_visibility_forbidden", "branch does not allow the requested visibility")

    if context.scope is MemoryScope.GLOBAL:
        if context.subject_kind is not SubjectKind.GLOBAL:
            _reject("scope_subject_mismatch", "global memory requires a global subject")
        if context.ontological_status is OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE:
            _reject(
                "global_roleplay_forbidden",
                "global memory cannot describe a fictional or roleplayed scene",
            )

    expected_subject_kind = SCOPED_SUBJECT_KINDS.get(context.scope)
    if expected_subject_kind is not None and context.subject_kind is not expected_subject_kind:
        _reject("scope_subject_mismatch", "memory scope does not match its typed subject")
    if expected_subject_kind is not None and not context.structural_anchor_matches:
        _reject("scope_anchor_mismatch", "memory scope does not match its structural anchor")

    if context.scope is MemoryScope.EPISODIC and not (
        (context.origin_session_id is not None and context.origin_session_matches)
        or context.imported_provenance
    ):
        _reject(
            "episodic_origin_missing",
            "episodic memory requires a matching origin session or import provenance",
        )

    if context.scope is MemoryScope.SCENE_LOCAL:
        if context.subject_kind is not SubjectKind.SCENE:
            _reject("scope_subject_mismatch", "scene-local memory requires a scene subject")
        if not context.structural_anchor_matches:
            _reject(
                "scope_anchor_mismatch",
                "scene-local memory does not match its structural anchor",
            )
        if context.origin_session_id is None or not context.origin_session_matches:
            _reject(
                "scene_origin_mismatch",
                "scene-local memory requires its matching origin session",
            )
        if context.visibility in {MemoryVisibility.SHAREABLE, MemoryVisibility.PUBLIC_SEED}:
            _reject(
                "scene_visibility_forbidden",
                "scene-local memory cannot be shareable or public seed",
            )

    if context.visibility is MemoryVisibility.SHAREABLE and context.sensitivity > 1:
        _reject(
            "shareable_sensitive",
            "shareable memory cannot have sensitivity above one",
        )

    if context.visibility is MemoryVisibility.PUBLIC_SEED:
        if context.status is not MemoryStatus.ACTIVE:
            _reject("public_seed_not_active", "public seed memory must be active")
        if context.sensitivity != 0:
            _reject("public_seed_sensitive", "public seed memory must have zero sensitivity")
        if not context.publication_approved:
            _reject(
                "public_seed_unapproved",
                "public seed memory requires explicit publication approval",
            )

    if context.transport_kind is TransportKind.GITHUB_INGRESS and context.scope in {
        MemoryScope.GLOBAL,
        MemoryScope.SCENE_LOCAL,
    }:
        _reject(
            "github_scope_forbidden",
            "GitHub ingress cannot create global or scene-local memory",
        )
    if context.transport_kind is TransportKind.RELAY and context.sensitivity == 4:
        _reject(
            "relay_sensitivity_forbidden",
            "relay transport cannot carry sensitivity-four memory",
        )
