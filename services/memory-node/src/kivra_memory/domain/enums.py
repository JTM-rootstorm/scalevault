"""Closed vocabularies in the ScaleVault v1 memory domain contract."""

from enum import StrEnum


class MemoryCategory(StrEnum):
    """The semantic category of a durable memory."""

    STABLE_FACT = "stable_fact"
    USER_PREFERENCE = "user_preference"
    ASSISTANT_PREFERENCE_LIKE_PATTERN = "assistant_preference_like_pattern"
    BOUNDARY_OR_PERMISSION = "boundary_or_permission"
    INTERACTION_CONVENTION = "interaction_convention"
    RELATIONSHIP_PATTERN = "relationship_pattern"
    EMERGENT_TENDENCY = "emergent_tendency"
    EPISODIC_ANCHOR = "episodic_anchor"
    PROJECT_DECISION = "project_decision"
    PROJECT_STATE = "project_state"
    PROCEDURE = "procedure"
    OPEN_QUESTION = "open_question"
    INTERPRETATION = "interpretation"
    EXTERNAL_FACT = "external_fact"


class OntologicalStatus(StrEnum):
    """How a memory statement relates to literal, observed, or fictional reality."""

    LITERAL_USER_FACT = "literal_user_fact"
    LITERAL_TECHNICAL_FACT = "literal_technical_fact"
    ASSISTANT_SELF_DESCRIPTION = "assistant_self_description"
    OBSERVED_ASSISTANT_BEHAVIOR = "observed_assistant_behavior"
    INTERACTION_CONVENTION = "interaction_convention"
    FICTIONAL_OR_ROLEPLAYED_SCENE = "fictional_or_roleplayed_scene"
    HYPOTHESIS = "hypothesis"
    UNCERTAIN = "uncertain"


class MemoryScope(StrEnum):
    GLOBAL = "global"
    PERSONA = "persona"
    RELATIONSHIP = "relationship"
    PROJECT = "project"
    EPISODIC = "episodic"
    SCENE_LOCAL = "scene_local"


class MemoryVisibility(StrEnum):
    PRIVATE_ROOT = "private_root"
    RESTRICTED = "restricted"
    SHAREABLE = "shareable"
    PUBLIC_SEED = "public_seed"


class MemoryStatus(StrEnum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    DISPUTED = "disputed"
    SUPERSEDED = "superseded"
    RETIRED = "retired"
    TOMBSTONED = "tombstoned"


class AuthorityClass(StrEnum):
    EXPLICIT_USER_CORRECTION = "explicit_user_correction"
    EXPLICIT_USER_STATEMENT = "explicit_user_statement"
    VERIFIED_PROJECT_SOURCE = "verified_project_source"
    ASSISTANT_OBSERVATION = "assistant_observation"
    ASSISTANT_INTERPRETATION = "assistant_interpretation"
    EXTERNAL_SOURCE = "external_source"
    IMPORTED_LEGACY_MEMORY = "imported_legacy_memory"


class EventOperation(StrEnum):
    OBSERVED = "observed"
    REMEMBERED = "remembered"
    CANDIDATE_PROMOTED = "candidate_promoted"
    CANDIDATE_EXPIRED = "candidate_expired"
    REVISED = "revised"
    LINKED = "linked"
    CONFLICT_OPENED = "conflict_opened"
    CONFLICT_RESOLVED = "conflict_resolved"
    SUPERSEDED = "superseded"
    RETIRED = "retired"
    TOMBSTONED = "tombstoned"
    BRANCH_CREATED = "branch_created"
    VISIBILITY_CHANGED = "visibility_changed"
    EVIDENCE_ATTACHED = "evidence_attached"
    EVIDENCE_REDACTED = "evidence_redacted"
    UNLINKED = "unlinked"
    PAYLOAD_PURGE_COMPLETED = "payload_purge_completed"


class LinkType(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    REFINES = "refines"
    CAUSED_BY = "caused_by"
    ASSOCIATED_WITH = "associated_with"
    SUPERSEDES = "supersedes"
    PART_OF = "part_of"
    FORKED_FROM = "forked_from"


class IngressState(StrEnum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class TransportKind(StrEnum):
    DIRECT_PRIVATE = "direct_private"
    SECURE_TUNNEL = "secure_tunnel"
    RELAY = "relay"
    GITHUB_INGRESS = "github_ingress"
    INTERNAL_SERVICE = "internal_service"
    ARCHIVE_RESTORE = "archive_restore"


class SubjectKind(StrEnum):
    GLOBAL = "global"
    PERSONA = "persona"
    RELATIONSHIP = "relationship"
    PROJECT = "project"
    EPISODE = "episode"
    SCENE = "scene"
    CONCEPT = "concept"


class ProposalOperation(StrEnum):
    """Operations accepted by the legacy GitHub proposal transport DTO."""

    OBSERVE = "observe"
    REMEMBER = "remember"


class ProposalConfidenceBasis(StrEnum):
    """Legacy proposal provenance basis, deliberately not a numeric score."""

    EXPLICIT = "explicit"
    VERIFIED = "verified"
    OBSERVED = "observed"
    INTERPRETED = "interpreted"
    UNCERTAIN = "uncertain"


def enum_values[EnumT: StrEnum](enum_type: type[EnumT]) -> tuple[str, ...]:
    """Return stable wire values for parity checks and SQL constraints."""

    return tuple(member.value for member in enum_type)
