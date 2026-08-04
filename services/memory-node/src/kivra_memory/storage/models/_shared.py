"""Relational vocabulary and constraint helpers shared by storage models."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import CheckConstraint

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY

TENANT_TABLE_ARGS = {"info": {TENANT_OWNED_INFO_KEY: True}}

ACTOR_KINDS = ("user", "persona", "agent", "service")
CLIENT_KINDS = ("interactive", "ingress", "worker", "operator")
TRANSPORT_KINDS = (
    "direct_private",
    "secure_tunnel",
    "relay",
    "github_ingress",
    "internal_service",
    "archive_restore",
)
DISCLOSURE_BOUNDARIES = (
    "private_node",
    "openai_secure_tunnel",
    "public_relay",
    "github_com",
    "internal",
    "archive",
)
MEMORY_CATEGORIES = (
    "stable_fact",
    "user_preference",
    "assistant_preference_like_pattern",
    "boundary_or_permission",
    "interaction_convention",
    "relationship_pattern",
    "emergent_tendency",
    "episodic_anchor",
    "project_decision",
    "project_state",
    "procedure",
    "open_question",
    "interpretation",
    "external_fact",
)
ONTOLOGICAL_STATUSES = (
    "literal_user_fact",
    "literal_technical_fact",
    "assistant_self_description",
    "observed_assistant_behavior",
    "interaction_convention",
    "fictional_or_roleplayed_scene",
    "hypothesis",
    "uncertain",
)
MEMORY_SCOPES = ("global", "persona", "relationship", "project", "episodic", "scene_local")
MEMORY_VISIBILITIES = ("private_root", "restricted", "shareable", "public_seed")
MEMORY_STATUSES = ("candidate", "active", "disputed", "superseded", "retired", "tombstoned")
AUTHORITY_CLASSES = (
    "explicit_user_correction",
    "explicit_user_statement",
    "verified_project_source",
    "assistant_observation",
    "assistant_interpretation",
    "external_source",
    "imported_legacy_memory",
)
MEMORY_OPERATIONS = (
    "observed",
    "remembered",
    "revised",
    "linked",
    "unlinked",
    "evidence_attached",
    "evidence_redacted",
    "conflict_opened",
    "conflict_resolved",
    "superseded",
    "retired",
    "tombstoned",
    "branch_created",
    "visibility_changed",
    "payload_purge_completed",
)


def values_check(column: str, values: Sequence[str], *, name: str) -> CheckConstraint:
    """Create a named closed-vocabulary check for a bounded text column."""

    rendered = ", ".join(f"'{value}'" for value in values)
    return CheckConstraint(f"{column} IN ({rendered})", name=name)


def uuid_v7_check(column: str, *, name: str) -> CheckConstraint:
    """Require an externally visible identifier to use RFC 9562 UUIDv7."""

    return CheckConstraint(f"scalevault_is_uuid_v7({column})", name=name)


def json_object_check(column: str, *, name: str) -> CheckConstraint:
    return CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=name)


def json_array_check(column: str, *, name: str) -> CheckConstraint:
    return CheckConstraint(f"jsonb_typeof({column}) = 'array'", name=name)


def sha256_check(column: str, *, name: str) -> CheckConstraint:
    return CheckConstraint(f"octet_length({column}) = 32", name=name)
