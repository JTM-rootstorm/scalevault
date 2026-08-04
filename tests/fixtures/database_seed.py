"""Synthetic Milestone 2 database rows with no import-time database access."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kivra_memory.domain.enums import EventOperation
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.base import Base
from kivra_memory.storage.models import (
    Actor,
    Branch,
    Client,
    Lineage,
    Persona,
    Tenant,
    TransportBinding,
    TransportInstallation,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from uuid import UUID

type SeedRow = dict[str, object]
type SeedRows = dict[str, tuple[SeedRow, ...]]

_SEED_TIMESTAMP_MS = 1_767_225_600_000
_CREATED_AT = datetime(2026, 1, 1, tzinfo=UTC)

_MODEL_ORDER: tuple[tuple[str, type[Base]], ...] = (
    ("tenants", Tenant),
    ("actors", Actor),
    ("personas", Persona),
    ("lineages", Lineage),
    ("branches", Branch),
    ("clients", Client),
    ("transport_installations", TransportInstallation),
    ("transport_bindings", TransportBinding),
)


def _seed_uuid(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_SEED_TIMESTAMP_MS, random_bits=ordinal)


def seed_rows() -> SeedRows:
    """Return a fresh deterministic row set containing only synthetic test identities."""

    tenant_id = _seed_uuid(1)
    user_actor_id = _seed_uuid(2)
    persona_actor_id = _seed_uuid(3)
    persona_id = _seed_uuid(4)
    lineage_id = _seed_uuid(5)
    branch_id = _seed_uuid(6)
    direct_client_id = _seed_uuid(7)
    relay_client_id = _seed_uuid(8)
    github_client_id = _seed_uuid(9)
    installation_id = _seed_uuid(10)
    direct_binding_id = _seed_uuid(11)
    relay_binding_id = _seed_uuid(12)
    github_binding_id = _seed_uuid(13)

    all_operations = [operation.value for operation in EventOperation]
    relay_operations = [
        operation.value
        for operation in EventOperation
        if operation
        not in {
            EventOperation.BRANCH_CREATED,
            EventOperation.TOMBSTONED,
            EventOperation.PAYLOAD_PURGE_COMPLETED,
        }
    ]
    proposal_operations = [EventOperation.OBSERVED.value, EventOperation.REMEMBERED.value]

    return {
        "tenants": (
            {
                "tenant_id": tenant_id,
                "slug": "synthetic-test",
                "display_name": "Synthetic Test Tenant",
                "state": "active",
                "created_at": _CREATED_AT,
                "updated_at": _CREATED_AT,
            },
        ),
        "actors": (
            {
                "actor_id": user_actor_id,
                "tenant_id": tenant_id,
                "handle": "synthetic-user",
                "display_name": "Synthetic Test User",
                "kind": "user",
                "metadata_": {"fixture_role": "user"},
                "created_at": _CREATED_AT,
                "revoked_at": None,
            },
            {
                "actor_id": persona_actor_id,
                "tenant_id": tenant_id,
                "handle": "synthetic-persona",
                "display_name": "Synthetic Test Persona",
                "kind": "persona",
                "metadata_": {"fixture_role": "persona"},
                "created_at": _CREATED_AT,
                "revoked_at": None,
            },
        ),
        "personas": (
            {
                "persona_id": persona_id,
                "tenant_id": tenant_id,
                "actor_id": persona_actor_id,
                "slug": "synthetic-persona",
                "display_name": "Synthetic Test Persona",
                "baseline_policy": {"visibility_ceiling": "private_root"},
                "created_at": _CREATED_AT,
                "retired_at": None,
            },
        ),
        "lineages": (
            {
                "lineage_id": lineage_id,
                "tenant_id": tenant_id,
                "persona_id": persona_id,
                "name": "synthetic-root",
                "created_at": _CREATED_AT,
                "sealed_at": None,
            },
        ),
        "branches": (
            {
                "branch_id": branch_id,
                "tenant_id": tenant_id,
                "lineage_id": lineage_id,
                "parent_branch_id": None,
                "fork_event_sequence": None,
                "name": "root",
                "visibility_ceiling": "private_root",
                "created_at": _CREATED_AT,
                "sealed_at": None,
            },
        ),
        "clients": (
            {
                "client_id": direct_client_id,
                "tenant_id": tenant_id,
                "public_id": "synthetic-direct-client",
                "display_name": "Synthetic Direct Client",
                "kind": "interactive",
                "transport_kind": "direct_private",
                "scopes": ["memory:read", "memory:write"],
                "capability_profile": {"profile": "private-read-write"},
                "created_at": _CREATED_AT,
                "revoked_at": None,
            },
            {
                "client_id": relay_client_id,
                "tenant_id": tenant_id,
                "public_id": "synthetic-relay-client",
                "display_name": "Synthetic Relay Client",
                "kind": "interactive",
                "transport_kind": "relay",
                "scopes": ["memory:read", "memory:write"],
                "capability_profile": {"profile": "relay-read-write"},
                "created_at": _CREATED_AT,
                "revoked_at": None,
            },
            {
                "client_id": github_client_id,
                "tenant_id": tenant_id,
                "public_id": "synthetic-github-ingress-client",
                "display_name": "Synthetic GitHub Ingress Client",
                "kind": "ingress",
                "transport_kind": "github_ingress",
                "scopes": ["memory:propose"],
                "capability_profile": {"profile": "proposal-only"},
                "created_at": _CREATED_AT,
                "revoked_at": None,
            },
        ),
        "transport_installations": (
            {
                "installation_id": installation_id,
                "tenant_id": tenant_id,
                "route_key": "synthetic-test-node",
                "relay_hostname": "relay.invalid",
                "capability_profile": {"profile": "synthetic-test"},
                "enrolled_at": _CREATED_AT,
                "revoked_at": None,
                "last_seen_at": None,
                "health_state": "healthy",
            },
        ),
        "transport_bindings": (
            {
                "transport_binding_id": direct_binding_id,
                "tenant_id": tenant_id,
                "actor_id": persona_actor_id,
                "client_id": direct_client_id,
                "transport_kind": "direct_private",
                "disclosure_boundary": "private_node",
                "installation_id": None,
                "authorized_operations": {"operations": list(all_operations)},
                "created_at": _CREATED_AT,
                "valid_until": None,
            },
            {
                "transport_binding_id": relay_binding_id,
                "tenant_id": tenant_id,
                "actor_id": persona_actor_id,
                "client_id": relay_client_id,
                "transport_kind": "relay",
                "disclosure_boundary": "public_relay",
                "installation_id": installation_id,
                "authorized_operations": {"operations": relay_operations},
                "created_at": _CREATED_AT,
                "valid_until": None,
            },
            {
                "transport_binding_id": github_binding_id,
                "tenant_id": tenant_id,
                "actor_id": persona_actor_id,
                "client_id": github_client_id,
                "transport_kind": "github_ingress",
                "disclosure_boundary": "github_com",
                "installation_id": installation_id,
                "authorized_operations": {"operations": proposal_operations},
                "created_at": _CREATED_AT,
                "valid_until": None,
            },
        ),
    }


def insert_seed_rows(session: Session | AsyncSession) -> tuple[Base, ...]:
    """Stage synthetic rows in dependency order without flushing or committing the session."""

    rows = seed_rows()
    instances = tuple(
        model(**row) for table_name, model in _MODEL_ORDER for row in rows[table_name]
    )
    session.add_all(instances)
    return instances
