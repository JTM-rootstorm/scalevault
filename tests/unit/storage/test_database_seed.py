from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import UUID

from kivra_memory.domain.enums import EventOperation
from kivra_memory.domain.identifiers import is_uuid7
from kivra_memory.storage.models import (
    Actor,
    Branch,
    Client,
    Lineage,
    Persona,
    Subject,
    Tenant,
    TransportBinding,
    TransportInstallation,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

_REPOSITORY_ROOT = str(Path(__file__).resolve().parents[3])
if _REPOSITORY_ROOT not in sys.path:
    sys.path.insert(0, _REPOSITORY_ROOT)

from tests.fixtures.database_seed import insert_seed_rows, seed_rows  # noqa: E402


def _uuid_values(value: object) -> list[UUID]:
    if isinstance(value, UUID):
        return [value]
    if isinstance(value, Mapping):
        return [item for nested in value.values() for item in _uuid_values(nested)]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [item for nested in value for item in _uuid_values(nested)]
    return []


def test_seed_rows_are_deterministic_and_all_identifiers_are_uuid7() -> None:
    first = seed_rows()
    second = seed_rows()

    assert first == second
    identifiers = _uuid_values(first)
    assert identifiers
    assert all(is_uuid7(identifier) for identifier in identifiers)
    assert len(set(identifiers)) == 14


def test_seed_rows_preserve_tenant_lineage_and_foreign_key_consistency() -> None:
    rows = seed_rows()
    tenant_id = cast(UUID, rows["tenants"][0]["tenant_id"])
    assert all(
        row["tenant_id"] == tenant_id
        for table_rows in rows.values()
        for row in table_rows
        if "tenant_id" in row
    )

    actor_ids = {row["actor_id"] for row in rows["actors"]}
    client_ids = {row["client_id"] for row in rows["clients"]}
    installation_ids = {row["installation_id"] for row in rows["transport_installations"]}
    persona = rows["personas"][0]
    lineage = rows["lineages"][0]
    branch = rows["branches"][0]
    subject = rows["subjects"][0]

    assert persona["actor_id"] in actor_ids
    assert lineage["persona_id"] == persona["persona_id"]
    assert branch["lineage_id"] == lineage["lineage_id"]
    assert branch["parent_branch_id"] is None
    assert branch["fork_event_sequence"] is None
    assert subject["lineage_id"] == lineage["lineage_id"]
    assert subject["kind"] == "global"
    assert all(
        subject[field] is None
        for field in (
            "persona_id",
            "relationship_actor_id",
            "project_ref",
            "episode_ref",
            "origin_session_id",
        )
    )

    for binding in rows["transport_bindings"]:
        assert binding["actor_id"] in actor_ids
        assert binding["client_id"] in client_ids
        if binding["installation_id"] is not None:
            assert binding["installation_id"] in installation_ids


def test_seed_has_required_clients_bindings_and_fail_closed_authorization_shape() -> None:
    rows = seed_rows()
    clients = {row["transport_kind"]: row for row in rows["clients"]}
    bindings = {row["transport_kind"]: row for row in rows["transport_bindings"]}
    required_transports = {"direct_private", "relay", "github_ingress"}

    assert set(clients) == required_transports
    assert set(bindings) == required_transports
    assert clients["direct_private"]["scopes"] == ["memory:read", "memory:write"]
    assert clients["relay"]["scopes"] == ["memory:read", "memory:write"]
    assert clients["github_ingress"]["scopes"] == ["memory:propose"]
    assert bindings["direct_private"]["disclosure_boundary"] == "private_node"
    assert bindings["relay"]["disclosure_boundary"] == "public_relay"
    assert bindings["github_ingress"]["disclosure_boundary"] == "github_com"
    known_operations = {operation.value for operation in EventOperation}
    for binding in bindings.values():
        authorization = cast(dict[str, object], binding["authorized_operations"])
        assert set(authorization) == {"operations"}
        operations = cast(list[object], authorization["operations"])
        assert operations
        assert all(isinstance(operation, str) for operation in operations)
        assert set(cast(list[str], operations)) <= known_operations
    assert bindings["github_ingress"]["authorized_operations"] == {
        "operations": ["observed", "remembered"]
    }
    assert bindings["direct_private"]["authorized_operations"] == {
        "operations": [operation.value for operation in EventOperation]
    }
    relay_operations = cast(
        list[str],
        cast(dict[str, object], bindings["relay"]["authorized_operations"])["operations"],
    )
    assert set(relay_operations).isdisjoint(
        {"branch_created", "tombstoned", "payload_purge_completed"}
    )
    assert {
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
        "visibility_changed",
    } == set(relay_operations)


def test_seed_contains_only_neutral_synthetic_data_and_no_secret_material() -> None:
    rows = seed_rows()
    rendered = repr(rows).lower()
    keys = {str(key) for table_rows in rows.values() for row in table_rows for key in row}

    assert "synthetic" in rendered
    assert "mike" not in rendered
    assert "kivra" not in rendered
    assert {
        "access_token",
        "authorization",
        "certificate_sha256",
        "credential",
        "evidence_excerpt",
        "memory_statement",
        "password",
        "private_key",
        "secret",
        "secret_hash",
        "statement",
    }.isdisjoint(keys)
    for forbidden in (
        "password",
        "private_key",
        "access_token",
        "memory_statement",
        "evidence_excerpt",
    ):
        assert forbidden not in rendered


def test_insert_seed_rows_stages_models_in_dependency_order_without_io() -> None:
    session = Session()
    try:
        assert not session.new
        instances = insert_seed_rows(session)

        assert tuple(type(instance) for instance in instances) == (
            Tenant,
            Actor,
            Actor,
            Persona,
            Lineage,
            Branch,
            Subject,
            Client,
            Client,
            Client,
            TransportInstallation,
            TransportBinding,
            TransportBinding,
            TransportBinding,
        )
        assert set(session.new) == set(instances)
    finally:
        session.close()


async def test_insert_seed_rows_accepts_async_session_without_database_io() -> None:
    session = AsyncSession()
    try:
        instances = insert_seed_rows(session)
        assert set(session.new) == set(instances)
    finally:
        await session.close()
