"""Focused tests for bearer credential persistence invariants."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.admin.credentials import CredentialAdminError
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.storage.credentials import (
    CredentialStorageError,
    _AdminCredentialState,
    _credential_lookup_statement,
    _CredentialState,
    _identity_from_state,
    _metadata_from_state,
    _monotonic_audit_timestamp,
    _state_is_active,
)
from kivra_memory.storage.models import (
    Actor,
    Client,
    ClientCredential,
    Tenant,
    TransportBinding,
)
from sqlalchemy import Table

from tests.fixtures.database_seed import seed_rows

_NOW = datetime(2026, 8, 9, 18, tzinfo=UTC)


def _id(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _state(
    *,
    actor_kind: str = "agent",
    client_kind: str = "interactive",
    provisioning_contract: object = "scalevault-codex-installation-v1",
) -> _CredentialState:
    tenant_id = _id("tenants", "tenant_id")
    actor_id = _id("actors", "actor_id", 1)
    client_id = _id("clients", "client_id")
    binding_id = _id("transport_bindings", "transport_binding_id")
    credential_id = _id("transport_bindings", "transport_binding_id", 1)
    return _CredentialState(
        tenant=Tenant(
            tenant_id=tenant_id,
            slug="credential-test",
            display_name="Credential Test",
            state="active",
        ),
        actor=Actor(
            actor_id=actor_id,
            tenant_id=tenant_id,
            handle="codex-test",
            display_name="Codex Test",
            kind=actor_kind,
            metadata_={"provisioning_contract": provisioning_contract},
            created_at=_NOW,
        ),
        client=Client(
            client_id=client_id,
            tenant_id=tenant_id,
            public_id="codex-test-client",
            display_name="Codex Test",
            kind=client_kind,
            transport_kind=TransportKind.DIRECT_PRIVATE.value,
            scopes=["memory.write.nominate"],
            capability_profile={
                "contract_version": "scalevault-client-capability-v1",
                "read": None,
            },
            created_at=_NOW,
        ),
        binding=TransportBinding(
            transport_binding_id=binding_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_kind=TransportKind.DIRECT_PRIVATE.value,
            disclosure_boundary="private_node",
            installation_id=None,
            authorized_operations={"operations": ["observed", "remembered"]},
            created_at=_NOW,
        ),
        credential=ClientCredential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=binding_id,
            kind="bearer_token",
            public_hint="codex:integration:test",
            secret_hash=f"hmac-sha256-v1:{'A' * 43}",
            secret_hash_key_id="test-v1",
            created_at=_NOW,
        ),
    )


def _admin_state(state: _CredentialState) -> _AdminCredentialState:
    return _AdminCredentialState(
        credential_id=state.credential.credential_id,
        tenant_id=state.tenant.tenant_id,
        actor_id=state.actor.actor_id,
        client_id=state.client.client_id,
        transport_binding_id=state.binding.transport_binding_id,
        public_hint=state.credential.public_hint,
        created_at=state.credential.created_at,
        expires_at=state.credential.expires_at,
        last_used_at=state.credential.last_used_at,
        revoked_at=state.credential.revoked_at,
        client_scopes=tuple(state.client.scopes),
        capability_profile=state.client.capability_profile,
        actor_metadata={
            "host_label": "jsonb-host",
            "environment_label": "integration",
        },
    )


def test_direct_bearer_requires_agent_actor_and_interactive_client() -> None:
    assert _state_is_active(
        _state(),
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )
    assert not _state_is_active(
        _state(actor_kind="persona"),
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )
    assert not _state_is_active(
        _state(client_kind="operator"),
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )


def test_first_phase_lookup_selects_only_verifier_locator_columns() -> None:
    statement = _credential_lookup_statement(
        _id("tenants", "tenant_id"),
        _id("transport_bindings", "transport_binding_id", 1),
    )
    assert tuple(column.key for column in statement.selected_columns) == (
        "tenant_id",
        "credential_id",
        "secret_hash",
        "secret_hash_key_id",
    )
    assert [cast(Table, table).name for table in statement.get_final_froms()] == [
        "client_credentials"
    ]
    sql = str(statement)
    assert "client_credentials.revoked_at IS NULL" in sql
    assert "client_credentials.created_at <= CURRENT_TIMESTAMP" in sql
    assert "client_credentials.expires_at IS NULL" in sql
    assert "client_credentials.expires_at > CURRENT_TIMESTAMP" in sql
    assert "client_credentials.secret_hash IS NOT NULL" in sql
    assert "client_credentials.secret_hash_key_id IS NOT NULL" in sql
    assert " JOIN " not in sql


def test_direct_bearer_requires_exact_provisioning_marker() -> None:
    for marker in (None, 1, "scalevault-codex-installation-v0"):
        assert not _state_is_active(
            _state(provisioning_contract=marker),
            transport_kind=TransportKind.DIRECT_PRIVATE,
            installation_id=None,
            used_at=_NOW,
        )


def test_active_boundaries_use_database_snapshot_time_exclusively() -> None:
    at_expiry = _state()
    at_expiry.credential.expires_at = _NOW
    assert not _state_is_active(
        at_expiry,
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )

    at_binding_expiry = _state()
    at_binding_expiry.binding.valid_until = _NOW
    assert not _state_is_active(
        at_binding_expiry,
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )

    created_later = _state()
    created_later.credential.created_at = datetime(2026, 8, 9, 18, 0, 1, tzinfo=UTC)
    assert not _state_is_active(
        created_later,
        transport_kind=TransportKind.DIRECT_PRIVATE,
        installation_id=None,
        used_at=_NOW,
    )


def test_last_used_audit_survives_database_clock_rollback() -> None:
    later = datetime(2026, 8, 9, 18, 1, tzinfo=UTC)
    assert _monotonic_audit_timestamp(None, _NOW) == _NOW
    assert _monotonic_audit_timestamp(_NOW, later) == later
    assert _monotonic_audit_timestamp(later, _NOW) == later


def test_jsonb_capability_lists_hydrate_for_authentication_and_metadata() -> None:
    state = _state()
    state.client.capability_profile = {
        "contract_version": "scalevault-client-capability-v1",
        "read": {
            "allowed_memory_scopes": ["persona", "relationship"],
            "allowed_visibilities": ["private_root", "restricted"],
            "max_sensitivity": 3,
            "allow_candidates": False,
        },
    }
    state.client.scopes = ["memory.read.context", "memory.write.nominate"]

    identity = _identity_from_state(state)
    metadata = _metadata_from_state(_admin_state(state))

    identity_read = identity.capability_profile["read"]
    assert isinstance(identity_read, dict)
    assert set(identity_read["allowed_memory_scopes"]) == {"persona", "relationship"}
    assert set(identity_read["allowed_visibilities"]) == {"private_root", "restricted"}
    assert identity_read["max_sensitivity"] == 3
    assert identity_read["allow_candidates"] is False
    assert metadata.capability_profile.read is not None
    assert metadata.capability_profile.read.allowed_memory_scopes == frozenset(
        {MemoryScope.PERSONA, MemoryScope.RELATIONSHIP}
    )
    assert metadata.capability_profile.read.allowed_visibilities == frozenset(
        {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}
    )


@pytest.mark.parametrize(
    "corrupt_profile",
    [
        {
            "contract_version": "scalevault-client-capability-v1",
            "read": {
                "allowed_memory_scopes": ["persona", "persona"],
                "allowed_visibilities": ["private_root"],
                "max_sensitivity": 3,
                "allow_candidates": False,
            },
        },
        {
            "contract_version": "scalevault-client-capability-v1",
            "read": None,
            "unknown": False,
        },
        {
            "contract_version": "scalevault-client-capability-v1",
            "read": {
                "allowed_memory_scopes": ("persona",),
                "allowed_visibilities": ["private_root"],
                "max_sensitivity": 3,
                "allow_candidates": False,
            },
        },
    ],
)
def test_corrupt_jsonb_capability_shape_fails_with_safe_storage_errors(
    corrupt_profile: dict[str, object],
) -> None:
    state = _state()
    state.client.capability_profile = corrupt_profile

    with pytest.raises(CredentialStorageError, match=r"^authentication failed$"):
        _identity_from_state(state)
    with pytest.raises(CredentialAdminError) as caught:
        _metadata_from_state(_admin_state(state))

    assert caught.value.code == "credential_metadata_invalid"


def test_storage_failure_is_content_free() -> None:
    error = CredentialStorageError()
    assert str(error) == "authentication failed"
    assert repr(error) == "CredentialStorageError('authentication failed')"
