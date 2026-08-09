"""Focused tests for bearer credential persistence invariants."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.admin.credentials import CredentialAdminError, SecureTunnelIssuance
from kivra_memory.auth import ClientCapabilityProfile
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.credentials import (
    CredentialStorageError,
    _AdminCredentialState,
    _credential_lookup_statement,
    _credential_reissue_occupancy_statement,
    _CredentialState,
    _identity_from_state,
    _metadata_from_state,
    _monotonic_audit_timestamp,
    _require_matching_secure_tunnel_state,
    _require_secure_tunnel_rotation_state,
    _SecureTunnelAdminState,
    _state_is_active,
    _validate_secure_tunnel_issuance,
)
from kivra_memory.storage.models import (
    Actor,
    Client,
    ClientCredential,
    Tenant,
    TransportBinding,
    TransportInstallation,
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
        installation=None,
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


def _secure_tunnel_state() -> _CredentialState:
    state = _state(
        actor_kind="agent",
        provisioning_contract="scalevault-chatgpt-secure-tunnel-v1",
    )
    installation_id = _id("transport_installations", "installation_id")
    state.client.transport_kind = TransportKind.SECURE_TUNNEL.value
    state.client.scopes = ["memory.read.context", "memory.status.transport"]
    state.binding.transport_kind = TransportKind.SECURE_TUNNEL.value
    state.binding.disclosure_boundary = "openai_secure_tunnel"
    state.binding.installation_id = installation_id
    state.binding.authorized_operations = {"operations": []}
    return replace(
        state,
        installation=TransportInstallation(
            installation_id=installation_id,
            tenant_id=state.tenant.tenant_id,
            route_key="secure-tunnel-test",
            capability_profile={
                "association_mode": "single_chatgpt_workspace",
                "contract_version": "scalevault-secure-tunnel-installation-v1",
            },
            enrolled_at=_NOW,
            health_state="healthy",
        ),
    )


def _secure_tunnel_admin_fixture() -> tuple[SecureTunnelIssuance, _SecureTunnelAdminState]:
    tenant_id = new_uuid7()
    actor_id = new_uuid7()
    client_id = new_uuid7()
    binding_id = new_uuid7()
    installation_id = new_uuid7()
    credential_id = new_uuid7()
    profile = ClientCapabilityProfile(
        contract_version="scalevault-client-capability-v1",
        read=None,
    )
    issuance = SecureTunnelIssuance(
        tenant_id=tenant_id,
        actor_id=actor_id,
        installation_id=installation_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        credential_id=credential_id,
        tunnel_label="workspace-one",
        actor_handle="chatgpt-workspace-one",
        actor_display_name="ChatGPT secure tunnel (workspace-one)",
        actor_metadata={"provisioning_contract": "scalevault-chatgpt-secure-tunnel-v1"},
        installation_route_key=f"chatgpt-workspace-one-{tenant_id}",
        installation_capability_profile={
            "association_mode": "single_chatgpt_workspace",
            "contract_version": "scalevault-secure-tunnel-installation-v1",
        },
        client_public_id=f"chatgpt-secure-tunnel-workspace-one-{tenant_id}",
        client_display_name="ChatGPT secure tunnel (workspace-one)",
        client_scopes=("memory.status.ingress", "memory.status.transport"),
        client_capability_profile=profile,
        public_hint="chatgpt:secure-tunnel:workspace-one",
        secret_hash=f"hmac-sha256-v1:{'A' * 43}",
        secret_hash_key_id="test-v1",
        created_at=_NOW,
        expires_at=None,
    )
    state = _SecureTunnelAdminState(
        credential=_AdminCredentialState(
            credential_id=credential_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=binding_id,
            public_hint=issuance.public_hint,
            created_at=_NOW,
            expires_at=None,
            last_used_at=None,
            revoked_at=None,
            client_scopes=issuance.client_scopes,
            capability_profile=profile.model_dump(mode="json"),
            actor_metadata=issuance.actor_metadata,
        ),
        secret_hash_key_id="test-v1",
        tenant_state="active",
        actor_handle=issuance.actor_handle,
        actor_display_name=issuance.actor_display_name,
        actor_kind="agent",
        actor_revoked_at=None,
        client_public_id=issuance.client_public_id,
        client_display_name=issuance.client_display_name,
        client_kind="interactive",
        client_transport_kind=TransportKind.SECURE_TUNNEL.value,
        client_revoked_at=None,
        binding_transport_kind=TransportKind.SECURE_TUNNEL.value,
        disclosure_boundary="openai_secure_tunnel",
        installation_id=installation_id,
        authorized_operations={"operations": []},
        binding_valid_until=None,
        installation_route_key=issuance.installation_route_key,
        installation_capability_profile=issuance.installation_capability_profile,
        installation_revoked_at=None,
    )
    return issuance, state


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


def test_dr_reissue_rejects_any_client_or_binding_credential_without_actor_scope() -> None:
    statement = _credential_reissue_occupancy_statement(
        tenant_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
    )
    sql = str(statement)

    assert "client_credentials.client_id =" in sql
    assert " OR client_credentials.transport_binding_id =" in sql
    assert "client_credentials.actor_id" not in sql
    assert "client_credentials.revoked_at" not in sql


def test_direct_bearer_requires_exact_provisioning_marker() -> None:
    for marker in (None, 1, "scalevault-codex-installation-v0"):
        assert not _state_is_active(
            _state(provisioning_contract=marker),
            transport_kind=TransportKind.DIRECT_PRIVATE,
            installation_id=None,
            used_at=_NOW,
        )


def test_secure_tunnel_bearer_requires_pinned_active_installation_and_read_only_authority() -> None:
    state = _secure_tunnel_state()
    installation_id = state.binding.installation_id
    assert installation_id is not None

    assert _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=installation_id,
        used_at=_NOW,
    )
    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=_id("tenants", "tenant_id"),
        used_at=_NOW,
    )

    state.client.scopes.append("memory.write.nominate")
    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=installation_id,
        used_at=_NOW,
    )
    state.client.scopes.pop()
    state.binding.authorized_operations = {"operations": ["observed"]}
    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=installation_id,
        used_at=_NOW,
    )


@pytest.mark.parametrize(
    ("actor_kind", "provisioning_contract"),
    [
        ("persona", "scalevault-chatgpt-secure-tunnel-v1"),
        ("agent", None),
        ("agent", "scalevault-codex-installation-v1"),
        ("agent", {"not": "a string"}),
    ],
)
def test_secure_tunnel_bearer_rejects_forged_actor_identity(
    actor_kind: str,
    provisioning_contract: object,
) -> None:
    state = _secure_tunnel_state()
    state.actor.kind = actor_kind
    state.actor.metadata_ = {"provisioning_contract": provisioning_contract}

    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=state.binding.installation_id,
        used_at=_NOW,
    )


@pytest.mark.parametrize(
    "profile",
    [
        {},
        {
            "association_mode": "multiple_chatgpt_workspaces",
            "contract_version": "scalevault-secure-tunnel-installation-v1",
        },
        {
            "association_mode": ["workspace-one", "workspace-two"],
            "contract_version": "scalevault-secure-tunnel-installation-v1",
        },
        {
            "association_mode": "single_chatgpt_workspace",
            "contract_version": "scalevault-secure-tunnel-installation-v0",
        },
        {
            "association_mode": "single_chatgpt_workspace",
            "contract_version": "scalevault-secure-tunnel-installation-v1",
            "workspace_id": "caller-controlled",
        },
    ],
)
def test_secure_tunnel_bearer_rejects_hostile_installation_profile(
    profile: dict[str, object],
) -> None:
    state = _secure_tunnel_state()
    assert state.installation is not None
    state.installation.capability_profile = profile

    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=state.binding.installation_id,
        used_at=_NOW,
    )


@pytest.mark.parametrize("target", ["actor", "client", "installation"])
def test_secure_tunnel_bearer_rejects_revoked_identity_components(target: str) -> None:
    state = _secure_tunnel_state()
    if target == "actor":
        state.actor.revoked_at = _NOW
    elif target == "client":
        state.client.revoked_at = _NOW
    else:
        assert state.installation is not None
        state.installation.revoked_at = _NOW

    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=state.binding.installation_id,
        used_at=_NOW,
    )


def test_secure_tunnel_bearer_rejects_wrong_client_and_binding_contract() -> None:
    state = _secure_tunnel_state()
    state.client.kind = "service"
    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=state.binding.installation_id,
        used_at=_NOW,
    )

    state = _secure_tunnel_state()
    state.binding.disclosure_boundary = "private_node"
    assert not _state_is_active(
        state,
        transport_kind=TransportKind.SECURE_TUNNEL,
        installation_id=state.binding.installation_id,
        used_at=_NOW,
    )


def test_secure_tunnel_issuance_requires_exact_derived_closed_contract() -> None:
    issuance, _state = _secure_tunnel_admin_fixture()
    _validate_secure_tunnel_issuance(issuance)

    invalid = (
        replace(issuance, actor_handle="chatgpt-other"),
        replace(issuance, actor_display_name="ChatGPT secure tunnel (other)"),
        replace(issuance, actor_metadata={"provisioning_contract": "forged"}),
        replace(issuance, installation_route_key="chatgpt-other"),
        replace(
            issuance,
            installation_capability_profile={
                "association_mode": "multiple_chatgpt_workspaces",
                "contract_version": "scalevault-secure-tunnel-installation-v1",
            },
        ),
        replace(issuance, client_public_id="chatgpt-secure-tunnel-other"),
        replace(issuance, client_display_name="ChatGPT secure tunnel (other)"),
        replace(issuance, client_scopes=("memory.write.nominate",)),
    )
    for proposal in invalid:
        with pytest.raises(CredentialAdminError, match="credential_request_invalid"):
            _validate_secure_tunnel_issuance(proposal)


def test_secure_tunnel_retry_matcher_rejects_any_distinguishing_state_drift() -> None:
    issuance, state = _secure_tunnel_admin_fixture()
    _require_matching_secure_tunnel_state(state, issuance)

    hostile = (
        replace(state, actor_handle="chatgpt-other"),
        replace(state, actor_display_name="ChatGPT secure tunnel (other)"),
        replace(state, installation_route_key="chatgpt-other"),
        replace(state, client_display_name="ChatGPT secure tunnel (other)"),
        replace(state, client_public_id="chatgpt-secure-tunnel-other"),
        replace(
            state,
            installation_capability_profile={
                "association_mode": "multiple_chatgpt_workspaces",
                "contract_version": "scalevault-secure-tunnel-installation-v1",
            },
        ),
        replace(state, actor_revoked_at=_NOW),
        replace(state, client_revoked_at=_NOW),
        replace(state, installation_revoked_at=_NOW),
        replace(state, secret_hash_key_id="other-v1"),
    )
    for existing in hostile:
        with pytest.raises(CredentialAdminError, match="credential_artifact_mismatch"):
            _require_matching_secure_tunnel_state(existing, issuance)


def test_secure_tunnel_rotation_rejects_identity_derivation_drift() -> None:
    _issuance, state = _secure_tunnel_admin_fixture()
    _require_secure_tunnel_rotation_state(
        state,
        replacement=None,
        require_active=True,
    )

    for existing in (
        replace(state, actor_handle="chatgpt-other"),
        replace(state, client_public_id="chatgpt-secure-tunnel-other"),
        replace(state, installation_route_key="chatgpt-other"),
        replace(
            state,
            credential=replace(
                state.credential,
                public_hint="chatgpt:secure-tunnel:other",
            ),
        ),
    ):
        with pytest.raises(CredentialAdminError, match="credential_artifact_mismatch"):
            _require_secure_tunnel_rotation_state(
                existing,
                replacement=None,
                require_active=True,
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
