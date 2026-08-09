from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.admin.credentials import (
    BearerCredentialReplacement,
    CodexInstallationIssuance,
    CredentialAdminError,
    CredentialAdminRepository,
    CredentialAdminService,
    CredentialMetadata,
    SecureTunnelIssuance,
)
from kivra_memory.auth import (
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
    ReadCapability,
)
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
PEPPER = bytes(range(32))


def _capability(*, readable: bool = True) -> ClientCapabilityProfile:
    return ClientCapabilityProfile(
        contract_version="scalevault-client-capability-v1",
        read=(
            ReadCapability(
                allowed_memory_scopes=frozenset({MemoryScope.GLOBAL, MemoryScope.PROJECT}),
                allowed_visibilities=frozenset(
                    {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}
                ),
                max_sensitivity=3,
                allow_candidates=False,
            )
            if readable
            else None
        ),
    )


def _metadata(
    issuance: CodexInstallationIssuance,
    *,
    credential_id: UUID | None = None,
    revoked_at: datetime | None = None,
) -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=issuance.credential_id if credential_id is None else credential_id,
        tenant_id=issuance.tenant_id,
        actor_id=issuance.actor_id,
        client_id=issuance.client_id,
        transport_binding_id=issuance.transport_binding_id,
        host_label=issuance.host_label,
        environment_label=issuance.environment_label,
        public_hint=issuance.public_hint,
        scopes=issuance.client_scopes,
        capability_profile=issuance.client_capability_profile,
        created_at=issuance.created_at,
        expires_at=issuance.expires_at,
        last_used_at=None,
        revoked_at=revoked_at,
    )


class _Repository:
    def __init__(self) -> None:
        self.created: CodexInstallationIssuance | None = None
        self.replacement: BearerCredentialReplacement | None = None
        self.rotated_credential_id: object | None = None
        self.records: tuple[CredentialMetadata, ...] = ()
        self.secure_tunnel: SecureTunnelIssuance | None = None

    async def create_codex_installation(
        self, issuance: CodexInstallationIssuance
    ) -> CredentialMetadata:
        self.created = issuance
        record = _metadata(issuance)
        self.records = (record,)
        return record

    async def create_or_load_secure_tunnel(
        self,
        issuance: SecureTunnelIssuance,
    ) -> CredentialMetadata:
        self.secure_tunnel = issuance
        record = CredentialMetadata(
            credential_id=issuance.credential_id,
            tenant_id=issuance.tenant_id,
            actor_id=issuance.actor_id,
            client_id=issuance.client_id,
            transport_binding_id=issuance.transport_binding_id,
            host_label="chatgpt",
            environment_label=issuance.tunnel_label,
            public_hint=issuance.public_hint,
            scopes=issuance.client_scopes,
            capability_profile=issuance.client_capability_profile,
            created_at=issuance.created_at,
            expires_at=issuance.expires_at,
            last_used_at=None,
            revoked_at=None,
        )
        self.records = (record,)
        return record

    async def list_bearer_credentials(
        self, *, tenant_id: object, client_id: object | None
    ) -> tuple[CredentialMetadata, ...]:
        return tuple(
            record
            for record in self.records
            if record.tenant_id == tenant_id
            and (client_id is None or record.client_id == client_id)
        )

    async def revoke_bearer_credential(
        self, *, tenant_id: object, credential_id: object, revoked_at: datetime
    ) -> CredentialMetadata:
        record = self.records[0]
        assert record.tenant_id == tenant_id
        assert record.credential_id == credential_id
        revoked = replace(record, revoked_at=record.revoked_at or revoked_at)
        self.records = (revoked,)
        return revoked

    async def rotate_bearer_credential(
        self,
        *,
        tenant_id: object,
        credential_id: object,
        replacement: BearerCredentialReplacement,
        rotated_at: datetime,
    ) -> CredentialMetadata:
        old = self.records[0]
        assert old.tenant_id == tenant_id
        assert old.credential_id == credential_id
        self.replacement = replacement
        self.rotated_credential_id = credential_id
        new = CredentialMetadata(
            credential_id=replacement.credential_id,
            tenant_id=old.tenant_id,
            actor_id=old.actor_id,
            client_id=old.client_id,
            transport_binding_id=old.transport_binding_id,
            host_label=old.host_label,
            environment_label=old.environment_label,
            public_hint=old.public_hint,
            scopes=old.scopes,
            capability_profile=old.capability_profile,
            created_at=rotated_at,
            expires_at=replacement.expires_at,
            last_used_at=None,
            revoked_at=None,
        )
        self.records = (new,)
        return new

    async def rotate_or_load_secure_tunnel_credential(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        replacement: BearerCredentialReplacement,
        rotated_at: datetime,
    ) -> CredentialMetadata:
        return await self.rotate_bearer_credential(
            tenant_id=tenant_id,
            credential_id=credential_id,
            replacement=replacement,
            rotated_at=rotated_at,
        )

    async def reissue_secure_tunnel_credential(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        client_id: UUID,
        transport_binding_id: UUID,
        installation_id: UUID,
        replacement: BearerCredentialReplacement,
    ) -> CredentialMetadata:
        del installation_id
        self.replacement = replacement
        return CredentialMetadata(
            credential_id=replacement.credential_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=transport_binding_id,
            host_label="chatgpt",
            environment_label="workspace-one",
            public_hint="chatgpt:secure-tunnel:workspace-one",
            scopes=("memory.status.transport",),
            capability_profile=_capability(readable=False),
            created_at=replacement.created_at,
            expires_at=replacement.expires_at,
            last_used_at=None,
            revoked_at=None,
        )


def _service(repository: _Repository) -> CredentialAdminService:
    return CredentialAdminService(
        cast(CredentialAdminRepository, repository),
        token_pepper=PEPPER,
        secret_hash_key_id="codex-primary-v1",
        now=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_create_provisions_distinguishable_identity_without_persisting_secret() -> None:
    repository = _Repository()
    service = _service(repository)
    tenant_id = new_uuid7()

    issued = await service.create(
        tenant_id=tenant_id,
        host_label="workstation-one",
        environment_label="production",
        scopes=(
            "memory.read.context",
            "memory.read.get",
            "memory.status.transport",
            "memory.write.nominate",
        ),
        capability_profile=_capability(),
        expires_at=NOW + timedelta(days=90),
    )

    issuance = repository.created
    assert issuance is not None
    parsed = BearerTokenCodec.parse_authorization(f"Bearer {issued.token}")
    assert parsed.tenant_id == tenant_id
    assert parsed.credential_id == issuance.credential_id
    assert BearerTokenHasher(PEPPER).verify(parsed, issuance.secret_hash)
    assert issued.token not in repr(issued)
    assert issued.token not in repr(issuance)
    assert issuance.actor_metadata == {
        "environment_label": "production",
        "host_label": "workstation-one",
        "provisioning_contract": "scalevault-codex-installation-v1",
    }
    assert issuance.client_scopes == (
        "memory.read.context",
        "memory.read.get",
        "memory.status.transport",
        "memory.write.nominate",
    )
    assert issuance.authorized_operations == ("observed", "remembered")
    assert issuance.public_hint == "codex:production:workstation-one"
    assert issuance.client_public_id == f"codex-production-workstation-one-{tenant_id}"


@pytest.mark.asyncio
async def test_secure_tunnel_create_or_load_persists_closed_read_only_identity() -> None:
    repository = _Repository()
    service = _service(repository)
    tenant_id = new_uuid7()
    actor_id = new_uuid7()
    installation_id = new_uuid7()
    artifact: list[str] = []

    def publish(proposed: str) -> str:
        artifact.append(proposed)
        return proposed

    metadata = await service.create_or_load_secure_tunnel(
        tenant_id=tenant_id,
        actor_id=actor_id,
        installation_id=installation_id,
        tunnel_label="workspace-one",
        scopes=("memory.read.context", "memory.status.ingress"),
        capability_profile=_capability(),
        authorization_artifact=publish,
    )

    issuance = repository.secure_tunnel
    assert issuance is not None
    assert artifact[0].startswith("Bearer svb1.")
    assert metadata.credential_id == BearerTokenCodec.parse_authorization(artifact[0]).credential_id
    assert issuance.actor_metadata == {
        "provisioning_contract": "scalevault-chatgpt-secure-tunnel-v1"
    }
    assert issuance.installation_capability_profile == {
        "association_mode": "single_chatgpt_workspace",
        "contract_version": "scalevault-secure-tunnel-installation-v1",
    }
    assert issuance.installation_route_key == f"chatgpt-workspace-one-{tenant_id}"
    assert issuance.client_public_id == f"chatgpt-secure-tunnel-workspace-one-{tenant_id}"
    assert issuance.client_scopes == ("memory.read.context", "memory.status.ingress")
    assert BearerTokenHasher(PEPPER).verify(
        BearerTokenCodec.parse_authorization(artifact[0]),
        issuance.secret_hash,
    )
    assert artifact[0] not in repr(issuance)


@pytest.mark.asyncio
async def test_secure_tunnel_rejects_write_or_legacy_scope() -> None:
    service = _service(_Repository())
    for scope in ("memory.write.nominate", "memory:read"):
        with pytest.raises(CredentialAdminError, match="credential_request_invalid"):
            await service.create_or_load_secure_tunnel(
                tenant_id=new_uuid7(),
                actor_id=new_uuid7(),
                installation_id=new_uuid7(),
                tunnel_label="workspace-one",
                scopes=(scope,),
                capability_profile=_capability(readable=False),
                authorization_artifact=lambda proposed: proposed,
            )


@pytest.mark.asyncio
async def test_secure_tunnel_rotation_publishes_authorization_before_repository() -> None:
    repository = _Repository()
    service = _service(repository)
    created = await service.create_or_load_secure_tunnel(
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        installation_id=new_uuid7(),
        tunnel_label="workspace-one",
        scopes=("memory.status.transport",),
        capability_profile=_capability(readable=False),
        authorization_artifact=lambda proposed: proposed,
    )
    artifact: list[str] = []

    def publish(proposed: str) -> str:
        artifact.append(proposed)
        return proposed

    rotated = await service.rotate_secure_tunnel(
        tenant_id=created.tenant_id,
        credential_id=created.credential_id,
        authorization_artifact=publish,
    )

    assert artifact[0].startswith("Bearer svb1.")
    assert repository.replacement is not None
    assert rotated.credential_id == BearerTokenCodec.parse_authorization(artifact[0]).credential_id
    assert repository.replacement.credential_id == rotated.credential_id
    assert artifact[0] not in repr(repository.replacement)


@pytest.mark.asyncio
async def test_secure_tunnel_reissue_publishes_artifact_for_exact_restored_selectors() -> None:
    repository = _Repository()
    service = _service(repository)
    artifact: list[str] = []

    def publish(proposed: str) -> str:
        artifact.append(proposed)
        return proposed

    tenant_id = new_uuid7()
    actor_id = new_uuid7()
    client_id = new_uuid7()
    binding_id = new_uuid7()
    record = await service.reissue_secure_tunnel(
        tenant_id=tenant_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        installation_id=new_uuid7(),
        authorization_artifact=publish,
    )

    assert artifact[0].startswith("Bearer svb1.")
    assert record.tenant_id == tenant_id
    assert record.actor_id == actor_id
    assert record.client_id == client_id
    assert record.transport_binding_id == binding_id
    assert repository.replacement is not None
    assert repository.replacement.credential_id == record.credential_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scopes,capability",
    [
        (("memory.write.observe",), _capability(readable=False)),
        (("memory.write.revise",), _capability(readable=False)),
        (("memory.admin",), _capability(readable=False)),
        (("memory:read",), _capability(readable=False)),
        (("memory.read.get",), _capability(readable=False)),
        (("memory.write.nominate",), _capability()),
    ],
)
async def test_create_rejects_legacy_admin_and_capability_mismatched_scopes(
    scopes: tuple[str, ...], capability: ClientCapabilityProfile
) -> None:
    with pytest.raises(CredentialAdminError, match="credential_request_invalid"):
        await _service(_Repository()).create(
            tenant_id=new_uuid7(),
            host_label="host",
            environment_label="test",
            scopes=scopes,
            capability_profile=capability,
        )


@pytest.mark.asyncio
async def test_rotation_is_one_atomic_repository_action_and_reuses_identity() -> None:
    repository = _Repository()
    service = _service(repository)
    original = await service.create(
        tenant_id=new_uuid7(),
        host_label="laptop",
        environment_label="production",
        scopes=("memory.status.transport", "memory.write.nominate"),
        capability_profile=_capability(readable=False),
    )

    rotated = await service.rotate(
        tenant_id=original.metadata.tenant_id,
        credential_id=original.metadata.credential_id,
        expires_at=NOW + timedelta(days=30),
    )

    assert repository.rotated_credential_id == original.metadata.credential_id
    assert repository.replacement is not None
    assert rotated.metadata.credential_id == repository.replacement.credential_id
    assert rotated.metadata.client_id == original.metadata.client_id
    assert rotated.metadata.actor_id == original.metadata.actor_id
    assert rotated.metadata.transport_binding_id == original.metadata.transport_binding_id
    assert rotated.token != original.token
    assert rotated.token not in repr(repository.replacement)


@pytest.mark.asyncio
async def test_list_and_idempotent_revoke_return_safe_metadata_only() -> None:
    repository = _Repository()
    service = _service(repository)
    issued = await service.create(
        tenant_id=new_uuid7(),
        host_label="desktop",
        environment_label="development",
        scopes=("memory.status.transport", "memory.write.nominate"),
        capability_profile=_capability(readable=False),
    )

    records = await service.list_metadata(tenant_id=issued.metadata.tenant_id)
    first = await service.revoke(
        tenant_id=issued.metadata.tenant_id,
        credential_id=issued.metadata.credential_id,
    )
    second = await service.revoke(
        tenant_id=issued.metadata.tenant_id,
        credential_id=issued.metadata.credential_id,
    )

    assert records == (issued.metadata,)
    assert first.revoked_at == NOW
    assert second.revoked_at == NOW
    assert issued.token not in repr(records)
