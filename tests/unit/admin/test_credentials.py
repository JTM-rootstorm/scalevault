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
                allowed_memory_scopes=frozenset(
                    {MemoryScope.GLOBAL, MemoryScope.PROJECT}
                ),
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

    async def create_codex_installation(
        self, issuance: CodexInstallationIssuance
    ) -> CredentialMetadata:
        self.created = issuance
        record = _metadata(issuance)
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
