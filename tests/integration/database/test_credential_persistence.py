from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID

from kivra_memory.admin import CredentialAdminService
from kivra_memory.application.authentication import BearerAuthenticator
from kivra_memory.auth import (
    BearerTokenHasher,
    ClientCapabilityProfile,
    ReadCapability,
    RequestTransportIdentity,
)
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.storage.credentials import (
    CredentialAdminStorageRepository,
    CredentialRepository,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import Client, ClientCredential
from sqlalchemy import func, select

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 9, 19, tzinfo=UTC)
_PEPPER = bytes(range(32))
_KEY_ID = "credential-storage-test-v1"
_VERIFIER = re.compile(r"hmac-sha256-v1:[A-Za-z0-9_-]{43}\Z")
_DIRECT_TRANSPORT = RequestTransportIdentity(
    transport_kind=TransportKind.DIRECT_PRIVATE,
    installation_id=None,
)


class PostgreSQLTestServer(Protocol):
    database_url: str


def _tenant_id() -> UUID:
    return cast(UUID, seed_rows()["tenants"][0]["tenant_id"])


async def test_admin_create_and_rotate_persist_only_versioned_verifiers(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    try:
        async with database.tenant_session(_tenant_id()) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            database_now = cast(datetime, await session.scalar(select(func.current_timestamp())))

        repository = CredentialAdminStorageRepository(database.session_factory)
        admin = CredentialAdminService(
            repository,
            token_pepper=_PEPPER,
            secret_hash_key_id=_KEY_ID,
            now=lambda: database_now,
        )
        capability = ClientCapabilityProfile(
            contract_version="scalevault-client-capability-v1",
            read=ReadCapability(
                allowed_memory_scopes=frozenset({MemoryScope.PERSONA, MemoryScope.RELATIONSHIP}),
                allowed_visibilities=frozenset(
                    {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}
                ),
                max_sensitivity=3,
                allow_candidates=False,
            ),
        )
        issued = await admin.create(
            tenant_id=_tenant_id(),
            host_label="storage-host",
            environment_label="integration",
            scopes=("memory.read.context", "memory.write.nominate"),
            capability_profile=capability,
        )
        lookup_repository = CredentialRepository(database.session_factory)
        lookup = await lookup_repository.lookup(
            _tenant_id(),
            issued.metadata.credential_id,
        )
        assert lookup is not None
        assert lookup.hash_key_id == _KEY_ID
        assert _VERIFIER.fullmatch(lookup.secret_verifier) is not None
        assert issued.token not in repr(lookup)
        assert lookup.secret_verifier not in repr(lookup)

        async with database.tenant_session(_tenant_id()) as session:
            stored_profile = await session.scalar(
                select(Client.capability_profile).where(
                    Client.client_id == issued.metadata.client_id
                )
            )
        assert stored_profile is not None
        assert stored_profile["contract_version"] == "scalevault-client-capability-v1"
        stored_read = stored_profile["read"]
        assert isinstance(stored_read, dict)
        assert isinstance(stored_read["allowed_memory_scopes"], list)
        assert set(stored_read["allowed_memory_scopes"]) == {"persona", "relationship"}
        assert isinstance(stored_read["allowed_visibilities"], list)
        assert set(stored_read["allowed_visibilities"]) == {"private_root", "restricted"}

        listed_after_jsonb_round_trip = await repository.list_bearer_credentials(
            tenant_id=_tenant_id(),
            client_id=issued.metadata.client_id,
        )
        assert len(listed_after_jsonb_round_trip) == 1
        assert listed_after_jsonb_round_trip[0].capability_profile == capability

        authenticated = await BearerAuthenticator(
            lookup_repository,
            hashers={_KEY_ID: BearerTokenHasher(_PEPPER)},
            clock=lambda: database_now,
        ).authenticate(f"Bearer {issued.token}", _DIRECT_TRANSPORT)
        assert authenticated.query_principal.scopes == frozenset({"memory.read.context"})
        assert authenticated.query_principal.allowed_memory_scopes == frozenset(
            {MemoryScope.PERSONA, MemoryScope.RELATIONSHIP}
        )

        replacement = await CredentialAdminService(
            repository,
            token_pepper=_PEPPER,
            secret_hash_key_id=_KEY_ID,
            now=lambda: database_now,
        ).rotate(
            tenant_id=_tenant_id(),
            credential_id=issued.metadata.credential_id,
        )

        assert (
            await lookup_repository.lookup(
                _tenant_id(),
                issued.metadata.credential_id,
            )
            is None
        )
        assert (
            await lookup_repository.lookup(
                _tenant_id(),
                replacement.metadata.credential_id,
            )
            is not None
        )
        revoked = await CredentialAdminService(
            repository,
            token_pepper=_PEPPER,
            secret_hash_key_id=_KEY_ID,
            now=lambda: database_now,
        ).revoke(
            tenant_id=_tenant_id(),
            credential_id=replacement.metadata.credential_id,
        )
        assert revoked.revoked_at == database_now
        assert (
            await lookup_repository.lookup(
                _tenant_id(),
                replacement.metadata.credential_id,
            )
            is None
        )

        expired = await CredentialAdminService(
            repository,
            token_pepper=_PEPPER,
            secret_hash_key_id=_KEY_ID,
            now=lambda: database_now - timedelta(hours=2),
        ).create(
            tenant_id=_tenant_id(),
            host_label="expired-host",
            environment_label="integration",
            scopes=("memory.write.nominate",),
            capability_profile=capability,
            expires_at=database_now - timedelta(hours=1),
        )
        not_yet_valid = await CredentialAdminService(
            repository,
            token_pepper=_PEPPER,
            secret_hash_key_id=_KEY_ID,
            now=lambda: database_now + timedelta(hours=1),
        ).create(
            tenant_id=_tenant_id(),
            host_label="future-host",
            environment_label="integration",
            scopes=("memory.write.nominate",),
            capability_profile=capability,
        )
        assert (
            await lookup_repository.lookup(
                _tenant_id(),
                expired.metadata.credential_id,
            )
            is None
        )
        assert (
            await lookup_repository.lookup(
                _tenant_id(),
                not_yet_valid.metadata.credential_id,
            )
            is None
        )

        listed = await repository.list_bearer_credentials(tenant_id=_tenant_id(), client_id=None)
        assert len(listed) == 4
        listed_by_id = {row.credential_id: row for row in listed}
        assert listed_by_id[issued.metadata.credential_id].revoked_at == database_now
        assert listed_by_id[replacement.metadata.credential_id].revoked_at == database_now
        assert listed_by_id[expired.metadata.credential_id].revoked_at is None
        assert listed_by_id[not_yet_valid.metadata.credential_id].revoked_at is None

        async with database.tenant_session(_tenant_id()) as session:
            rows = (
                await session.scalars(
                    select(ClientCredential).order_by(ClientCredential.created_at)
                )
            ).all()
        assert len(rows) == 4
        assert all(
            row.secret_hash is not None
            and _VERIFIER.fullmatch(row.secret_hash) is not None
            and row.secret_hash_key_id == _KEY_ID
            for row in rows
        )
        assert all(issued.token != row.secret_hash for row in rows)
        assert all(replacement.token != row.secret_hash for row in rows)
    finally:
        await database.dispose()
