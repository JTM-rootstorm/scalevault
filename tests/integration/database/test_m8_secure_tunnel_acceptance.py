from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.admin import CredentialAdminService
from kivra_memory.api.app import create_app
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.auth import ClientCapabilityProfile, ReadCapability
from kivra_memory.config import Settings
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.runtime import ChatGPTReadRuntime, MemoryNodeRuntime
from kivra_memory.storage.credentials import CredentialAdminStorageRepository
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    CommandReceipt,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    MemoryEvent,
    MemoryEventCounter,
    MemoryEvidence,
    MemoryLink,
    OutboxJob,
    SelectionDecision,
    SelectionDecisionCounter,
)
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import PostgresDsn
from sqlalchemy import func, select

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_TOKEN_PEPPER = bytes(range(32))
_HASH_KEY_ID = "m8-secure-tunnel-acceptance-v1"
_UUID_TIMESTAMP_MS = 1_786_291_200_000
_READ_STATUS_TOOLS = frozenset(
    {
        "memory_context_pack",
        "memory_search",
        "memory_get",
        "memory_timeline",
        "memory_conflicts",
        "memory_lineage",
        "memory_selection_history",
        "memory_selection_decisions",
        "memory_ingress_status",
        "memory_transport_status",
    }
)
_SECURE_TUNNEL_SCOPES = (
    "memory.read.conflicts",
    "memory.read.context",
    "memory.read.get",
    "memory.read.lineage",
    "memory.read.search",
    "memory.read.selection_history",
    "memory.read.timeline",
    "memory.status.ingress",
    "memory.status.transport",
)


class PostgreSQLTestServer(Protocol):
    database_url: str


class _ProtectedAuthorizationArtifact:
    """Test double for an atomic root-owned credential artifact."""

    def __init__(self) -> None:
        self._authorization: str | None = None
        self.calls = 0

    def publish_or_load(self, proposed: str) -> str:
        self.calls += 1
        if self._authorization is None:
            self._authorization = proposed
        return self._authorization

    def authorization(self) -> str:
        if self._authorization is None:
            raise AssertionError("authorization artifact was not published")
        return self._authorization

    def __repr__(self) -> str:
        return "_ProtectedAuthorizationArtifact(<redacted>)"


def _identifier(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_UUID_TIMESTAMP_MS, random_bits=ordinal)


def _tenant_id() -> UUID:
    return cast(UUID, seed_rows()["tenants"][0]["tenant_id"])


def _wrong_secret(authorization: str) -> str:
    secret_offset = -10
    replacement = "A" if authorization[secret_offset] != "A" else "B"
    return authorization[:secret_offset] + replacement + authorization[secret_offset + 1 :]


def _settings(database_url: str, pepper_path: Path, installation_id: UUID) -> Settings:
    return Settings(
        environment="test",
        database_url=PostgresDsn(database_url),
        client_token_pepper_credential=pepper_path,
        client_token_pepper_key_id=_HASH_KEY_ID,
        chatgpt_secure_tunnel_enabled=True,
        chatgpt_secure_tunnel_installation_id=installation_id,
    )


def _read_capability() -> ClientCapabilityProfile:
    return ClientCapabilityProfile(
        contract_version="scalevault-client-capability-v1",
        read=ReadCapability(
            allowed_memory_scopes=frozenset(
                {
                    MemoryScope.PERSONA,
                    MemoryScope.RELATIONSHIP,
                    MemoryScope.PROJECT,
                }
            ),
            allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
            max_sensitivity=3,
            allow_candidates=False,
        ),
    )


async def _canonical_counts(database: Database) -> tuple[int, ...]:
    tables = tuple(
        model.__table__
        for model in (
            MemoryEventCounter,
            SelectionDecisionCounter,
            MemoryEvent,
            SelectionDecision,
            Memory,
            MemoryEvidence,
            MemoryLink,
            MemoryConflict,
            MemoryConflictMember,
            MemoryContentKey,
            CommandReceipt,
            OutboxJob,
        )
    )
    async with database.tenant_session(_tenant_id()) as session:
        counts: list[int] = []
        for table in tables:
            counts.append(int(await session.scalar(select(func.count()).select_from(table)) or 0))
        return tuple(counts)


@asynccontextmanager
async def _mcp_session(
    app: FastAPI,
    *,
    path: str,
    authorization: str,
) -> AsyncIterator[ClientSession]:
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8080",
            headers={"Authorization": authorization},
        ) as client,
        streamable_http_client(
            f"http://127.0.0.1:8080{path}",
            http_client=client,
        ) as (read_stream, write_stream, _),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


async def test_postgresql_backed_secure_tunnel_is_read_only_and_transport_distinct(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
    tmp_path: Path,
) -> None:
    _ = migrated_database
    installation_id = _identifier(1)
    secure_actor_id = _identifier(2)
    pepper_path = tmp_path / "client-token-pepper"
    pepper_path.write_bytes(_TOKEN_PEPPER)
    pepper_path.chmod(0o600)

    database = Database(postgresql_server.database_url)
    artifact = _ProtectedAuthorizationArtifact()
    try:
        async with database.tenant_session(_tenant_id()) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()

        repository = CredentialAdminStorageRepository(database.session_factory)
        admin = CredentialAdminService(
            repository,
            token_pepper=_TOKEN_PEPPER,
            secret_hash_key_id=_HASH_KEY_ID,
        )
        secure_metadata = await admin.create_or_load_secure_tunnel(
            tenant_id=_tenant_id(),
            actor_id=secure_actor_id,
            installation_id=installation_id,
            tunnel_label="m8-acceptance",
            scopes=_SECURE_TUNNEL_SCOPES,
            capability_profile=_read_capability(),
            authorization_artifact=artifact.publish_or_load,
        )
        loaded_metadata = await admin.create_or_load_secure_tunnel(
            tenant_id=_tenant_id(),
            actor_id=secure_actor_id,
            installation_id=installation_id,
            tunnel_label="m8-acceptance",
            scopes=_SECURE_TUNNEL_SCOPES,
            capability_profile=_read_capability(),
            authorization_artifact=artifact.publish_or_load,
        )
        direct_credential = await admin.create(
            tenant_id=_tenant_id(),
            host_label="m8-direct",
            environment_label="integration",
            scopes=("memory.status.transport",),
            capability_profile=ClientCapabilityProfile(
                contract_version="scalevault-client-capability-v1",
                read=None,
            ),
        )
        secure_authorization = artifact.authorization()
        direct_authorization = f"Bearer {direct_credential.token}"

        assert loaded_metadata == secure_metadata
        assert artifact.calls == 2
        assert secure_authorization not in repr(artifact)

        before = await _canonical_counts(database)
        settings = _settings(
            postgresql_server.database_url,
            pepper_path,
            installation_id,
        )
        runtime = MemoryNodeRuntime.from_settings(
            settings,
            sealed_runtime=SealedRuntime(key_provider=None, digest_binder=None),
        )
        chatgpt_runtime = ChatGPTReadRuntime.from_memory_runtime(settings, runtime)
        app = create_app(
            settings,
            runtime=runtime,
            chatgpt_runtime=chatgpt_runtime,
        )
        transport = ASGITransport(app=app)

        async with app.router.lifespan_context(app):
            async with _mcp_session(
                app,
                path="/chatgpt/mcp",
                authorization=secure_authorization,
            ) as secure_session:
                secure_tools = (await secure_session.list_tools()).tools
                secure_status = await secure_session.call_tool(
                    "memory_transport_status",
                    {"contract_version": "mcp-read-v1"},
                )
                forbidden_mutation = await secure_session.call_tool("memory_nominate", {})

            async with _mcp_session(
                app,
                path="/mcp",
                authorization=direct_authorization,
            ) as direct_session:
                direct_tools = (await direct_session.list_tools()).tools
                direct_status = await direct_session.call_tool(
                    "memory_transport_status",
                    {"contract_version": "mcp-read-v1"},
                )

            async with AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1:8080",
            ) as client:
                missing = await client.post("/chatgpt/mcp")
                wrong = await client.post(
                    "/chatgpt/mcp",
                    headers={"Authorization": _wrong_secret(secure_authorization)},
                )
                direct_on_secure = await client.post(
                    "/chatgpt/mcp",
                    headers={"Authorization": direct_authorization},
                )
                secure_on_direct = await client.post(
                    "/mcp",
                    headers={"Authorization": secure_authorization},
                )

                await admin.revoke(
                    tenant_id=_tenant_id(),
                    credential_id=secure_metadata.credential_id,
                )
                revoked = await client.post(
                    "/chatgpt/mcp",
                    headers={"Authorization": secure_authorization},
                )

        assert {tool.name for tool in secure_tools} == _READ_STATUS_TOOLS
        assert all(
            tool.annotations is not None
            and tool.annotations.readOnlyHint is True
            and tool.annotations.destructiveHint is False
            for tool in secure_tools
        )
        assert forbidden_mutation.isError is True
        assert forbidden_mutation.structuredContent is None
        assert secure_status.structuredContent is not None
        assert secure_status.structuredContent["ok"] is True
        assert secure_status.structuredContent["result"] == {
            "transport_kind": "secure_tunnel",
            "binding_state": "active",
            "installation_state": "active",
            "health_state": "unknown",
            "freshness": "never",
        }

        direct_tool_names = {tool.name for tool in direct_tools}
        assert "memory_nominate" in direct_tool_names
        assert direct_tool_names > _READ_STATUS_TOOLS
        assert direct_status.structuredContent is not None
        assert direct_status.structuredContent["result"]["transport_kind"] == "direct_private"

        failures = (missing, wrong, direct_on_secure, secure_on_direct, revoked)
        assert {response.status_code for response in failures} == {401}
        assert all(
            response.json() == {"error": "authentication_required"}
            and response.headers["www-authenticate"] == "Bearer"
            for response in failures
        )
        assert await _canonical_counts(database) == before
    finally:
        await database.dispose()
