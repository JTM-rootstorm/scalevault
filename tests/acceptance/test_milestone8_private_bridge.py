"""Isolated Milestone 8 contracts pending live ChatGPT and GitHub acceptance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.mcp import (
    ReadExecutor,
    ReadPrincipalResolver,
    create_chatgpt_read_mcp,
)
from kivra_memory.application.queries import CandidateRepository, QueryEngine
from kivra_memory.config import Settings
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
    TransportKind,
)
from kivra_memory.domain.events import MemoryState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.ingress.status import (
    IngressStatusPayload,
    IngressStatusResult,
)
from kivra_memory.ingress.validator import validate_ingress
from kivra_memory.retrieval.contracts import QueryPrincipal
from kivra_memory.storage.retrieval import HydratedMemory
from kivra_memory.storage.retrieval import (
    ResolvedReadContext as StorageReadContext,
)
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

ROOT = Path(__file__).resolve().parents[2]
PROPOSAL_FIXTURE = (
    ROOT
    / "tests"
    / "contract"
    / "fixtures"
    / "json_schemas"
    / "chatgpt-memory-proposal-v2.schema.json"
)
READ_TOOL_NAMES = {
    "memory_context_pack",
    "memory_search",
    "memory_get",
    "memory_timeline",
    "memory_conflicts",
    "memory_lineage",
    "memory_selection_history",
    "memory_ingress_status",
    "memory_transport_status",
    "memory_selection_decisions",
}
MUTATION_TOOL_NAMES = {
    "memory_nominate",
    "memory_observe",
    "memory_remember",
    "memory_revise",
    "memory_link",
    "memory_open_conflict",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_forget",
}
NOW = datetime(2026, 8, 9, 20, tzinfo=UTC)


def uid(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=ordinal)


TENANT_ID = uid(1)
CODEX_ACTOR_ID = uid(2)
CODEX_CLIENT_ID = uid(3)
CHATGPT_ACTOR_ID = uid(4)
CHATGPT_CLIENT_ID = uid(5)
TUNNEL_BINDING_ID = uid(6)
TUNNEL_INSTALLATION_ID = uid(7)
PERSONA_ID = uid(8)
LINEAGE_ID = uid(9)
BRANCH_ID = uid(10)
SUBJECT_ID = uid(11)
MEMORY_ID = uid(12)
EVENT_ID = uid(13)
CODEX_STATEMENT = "Codex recorded this synthetic Milestone 8 continuity fact."


@dataclass(frozen=True, slots=True)
class SecureTunnelReadAuthority:
    """Local Protocol value until installation-bound tunnel auth exists in production."""

    installation_id: UUID
    transport_kind: TransportKind
    principal: QueryPrincipal


class SecureTunnelReadSurface(Protocol):
    """Minimum read-only MCP surface expected from the future tunnel profile."""

    def application(self) -> FastAPI: ...


def _query_principal() -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=TENANT_ID,
        actor_id=CHATGPT_ACTOR_ID,
        client_id=CHATGPT_CLIENT_ID,
        transport_binding_id=TUNNEL_BINDING_ID,
        scopes=frozenset({"memory.read.get", "memory.status.ingress"}),
        allowed_memory_scopes=frozenset({MemoryScope.PROJECT}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=1,
    )


def _codex_memory() -> MemoryState:
    return MemoryState(
        memory_id=MEMORY_ID,
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        branch_id=BRANCH_ID,
        subject_id=SUBJECT_ID,
        subject_kind=SubjectKind.PROJECT,
        revision=1,
        category=MemoryCategory.PROJECT_STATE,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement=CODEX_STATEMENT,
        reason_to_remember="Synthetic cross-surface acceptance fixture.",
        interpretation_limits=("Acceptance-test data only.",),
        confidence=Decimal("0.900000"),
        salience=Decimal("0.800000"),
        durability=Decimal("0.700000"),
        sensitivity=1,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=NOW,
        publication_approved_at=None,
        publication_approved_by_actor_id=None,
        content_protection="plaintext",
        content_key_id=None,
        created_at=NOW,
        updated_at=NOW,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={
            "synthetic_writer_actor_id": str(CODEX_ACTOR_ID),
            "synthetic_writer_client_id": str(CODEX_CLIENT_ID),
        },
    )


class _CanonicalReadRepository:
    def __init__(self) -> None:
        self.resolved_call: dict[str, object] | None = None
        self.filters: object | None = None

    async def resolve_context(self, **kwargs: object) -> StorageReadContext:
        self.resolved_call = kwargs
        return StorageReadContext(
            lineage_id=LINEAGE_ID,
            branch_id=BRANCH_ID,
            logical_session_id=None,
            project_subject_ids=frozenset({SUBJECT_ID}),
            relationship_subject_ids=frozenset(),
            session_subject_ids=frozenset(),
        )

    async def get_memory(self, filters: object, memory_id: UUID) -> HydratedMemory | None:
        self.filters = filters
        if memory_id != MEMORY_ID:
            return None
        return HydratedMemory(state=_codex_memory(), last_event_id=EVENT_ID)


class _IsolatedSecureTunnelSurface:
    """Compose the production read-only tools with a pinned tunnel authority."""

    def __init__(self, authority: SecureTunnelReadAuthority) -> None:
        if (
            authority.transport_kind is not TransportKind.SECURE_TUNNEL
            or authority.installation_id != TUNNEL_INSTALLATION_ID
        ):
            raise ValueError("secure tunnel authority is invalid")
        self.repository = _CanonicalReadRepository()

        @asynccontextmanager
        async def session_factory(_tenant_id: UUID) -> AsyncIterator[AsyncSession]:
            yield cast(AsyncSession, object())

        engine = QueryEngine(
            session_factory,
            lambda _session: cast(CandidateRepository, self.repository),
        )

        async def resolver(_context: object) -> QueryPrincipal:
            return authority.principal

        async def executor(principal: QueryPrincipal, query: object) -> object:
            return await engine.execute(principal, cast(Any, query))

        server = create_chatgpt_read_mcp(
            read_principal_resolver=cast(ReadPrincipalResolver, resolver),
            read_executor=cast(ReadExecutor, executor),
        )
        self._server = server

    def application(self) -> FastAPI:
        server = self._server

        @asynccontextmanager
        async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
            async with server.session_manager.run():
                yield

        app = FastAPI(lifespan=lifespan)
        app.mount("/chatgpt", server.streamable_http_app())
        return app


@asynccontextmanager
async def _mcp_session(surface: SecureTunnelReadSurface) -> AsyncIterator[ClientSession]:
    app = surface.application()
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client,
        streamable_http_client("http://127.0.0.1:8080/chatgpt/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


def _surface() -> _IsolatedSecureTunnelSurface:
    return _IsolatedSecureTunnelSurface(
        SecureTunnelReadAuthority(
            installation_id=TUNNEL_INSTALLATION_ID,
            transport_kind=TransportKind.SECURE_TUNNEL,
            principal=_query_principal(),
        )
    )


async def test_secure_tunnel_discovers_only_read_tools_and_mutations_are_uncallable() -> None:
    surface = _surface()
    async with _mcp_session(surface) as session:
        tools = (await session.list_tools()).tools
        discovered = {tool.name for tool in tools}
        mutation_attempts = {
            name: await session.call_tool(name, {}) for name in MUTATION_TOOL_NAMES
        }

    assert discovered == READ_TOOL_NAMES
    assert discovered.isdisjoint(MUTATION_TOOL_NAMES)
    for rejection_result in mutation_attempts.values():
        assert rejection_result.isError is True
        assert rejection_result.structuredContent is None
    assert surface.repository.resolved_call is None
    assert all(
        tool.annotations is not None
        and tool.annotations.readOnlyHint is True
        and tool.annotations.destructiveHint is False
        for tool in tools
    )


async def test_secure_tunnel_reads_codex_memory_through_authorized_query_engine() -> None:
    surface = _surface()
    async with _mcp_session(surface) as session:
        result = await session.call_tool(
            "memory_get",
            {
                "contract_version": "mcp-read-v1",
                "memory_id": str(MEMORY_ID),
                "persona_id": str(PERSONA_ID),
                "branch_id": str(BRANCH_ID),
                "include_conflicts": False,
            },
        )

    assert result.isError is False
    payload = cast(dict[str, Any], result.structuredContent)
    assert payload["result"]["memory"]["statement"] == CODEX_STATEMENT
    assert payload["result"]["memory"]["memory_id"] == str(MEMORY_ID)
    assert surface.repository.resolved_call is not None
    assert surface.repository.resolved_call["tenant_id"] == TENANT_ID
    assert surface.repository.resolved_call["actor_id"] == CHATGPT_ACTOR_ID
    assert surface.repository.resolved_call["client_id"] == CHATGPT_CLIENT_ID
    assert surface.repository.resolved_call["transport_binding_id"] == TUNNEL_BINDING_ID


@dataclass(frozen=True, slots=True)
class ProposalReference:
    ingress_id: UUID
    immutable_path: str
    commit_id: str
    blob_id: str


class GitHubProposalFallback(Protocol):
    """External connected-app seam; ScaleVault never receives write credentials."""

    async def create_unique(self, raw_proposal: bytes, /) -> ProposalReference: ...


class ProposalIngressStatus(Protocol):
    async def ingest(
        self, reference: ProposalReference, raw_proposal: bytes, /
    ) -> IngressStatusResult: ...

    async def status(self, ingress_id: UUID, /) -> IngressStatusResult: ...


class _InMemoryGitHubFallback:
    def __init__(self) -> None:
        self.paths: set[str] = set()
        self.create_calls = 0

    async def create_unique(self, raw_proposal: bytes, /) -> ProposalReference:
        validated = validate_ingress(
            raw_proposal,
            _proposal_path(raw_proposal),
            source_git_blob_sha="2" * 40,
        )
        ingress_id = UUID(validated.source_id)
        path = _proposal_path(raw_proposal)
        if path in self.paths:
            raise ValueError("create-only proposal path already exists")
        self.paths.add(path)
        self.create_calls += 1
        return ProposalReference(
            ingress_id=ingress_id,
            immutable_path=path,
            commit_id="1" * 40,
            blob_id="2" * 40,
        )


class _InMemoryProposalIngress:
    def __init__(self) -> None:
        self._objects: dict[UUID, tuple[ProposalReference, bytes, IngressStatusResult]] = {}
        self.canonical_mutations = 0

    async def ingest(
        self, reference: ProposalReference, raw_proposal: bytes, /
    ) -> IngressStatusResult:
        prior = self._objects.get(reference.ingress_id)
        if prior is not None:
            if prior[:2] != (reference, raw_proposal):
                raise ValueError("immutable proposal identity changed")
            return prior[2]
        validated = validate_ingress(
            raw_proposal,
            reference.immutable_path,
            source_git_blob_sha=reference.blob_id,
        )
        if UUID(validated.source_id) != reference.ingress_id:
            raise ValueError("proposal status correlation failed")
        self.canonical_mutations += 1
        result = IngressStatusResult(
            result=IngressStatusPayload(
                ingress_id=reference.ingress_id,
                state="accepted",
                result_event_id=uid(100 + self.canonical_mutations),
                result_memory_id=uid(200 + self.canonical_mutations),
                error_code=None,
                discovered_at=NOW,
                validated_at=NOW,
                processed_at=NOW,
            )
        )
        self._objects[reference.ingress_id] = (reference, raw_proposal, result)
        return result

    async def status(self, ingress_id: UUID, /) -> IngressStatusResult:
        return self._objects[ingress_id][2]


def _proposal_raw(*, proposal_id: UUID | None = None) -> bytes:
    document = json.loads(PROPOSAL_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    if proposal_id is not None:
        document["proposal_id"] = str(proposal_id)
        document["idempotency_key"] = f"chatgpt-fallback:{proposal_id}"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _proposal_path(raw_proposal: bytes) -> str:
    document = json.loads(raw_proposal)
    assert isinstance(document, dict)
    return f"ingress/v2/{document['installation_id']}/2026/08/{document['proposal_id']}.json"


async def test_github_unique_fallback_replay_is_idempotent_and_status_correlates() -> None:
    writer = cast(GitHubProposalFallback, _InMemoryGitHubFallback())
    ingress = cast(ProposalIngressStatus, _InMemoryProposalIngress())
    raw = _proposal_raw()

    reference = await writer.create_unique(raw)
    accepted = await ingress.ingest(reference, raw)
    replay = await ingress.ingest(reference, raw)
    status = await ingress.status(reference.ingress_id)

    assert reference.immutable_path.endswith(f"/{reference.ingress_id}.json")
    assert accepted == replay == status
    assert status.result.ingress_id == reference.ingress_id
    assert status.result.state == "accepted"
    assert status.result.result_event_id is not None
    assert status.result.result_memory_id is not None
    assert cast(_InMemoryGitHubFallback, writer).create_calls == 1
    assert cast(_InMemoryProposalIngress, ingress).canonical_mutations == 1


async def test_github_fallback_uses_a_unique_create_only_path_per_proposal() -> None:
    writer = _InMemoryGitHubFallback()
    first = await writer.create_unique(_proposal_raw(proposal_id=uid(301)))
    second = await writer.create_unique(_proposal_raw(proposal_id=uid(302)))

    assert first.ingress_id != second.ingress_id
    assert first.immutable_path != second.immutable_path
    with pytest.raises(ValueError, match="create-only"):
        await writer.create_unique(_proposal_raw(proposal_id=uid(301)))


def test_tunnel_deployment_requires_no_public_listener() -> None:
    tunnel_unit = (ROOT / "deploy/memory-node/systemd/kivra-memory-tunnel.service").read_text(
        encoding="utf-8"
    )
    tunnel_readme = (ROOT / "deploy/memory-node/tunnel/README.md").read_text(encoding="utf-8")

    tunnel_target = "--mcp.server-url=url=http://127.0.0.1:8080/chatgpt/mcp,channel=main"
    authorization_header = '"Authorization: file:%d/chatgpt-mcp-authorization"'

    assert tunnel_unit.count(tunnel_target) == 2
    assert tunnel_unit.count(f"--mcp.extra-headers={authorization_header}") == 2
    assert tunnel_unit.count(f"--mcp.discovery-extra-headers={authorization_header}") == 2
    assert "LoadCredential=chatgpt-mcp-authorization:" in tunnel_unit
    assert "--health.listen-addr=127.0.0.1:8081" in tunnel_unit
    assert "0.0.0.0" not in tunnel_unit
    assert "ListenStream=" not in tunnel_unit
    assert "Bearer svb1." not in tunnel_unit
    assert "outbound HTTPS" in tunnel_readme
    assert "requires no public listener" in tunnel_readme

    with pytest.raises(ValidationError, match="host must be loopback"):
        Settings(
            environment="production",
            host="0.0.0.0",
            database_url=cast(
                Any,
                "postgresql+psycopg://memory@127.0.0.1/kivra_memory",
            ),
            client_token_pepper_credential=Path(
                "/run/credentials/kivra-memory-api.service/client-token-pepper"
            ),
            client_token_pepper_key_id="m8-test",
        )


def test_fallback_fixture_contains_no_hidden_transport_secret() -> None:
    raw = _proposal_raw()
    lowered = raw.lower()

    assert hashlib.sha256(raw).digest() != b"\x00" * 32
    assert b"authorization" not in lowered
    assert b"bearer" not in lowered
    assert b"token" not in lowered
    assert b"private_key" not in lowered
