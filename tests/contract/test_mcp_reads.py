from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.api.mcp import ReadExecutor, ReadPrincipalResolver
from kivra_memory.application.status import (
    IngressStatusQuery,
    TransportStatusQuery,
    TransportStatusResult,
)
from kivra_memory.config import Settings
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.budgeting import HARD_RESPONSE_BYTE_CEILING
from kivra_memory.retrieval.contracts import (
    ContextPackQuery,
    ContextPackResult,
    MemoryConflictsQuery,
    MemoryGetQuery,
    MemoryLineageQuery,
    MemorySearchPage,
    MemorySearchQuery,
    MemorySearchResult,
    MemorySelectionHistoryQuery,
    MemoryTimelineQuery,
    QueryPrincipal,
    ReadError,
    ReadErrorBody,
    ReadResultMetadata,
)
from kivra_memory.transport.status import TransportStatusPayload
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

READ_TOOL_NAMES = [
    "memory_context_pack",
    "memory_search",
    "memory_get",
    "memory_timeline",
    "memory_conflicts",
    "memory_lineage",
    "memory_selection_history",
    "memory_ingress_status",
    "memory_transport_status",
]
MUTATION_TOOL_NAMES = [
    "memory_observe",
    "memory_remember",
    "memory_revise",
    "memory_link",
    "memory_open_conflict",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_forget",
]


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def principal() -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=uid(1),
        actor_id=uid(2),
        client_id=uid(3),
        transport_binding_id=uid(4),
        scopes=frozenset({"memory:read"}),
        allowed_memory_scopes=frozenset({MemoryScope.PROJECT}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=4,
    )


def common_arguments() -> dict[str, Any]:
    return {
        "contract_version": "mcp-read-v1",
        "persona_id": str(uid(10)),
        "branch_id": str(uid(11)),
    }


READ_CASES: list[tuple[str, dict[str, Any], type[object]]] = [
    (
        "memory_context_pack",
        {**common_arguments(), "query": "current project context", "token_budget": 512},
        ContextPackQuery,
    ),
    (
        "memory_search",
        {**common_arguments(), "query": "adapter contract", "limit": 5},
        MemorySearchQuery,
    ),
    (
        "memory_get",
        {**common_arguments(), "memory_id": str(uid(12))},
        MemoryGetQuery,
    ),
    (
        "memory_timeline",
        {
            **common_arguments(),
            "window": {
                "starts_at": "2026-08-08T12:00:00.000000Z",
                "ends_at": "2026-08-08T13:00:00.000000Z",
            },
            "limit": 5,
        },
        MemoryTimelineQuery,
    ),
    (
        "memory_conflicts",
        {**common_arguments(), "subject_id": str(uid(14)), "limit": 5},
        MemoryConflictsQuery,
    ),
    ("memory_lineage", common_arguments(), MemoryLineageQuery),
    (
        "memory_selection_history",
        {**common_arguments(), "limit": 5},
        MemorySelectionHistoryQuery,
    ),
    (
        "memory_ingress_status",
        {"contract_version": "mcp-read-v1", "ingress_id": str(uid(15))},
        IngressStatusQuery,
    ),
    (
        "memory_transport_status",
        {"contract_version": "mcp-read-v1"},
        TransportStatusQuery,
    ),
]


class RecordingResolver:
    def __init__(self) -> None:
        self.contexts: list[object] = []

    async def __call__(self, context: object) -> QueryPrincipal | ReadError:
        self.contexts.append(context)
        return principal()


class RecordingReadExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[QueryPrincipal, object]] = []

    async def __call__(self, authority: QueryPrincipal, query: object) -> ReadError:
        self.calls.append((authority, query))
        return ReadError(
            error=ReadErrorBody(
                code="not_found",
                message=ReadErrorBody.SAFE_MESSAGES["not_found"],
            )
        )


class RaisingResolver:
    async def __call__(self, context: object) -> QueryPrincipal | ReadError:
        del context
        raise RuntimeError("SENSITIVE_RESOLVER_MARKER bearer secret")


class RaisingReadExecutor:
    async def __call__(self, authority: QueryPrincipal, query: object) -> ReadError:
        del authority, query
        raise RuntimeError("SENSITIVE_EXECUTOR_MARKER SQL private_statement")


class TransportSuccessExecutor:
    async def __call__(self, authority: QueryPrincipal, query: object) -> TransportStatusResult:
        del authority, query
        return TransportStatusResult(
            result=TransportStatusPayload(
                transport_kind=TransportKind.DIRECT_PRIVATE,
                installation_state="not_applicable",
                health_state=None,
                freshness="never",
            )
        )


class OversizedSearchExecutor:
    async def __call__(self, authority: QueryPrincipal, query: object) -> MemorySearchResult:
        del authority, query
        fixture = Path(__file__).parent / "fixtures/json_schemas/context-pack.schema.json"
        template = ContextPackResult.model_validate_json(fixture.read_text(encoding="utf-8"))
        hit = template.result.persona[0]
        hits = tuple(
            hit.model_copy(update={"memory_id": uid(100 + index), "statement": "x" * 8192})
            for index in range(40)
        )
        return MemorySearchResult(
            result=MemorySearchPage(query_id=uid(99), hits=hits),
            metadata=ReadResultMetadata(),
        )


@asynccontextmanager
async def mcp_session(app: FastAPI) -> AsyncIterator[ClientSession]:
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client,
        streamable_http_client("http://127.0.0.1:8080/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        yield session


def read_app(
    resolver: ReadPrincipalResolver | None = None,
    executor: ReadExecutor | None = None,
) -> FastAPI:
    kwargs: dict[str, object] = {}
    if resolver is not None:
        kwargs["read_principal_resolver"] = resolver
    if executor is not None:
        kwargs["read_executor"] = executor
    return create_app(Settings(environment="test"), **kwargs)  # type: ignore[arg-type]


async def test_production_discovery_lists_nine_reads_before_eight_mutations() -> None:
    async with mcp_session(read_app()) as session:
        initialized = await session.initialize()
        tools = (await session.list_tools()).tools

    assert initialized.instructions is not None
    assert initialized.instructions.startswith(
        "Use this server as the authoritative shared continuity store for the Kivra persona."
    )
    assert [tool.name for tool in tools] == READ_TOOL_NAMES + MUTATION_TOOL_NAMES


async def test_read_schemas_are_closed_explicit_and_have_read_annotations() -> None:
    async with mcp_session(read_app()) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools[: len(READ_TOOL_NAMES)]

    forbidden = {
        "tenant_id",
        "actor_id",
        "client_id",
        "installation_id",
        "transport_binding_id",
        "authorization",
    }
    for tool in tools:
        assert tool.inputSchema["additionalProperties"] is False
        assert "contract_version" in tool.inputSchema["required"]
        assert forbidden.isdisjoint(tool.inputSchema["properties"])
        assert tool.outputSchema is not None
        for definition in tool.outputSchema.get("$defs", {}).values():
            if definition.get("type") == "object" and "properties" in definition:
                assert set(definition["required"]) == set(definition["properties"])
                assert definition["additionalProperties"] is False
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is False
    semantic_uuid = tools[0].inputSchema["properties"]["persona_id"]
    ingress_uuid = tools[7].inputSchema["properties"]["ingress_id"]
    assert semantic_uuid["pattern"].startswith("^[0-9a-f]")
    assert ingress_uuid["pattern"].startswith("^[0-9a-f]")


@pytest.mark.parametrize(("tool_name", "arguments", "query_type"), READ_CASES)
async def test_each_read_resolves_principal_and_dispatches_exactly_once(
    tool_name: str,
    arguments: dict[str, Any],
    query_type: type[object],
) -> None:
    resolver = RecordingResolver()
    executor = RecordingReadExecutor()
    async with mcp_session(read_app(resolver, executor)) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "not_found"
    assert len(resolver.contexts) == 1
    assert len(executor.calls) == 1
    assert executor.calls[0][0] == principal()
    assert type(executor.calls[0][1]) is query_type


async def test_principal_is_resolved_again_for_every_request() -> None:
    resolver = RecordingResolver()
    executor = RecordingReadExecutor()
    async with mcp_session(read_app(resolver, executor)) as session:
        await session.initialize()
        first = await session.call_tool("memory_lineage", common_arguments())
        second = await session.call_tool("memory_lineage", common_arguments())

    assert first.structuredContent is not None
    assert second.structuredContent is not None
    assert len(resolver.contexts) == 2
    assert len(executor.calls) == 2


async def test_default_read_dependencies_fail_closed_before_execution() -> None:
    async with mcp_session(read_app()) as session:
        await session.initialize()
        result = await session.call_tool("memory_lineage", common_arguments())

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "dependency_unavailable"


async def test_success_response_is_unwrapped_structured_content() -> None:
    async with mcp_session(read_app(RecordingResolver(), TransportSuccessExecutor())) as session:
        await session.initialize()
        result = await session.call_tool(
            "memory_transport_status", {"contract_version": "mcp-read-v1"}
        )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    assert result.structuredContent["tool"] == "memory_transport_status"
    assert result.structuredContent["result"]["transport_kind"] == "direct_private"
    assert "root" not in result.structuredContent


async def test_oversized_executor_response_fails_closed_below_transport_ceiling() -> None:
    async with mcp_session(read_app(RecordingResolver(), OversizedSearchExecutor())) as session:
        await session.initialize()
        result = await session.call_tool(
            "memory_search", {**common_arguments(), "query": "bounded", "limit": 40}
        )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "internal_error"
    serialized = json.dumps(result.structuredContent, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= HARD_RESPONSE_BYTE_CEILING


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        (
            "memory_context_pack",
            {
                **common_arguments(),
                "query": "strict bool",
                "token_budget": 512,
                "include_evidence": "true",
            },
        ),
        (
            "memory_context_pack",
            {**common_arguments(), "query": "strict int", "token_budget": "512"},
        ),
        (
            "memory_search",
            {**common_arguments(), "query": "strict limit", "limit": "5"},
        ),
        (
            "memory_search",
            {**common_arguments(), "query": "nested", "filters": "SECRET_MARKER"},
        ),
        (
            "memory_lineage",
            {**common_arguments(), "persona_id": str(uid(10)).upper()},
        ),
    ],
)
async def test_noncanonical_input_is_sanitized_before_authority_or_execution(
    tool_name: str, arguments: dict[str, Any]
) -> None:
    resolver = RecordingResolver()
    executor = RecordingReadExecutor()
    async with mcp_session(read_app(resolver, executor)) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, arguments)

    rendered = repr(result.model_dump(mode="json"))
    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert "SECRET_MARKER" not in rendered
    assert resolver.contexts == []
    assert executor.calls == []


async def test_resolver_exception_is_sanitized_without_executor_call() -> None:
    executor = RecordingReadExecutor()
    async with mcp_session(read_app(RaisingResolver(), executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_lineage", common_arguments())

    rendered = repr(result.model_dump(mode="json"))
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "internal_error"
    assert "SENSITIVE_RESOLVER_MARKER" not in rendered
    assert executor.calls == []


async def test_executor_exception_is_sanitized() -> None:
    async with mcp_session(read_app(RecordingResolver(), RaisingReadExecutor())) as session:
        await session.initialize()
        result = await session.call_tool("memory_lineage", common_arguments())

    rendered = repr(result.model_dump(mode="json"))
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "internal_error"
    assert "SENSITIVE_EXECUTOR_MARKER" not in rendered
    assert "private_statement" not in rendered
