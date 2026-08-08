from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.api.mcp import MutationExecutor
from kivra_memory.config import Settings
from kivra_memory.domain.commands import (
    DirectMutationCommand,
    ForgetCommand,
    LinkCommand,
    MutationResponse,
    MutationResult,
    ObserveCommand,
    OpenConflictCommand,
    RememberCommand,
    ResolveConflictCommand,
    RetireCommand,
    ReviseCommand,
)
from kivra_memory.domain.identifiers import new_uuid7
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

TOOL_NAMES = [
    "memory_observe",
    "memory_remember",
    "memory_revise",
    "memory_link",
    "memory_open_conflict",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_forget",
]
MutationOperation = Literal[
    "observe",
    "remember",
    "revise",
    "link",
    "open_conflict",
    "resolve_conflict",
    "retire",
    "forget",
]


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def common_arguments() -> dict[str, Any]:
    return {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": "mcp-contract-test:one",
        "logical_session_id": str(uid(1)),
        "persona_id": str(uid(2)),
        "branch_id": str(uid(3)),
        "reason": "Exercise the MCP command adapter.",
    }


def memory_arguments() -> dict[str, Any]:
    return {
        "subject_id": str(uid(4)),
        "subject_kind": "project",
        "category": "project_decision",
        "ontological_status": "literal_technical_fact",
        "scope": "project",
        "visibility": "private_root",
        "statement": "The MCP adapter constructs strict domain commands.",
        "reason_to_remember": "This is durable contract-test context.",
        "interpretation_limits": ["Synthetic fixture only."],
        "confidence": 0.9,
        "salience": 0.8,
        "durability": 0.7,
        "sensitivity": 0,
        "authority_class": "verified_project_source",
        "observed_at": "2026-08-08T12:00:00Z",
        "origin_session_id": str(uid(1)),
        "metadata": {"fixture": True},
    }


def mutation_arguments() -> list[tuple[str, dict[str, Any], type[DirectMutationCommand]]]:
    common = common_arguments()
    return [
        ("memory_observe", {**common, "memory": memory_arguments()}, ObserveCommand),
        ("memory_remember", {**common, "memory": memory_arguments()}, RememberCommand),
        (
            "memory_revise",
            {
                **common,
                "memory_id": str(uid(10)),
                "expected_revision": 1,
                "changes": {"statement": "The strict adapter was exercised."},
            },
            ReviseCommand,
        ),
        (
            "memory_link",
            {
                **common,
                "source_memory_id": str(uid(10)),
                "source_expected_revision": 1,
                "target_memory_id": str(uid(11)),
                "target_expected_revision": 2,
                "link_type": "supports",
            },
            LinkCommand,
        ),
        (
            "memory_open_conflict",
            {
                **common,
                "subject_id": str(uid(4)),
                "members": [
                    {"memory_id": str(uid(10)), "expected_revision": 1},
                    {"memory_id": str(uid(11)), "expected_revision": 2},
                ],
                "conflict_reason": "The synthetic claims cannot both hold.",
            },
            OpenConflictCommand,
        ),
        (
            "memory_resolve_conflict",
            {
                **common,
                "conflict_id": str(uid(12)),
                "members": [
                    {
                        "memory_id": str(uid(10)),
                        "expected_revision": 2,
                        "disposition": "retained",
                        "resulting_status": "active",
                    },
                    {
                        "memory_id": str(uid(11)),
                        "expected_revision": 3,
                        "disposition": "retired",
                        "resulting_status": "retired",
                    },
                ],
                "resolution_kind": "explicit_user_resolution",
                "resolution_rationale": "The synthetic authority selected one claim.",
                "user_confirmed": True,
            },
            ResolveConflictCommand,
        ),
        (
            "memory_retire",
            {**common, "memory_id": str(uid(10)), "expected_revision": 2},
            RetireCommand,
        ),
        (
            "memory_forget",
            {
                **common,
                "memory_id": str(uid(10)),
                "expected_revision": 2,
                "mode": "logical",
                "confirmation": "confirm_logical_forget",
            },
            ForgetCommand,
        ),
    ]


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[DirectMutationCommand] = []

    async def __call__(self, command: DirectMutationCommand) -> MutationResponse:
        self.calls.append(command)
        fields: dict[str, Any] = {}
        if command.OPERATION == "open_conflict":
            fields.update(conflict_id=uid(42), conflict_state="open")
        elif command.OPERATION == "resolve_conflict":
            fields.update(conflict_id=uid(42), conflict_state="resolved")
        elif command.OPERATION == "forget":
            fields["forget_state"] = "logically_forgotten"
        return MutationResult(
            contract_version="mcp-mutation-v1",
            operation=cast(MutationOperation, command.OPERATION),
            receipt_id=uid(40),
            event_id=uid(41),
            **fields,
        )


class RaisingExecutor:
    async def __call__(self, command: DirectMutationCommand) -> MutationResponse:
        del command
        raise RuntimeError("SENSITIVE_EXECUTOR_MARKER SQL SELECT private_memory")


@asynccontextmanager
async def mcp_session(app: FastAPI) -> AsyncIterator[ClientSession]:
    transport = ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as http_client,
        streamable_http_client(
            "http://127.0.0.1:8080/mcp",
            http_client=http_client,
        ) as (read_stream, write_stream, _),
        ClientSession(read_stream, write_stream) as session,
    ):
        yield session


def mutation_app(executor: MutationExecutor | None = None) -> FastAPI:
    settings = Settings(environment="test")
    return create_app(settings, mutation_executor=executor) if executor else create_app(settings)


async def test_mutation_schemas_keep_identity_out_of_top_level_arguments() -> None:
    async with mcp_session(mutation_app()) as session:
        await session.initialize()
        tools = [tool for tool in (await session.list_tools()).tools if tool.name in TOOL_NAMES]

    forbidden = {
        "tenant_id",
        "actor_id",
        "client_id",
        "installation_id",
        "transport_kind",
        "transport_binding_id",
        "authorization_scope",
        "command",
    }
    common = {
        "contract_version",
        "idempotency_key",
        "logical_session_id",
        "persona_id",
        "branch_id",
        "reason",
        "causation_event_id",
    }
    for tool in tools:
        properties = tool.inputSchema["properties"]
        assert tool.inputSchema["additionalProperties"] is False
        assert common <= properties.keys()
        assert forbidden.isdisjoint(properties)
        assert properties["contract_version"]["const"] == "mcp-mutation-v1"
        assert properties["idempotency_key"]["minLength"] == 1
        assert properties["idempotency_key"]["maxLength"] == 255
        assert tool.outputSchema is not None
        output_definitions = tool.outputSchema["$defs"]
        assert set(output_definitions["MutationResult"]["required"]) == {
            "ok",
            "contract_version",
            "operation",
            "receipt_id",
            "event_id",
            "memory_id",
            "revision",
            "idempotent_replay",
            "conflict_id",
            "conflict_state",
            "forget_state",
            "warnings",
        }
        assert set(output_definitions["MutationError"]["required"]) == {
            "ok",
            "contract_version",
            "error",
        }
        assert set(output_definitions["MutationErrorBody"]["required"]) == {
            "code",
            "message",
            "retryable",
            "retry_after_ms",
            "details",
        }
        assert output_definitions["MutationResult"]["properties"]["ok"]["const"] is True
        assert output_definitions["MutationError"]["properties"]["ok"]["const"] is False
        assert (
            output_definitions["MutationResult"]["properties"]["contract_version"]["const"]
            == "mcp-mutation-v1"
        )
        assert (
            output_definitions["MutationError"]["properties"]["contract_version"]["const"]
            == "mcp-mutation-v1"
        )
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is False
        assert tool.annotations.destructiveHint is (tool.name == "memory_forget")


@pytest.mark.parametrize(("tool_name", "arguments", "command_type"), mutation_arguments())
async def test_each_tool_constructs_one_strict_command_and_returns_unwrapped_structured_output(
    tool_name: str,
    arguments: dict[str, Any],
    command_type: type[DirectMutationCommand],
) -> None:
    executor = RecordingExecutor()
    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    assert result.structuredContent["operation"] == tool_name.removeprefix("memory_")
    assert "root" not in result.structuredContent
    assert "result" not in result.structuredContent
    assert len(executor.calls) == 1
    assert type(executor.calls[0]) is command_type
    assert executor.calls[0].model_config["strict"] is True


async def test_default_app_executor_fails_closed_without_authenticated_identity() -> None:
    _, arguments, _ = mutation_arguments()[6]
    async with mcp_session(mutation_app()) as session:
        await session.initialize()
        result = await session.call_tool("memory_retire", arguments)

    assert result.isError is False
    assert result.structuredContent == {
        "ok": False,
        "contract_version": "mcp-mutation-v1",
        "error": {
            "code": "dependency_unavailable",
            "message": "A required dependency is unavailable.",
            "retryable": False,
            "retry_after_ms": None,
            "details": None,
        },
    }


async def test_uuidv7_is_rejected_before_executor_invocation() -> None:
    executor = RecordingExecutor()
    _, arguments, _ = mutation_arguments()[6]
    arguments["memory_id"] = str(uuid4())
    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_retire", arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert executor.calls == []


async def test_forget_confirmation_mismatch_returns_safe_structured_invalid_input() -> None:
    executor = RecordingExecutor()
    _, arguments, _ = mutation_arguments()[7]
    arguments["confirmation"] = "confirm_hard_forget"
    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_forget", arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is False
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert executor.calls == []


async def test_unknown_top_level_fields_are_rejected_before_executor_invocation() -> None:
    executor = RecordingExecutor()
    _, arguments, _ = mutation_arguments()[6]
    arguments["tenant_id"] = str(uid(99))
    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_retire", arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert executor.calls == []


async def test_executor_exception_returns_safe_internal_error_without_sensitive_text() -> None:
    _, arguments, _ = mutation_arguments()[6]
    async with mcp_session(mutation_app(RaisingExecutor())) as session:
        await session.initialize()
        result = await session.call_tool("memory_retire", arguments)

    rendered = repr(result.model_dump(mode="json"))
    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "internal_error"
    assert "SENSITIVE_EXECUTOR_MARKER" not in rendered
    assert "private_memory" not in rendered


async def test_malformed_nested_payload_returns_sanitized_structured_error() -> None:
    executor = RecordingExecutor()
    _, arguments, _ = mutation_arguments()[0]
    arguments["memory"]["statement"] = "SENSITIVE_NESTED_MARKER"
    arguments["memory"]["confidence"] = "not-a-number"
    arguments["memory"]["metadata"] = {"sql": "SELECT SENSITIVE_NESTED_MARKER"}
    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_observe", arguments)

    rendered = repr(result.model_dump(mode="json"))
    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert "SENSITIVE_NESTED_MARKER" not in rendered
    assert "not-a-number" not in rendered
    assert executor.calls == []


@pytest.mark.parametrize(
    ("tool_index", "field_path", "invalid_value"),
    [
        (0, ("memory", "confidence"), "0.9"),
        (0, ("memory", "sensitivity"), "0"),
        (0, ("memory",), '{"statement":"SENSITIVE_JSON_STRING"}'),
        (5, ("user_confirmed",), "true"),
        (6, ("expected_revision",), "2"),
        (6, ("memory_id",), str(uid(10)).upper()),
    ],
)
async def test_noncanonical_json_scalars_and_uuid_spellings_never_reach_executor(
    tool_index: int,
    field_path: tuple[str, ...],
    invalid_value: object,
) -> None:
    executor = RecordingExecutor()
    tool_name, arguments, _ = mutation_arguments()[tool_index]
    target = arguments
    for field_name in field_path[:-1]:
        target = target[field_name]
    target[field_path[-1]] = invalid_value

    async with mcp_session(mutation_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, arguments)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert executor.calls == []
