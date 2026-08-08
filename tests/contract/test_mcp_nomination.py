from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.api.mcp import (
    NominationError,
    NominationExecutor,
    NominationResponse,
    NominationWireRequest,
)
from kivra_memory.application.selection import NominationCommandLike, SelectionResult
from kivra_memory.config import Settings
from kivra_memory.domain.identifiers import new_uuid7
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def nomination_arguments() -> dict[str, Any]:
    return {
        "contract_version": "mcp-mutation-v2",
        "idempotency_key": "nomination-contract:one",
        "persona_id": str(uid(1)),
        "branch_id": str(uid(2)),
        "logical_session_id": str(uid(3)),
        "reason": "Evaluate a durable project decision.",
        "proposal": {
            "subject_id": str(uid(4)),
            "subject_kind": "project",
            "category": "project_decision",
            "ontological_status": "literal_technical_fact",
            "scope": "project",
            "visibility": "private_root",
            "statement": "The nomination adapter accepts only untrusted semantic intent.",
            "reason_to_remember": "This is a durable contract boundary.",
            "interpretation_limits": ["Synthetic test fixture."],
            "confidence": 0.9,
            "salience": 0.8,
            "durability": 0.9,
            "sensitivity": 0,
            "observed_at": "2026-08-08T12:00:00Z",
            "origin_session_id": str(uid(3)),
            "metadata": {"fixture": True},
            "selection_basis": "verified_project_decision",
            "epistemic_qualifiers": [],
            "evidence_references": [
                {
                    "evidence_key": "project-source",
                    "opaque_reference": "opaque:test:project-source",
                }
            ],
        },
    }


class RecordingNominationExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[object, NominationCommandLike]] = []

    async def __call__(self, context: object, command: NominationCommandLike) -> NominationResponse:
        self.calls.append((context, command))
        return SelectionResult(
            receipt_id=uid(10),
            decision_id=uid(11),
            outcome="active",
            policy_version="selection-v1",
            policy_sha256="a" * 64,
            reason_codes=("verified_project_decision",),
            matched_rule_ids=("basis.verified_project_decision",),
            event_id=uid(12),
            memory_id=uid(13),
            revision=1,
        )


class RaisingNominationExecutor:
    async def __call__(self, context: object, command: NominationCommandLike) -> NominationResponse:
        del context, command
        raise RuntimeError("SENSITIVE_NOMINATION_MARKER SQL private statement")


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


def nomination_app(executor: NominationExecutor | None = None) -> FastAPI:
    if executor is None:
        return create_app(Settings(environment="test"))
    return create_app(Settings(environment="test"), nomination_executor=executor)


async def test_nomination_schema_excludes_trusted_and_identity_inputs() -> None:
    async with mcp_session(nomination_app()) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools

    tool = tools[10]
    assert tool.name == "memory_nominate"
    assert tool.inputSchema["additionalProperties"] is False
    rendered = repr(tool.inputSchema)
    for forbidden in (
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "effective_authority_class",
        "authority_class",
        "evidence_trust",
        "content_signals",
        "candidate_deadline",
        "policy_outcome",
    ):
        assert forbidden not in rendered
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is False
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.idempotentHint is True
    assert tool.annotations.openWorldHint is False
    assert tool.outputSchema is not None
    assert set(tool.outputSchema["$defs"]["SelectionResult"]["properties"]) == {
        "ok",
        "contract_version",
        "operation",
        "receipt_id",
        "decision_id",
        "outcome",
        "policy_version",
        "policy_sha256",
        "reason_codes",
        "matched_rule_ids",
        "event_id",
        "memory_id",
        "revision",
        "idempotent_replay",
        "warnings",
    }
    for definition in tool.outputSchema.get("$defs", {}).values():
        if definition.get("type") == "object" and "properties" in definition:
            assert set(definition["required"]) == set(definition["properties"])


async def test_nomination_constructs_strict_dto_and_calls_executor_once() -> None:
    executor = RecordingNominationExecutor()
    async with mcp_session(nomination_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_nominate", nomination_arguments())

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    assert result.structuredContent["outcome"] == "active"
    assert result.structuredContent["policy_version"] == "selection-v1"
    assert "root" not in result.structuredContent
    assert len(executor.calls) == 1
    command = executor.calls[0][1]
    assert type(command) is NominationWireRequest
    assert not hasattr(command.proposal, "effective_authority_class")
    assert not hasattr(command.proposal, "content_signals")


async def test_default_nomination_executor_fails_closed() -> None:
    async with mcp_session(nomination_app()) as session:
        await session.initialize()
        result = await session.call_tool("memory_nominate", nomination_arguments())

    assert result.structuredContent is not None
    assert result.structuredContent["contract_version"] == "mcp-mutation-v2"
    assert result.structuredContent["error"]["code"] == "dependency_unavailable"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("persona_id",), str(uid(1)).upper()),
        (("proposal", "confidence"), "0.9"),
        (("proposal", "sensitivity"), "0"),
        (("proposal", "epistemic_qualifiers"), "roleplay_not_literal"),
    ],
)
async def test_invalid_nomination_never_reaches_executor(
    path: tuple[str, ...], value: object
) -> None:
    executor = RecordingNominationExecutor()
    arguments = nomination_arguments()
    target = arguments
    for field_name in path[:-1]:
        target = target[field_name]
    target[path[-1]] = value

    async with mcp_session(nomination_app(executor)) as session:
        await session.initialize()
        result = await session.call_tool("memory_nominate", arguments)

    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "invalid_input"
    assert executor.calls == []


async def test_nomination_exception_and_payload_are_not_reflected() -> None:
    arguments = nomination_arguments()
    arguments["proposal"]["statement"] = "SENSITIVE_INPUT_MARKER"
    async with mcp_session(nomination_app(RaisingNominationExecutor())) as session:
        await session.initialize()
        result = await session.call_tool("memory_nominate", arguments)

    rendered = repr(result.model_dump(mode="json"))
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "internal_error"
    assert "SENSITIVE_NOMINATION_MARKER" not in rendered
    assert "SENSITIVE_INPUT_MARKER" not in rendered
    assert "private statement" not in rendered


def test_omit_and_reject_receipts_cannot_identify_memory_content() -> None:
    with pytest.raises(ValueError, match="cannot identify"):
        SelectionResult(
            receipt_id=uid(20),
            decision_id=uid(21),
            outcome="reject",
            policy_version="selection-v1",
            policy_sha256="b" * 64,
            reason_codes=("authority_not_established",),
            matched_rule_ids=(),
            event_id=uid(22),
            memory_id=None,
            revision=None,
        )


def test_nomination_error_contract_has_no_arbitrary_diagnostics() -> None:
    assert set(NominationError.model_fields) == {"ok", "contract_version", "error"}
