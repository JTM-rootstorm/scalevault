from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any
from uuid import UUID

import pytest
from kivra_memory.api.mcp import NominationWireRequest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.tools.diagnostics import (
    ConfigurationError,
    DiagnosticConfig,
    DiagnosticSession,
    InitializedServer,
    main,
    run_diagnostics,
)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def config(*, write: bool = False, expected_transport: str = "direct_private") -> DiagnosticConfig:
    return DiagnosticConfig(
        url="https://memory.example.test/mcp",
        bearer_token="SENSITIVE_BEARER_TOKEN",
        persona_id=uid(1),
        branch_id=uid(2),
        expected_transport=expected_transport,  # type: ignore[arg-type]
        canary_subject_id=uid(3) if write else None,
        write_canary=write,
        write_confirmation="nominate-routine-banter-and-require-omit" if write else None,
    )


class FakeSession:
    def __init__(
        self,
        *,
        transport: str = "direct_private",
        nomination_outcome: str = "omit",
    ) -> None:
        self.transport = transport
        self.nomination_outcome = nomination_outcome
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.memory_id = str(uid(30))

    async def initialize(self) -> InitializedServer:
        return InitializedServer(name="ScaleVault Memory Node", instructions_present=True)

    async def list_tools(self) -> frozenset[str]:
        return frozenset(
            {
                "memory_get",
                "memory_transport_status",
                "memory_nominate",
            }
        )

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append((name, arguments))
        if name == "memory_transport_status":
            return {
                "ok": True,
                "result": {
                    "transport_kind": self.transport,
                    "installation_state": (
                        "not_applicable" if self.transport == "direct_private" else "active"
                    ),
                },
            }
        if name == "memory_get":
            return {"ok": False, "error": {"code": "not_found"}}
        if name == "memory_nominate":
            if self.nomination_outcome in {"omit", "reject"}:
                return {
                    "ok": True,
                    "operation": "nominate",
                    "outcome": self.nomination_outcome,
                    "event_id": None,
                    "memory_id": None,
                    "revision": None,
                }
            return {
                "ok": True,
                "operation": "nominate",
                "outcome": self.nomination_outcome,
                "memory_id": self.memory_id,
                "revision": 1,
            }
        return {"ok": False, "error": {"code": "dependency_unavailable"}}


def factory(
    session: DiagnosticSession,
) -> Callable[[DiagnosticConfig], AbstractAsyncContextManager[DiagnosticSession]]:
    @asynccontextmanager
    async def connect(_config: DiagnosticConfig) -> AsyncIterator[DiagnosticSession]:
        yield session

    return connect


def test_config_redacts_bearer_and_rejects_unencrypted_non_loopback_url() -> None:
    assert "SENSITIVE_BEARER_TOKEN" not in repr(config())

    with pytest.raises(ConfigurationError, match="unencrypted_non_loopback_url"):
        DiagnosticConfig(
            url="http://memory.example.test/mcp",
            bearer_token="token",
            persona_id=uid(1),
            branch_id=uid(2),
            expected_transport="direct_private",
        )


def test_write_canary_requires_both_explicit_opt_ins() -> None:
    with pytest.raises(ConfigurationError, match="write_confirmation_required"):
        DiagnosticConfig(
            url="https://memory.example.test/mcp",
            bearer_token="token",
            persona_id=uid(1),
            branch_id=uid(2),
            expected_transport="direct_private",
            write_canary=True,
            canary_subject_id=uid(3),
        )

    with pytest.raises(ConfigurationError, match="canary_subject_required"):
        DiagnosticConfig(
            url="https://memory.example.test/mcp",
            bearer_token="token",
            persona_id=uid(1),
            branch_id=uid(2),
            expected_transport="direct_private",
            write_canary=True,
            write_confirmation="nominate-routine-banter-and-require-omit",
        )


async def test_read_only_diagnostic_checks_auth_discovery_transport_and_read() -> None:
    session = FakeSession()
    report = await run_diagnostics(config(), factory(session))

    assert report.ok is True
    assert [check.name for check in report.checks] == [
        "authentication",
        "server_identity",
        "discovery",
        "transport_identity",
        "read_canary",
        "write_canary",
    ]
    assert report.checks[-1].status == "skipped"
    assert [name for name, _ in session.calls] == ["memory_transport_status", "memory_get"]
    assert session.calls[1][1]["memory_id"] not in {str(uid(1)), str(uid(2))}
    assert "SENSITIVE_BEARER_TOKEN" not in json.dumps(report.as_dict())


async def test_write_canary_requires_non_persisting_routine_banter_omit() -> None:
    session = FakeSession()
    report = await run_diagnostics(config(write=True), factory(session))

    assert report.ok is True
    assert report.recovery_reference is None
    assert [name for name, _ in session.calls][-1:] == ["memory_nominate"]
    nomination = session.calls[-1][1]
    parsed_nomination = NominationWireRequest.model_validate_json(json.dumps(nomination))
    assert parsed_nomination.proposal.selection_basis.value == "routine_banter"
    assert parsed_nomination.logical_session_id is None
    assert parsed_nomination.proposal.subject_id == uid(3)
    assert parsed_nomination.proposal.subject_kind.value == "project"
    assert parsed_nomination.proposal.scope.value == "project"
    assert parsed_nomination.proposal.origin_session_id is None
    assert parsed_nomination.proposal.evidence_references == ()
    assert report.checks[-1].code == "write_omit_confirmed"


async def test_reject_fails_without_claiming_recovery_is_needed() -> None:
    session = FakeSession(nomination_outcome="reject")
    report = await run_diagnostics(config(write=True), factory(session))

    assert report.ok is False
    assert report.checks[-1].code == "nomination_reject"
    assert report.recovery_reference is None


async def test_unexpected_durable_result_exposes_only_synthetic_recovery_reference() -> None:
    session = FakeSession(nomination_outcome="candidate")
    report = await run_diagnostics(config(write=True), factory(session))

    assert report.ok is False
    assert report.checks[-1].code == "unexpected_durable_nomination"
    assert report.recovery_reference is not None
    assert report.recovery_reference.memory_id == session.memory_id
    assert report.recovery_reference.expected_revision == 1
    rendered = json.dumps(report.as_dict())
    assert "ScaleVault diagnostic" not in rendered
    assert "SENSITIVE_BEARER_TOKEN" not in rendered


async def test_unexpected_transport_fails_before_canaries() -> None:
    session = FakeSession(transport="relay")
    report = await run_diagnostics(config(), factory(session))

    assert report.ok is False
    assert report.checks[-1].code == "unexpected_transport"
    assert [name for name, _ in session.calls] == ["memory_transport_status"]


def test_cli_configuration_failure_is_payload_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("KIVRA_MEMORY_MCP_URL", raising=False)
    monkeypatch.delenv("KIVRA_MEMORY_TOKEN", raising=False)
    monkeypatch.delenv("KIVRA_MEMORY_PERSONA_ID", raising=False)
    monkeypatch.delenv("KIVRA_MEMORY_BRANCH_ID", raising=False)

    with pytest.raises(SystemExit) as raised:
        main([])

    assert raised.value.code == 2
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "checks": [
            {
                "code": "invalid_scope_identifier",
                "name": "configuration",
                "status": "fail",
            }
        ],
        "ok": False,
    }
