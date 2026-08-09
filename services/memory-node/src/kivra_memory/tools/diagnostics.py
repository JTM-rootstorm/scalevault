"""Payload-safe diagnostics for a Codex-to-ScaleVault MCP connection."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from kivra_memory.domain.identifiers import is_uuid7, new_uuid7

TransportKind = Literal["direct_private", "secure_tunnel", "relay"]
CheckStatus = Literal["pass", "fail", "skipped"]

_EXPECTED_SERVER_NAME = "ScaleVault Memory Node"
_REQUIRED_TOOLS = frozenset(
    {
        "memory_get",
        "memory_transport_status",
        "memory_nominate",
    }
)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_WRITE_CONFIRMATION = "nominate-routine-banter-and-require-omit"


class ConfigurationError(ValueError):
    """A payload-safe local diagnostic configuration failure."""


@dataclass(frozen=True, slots=True)
class DiagnosticConfig:
    """Validated connection and canary inputs.

    The bearer token is intentionally excluded from dataclass representations.
    """

    url: str
    bearer_token: str = field(repr=False)
    persona_id: UUID
    branch_id: UUID
    expected_transport: TransportKind
    canary_subject_id: UUID | None = None
    timeout_seconds: float = 15.0
    write_canary: bool = False
    write_confirmation: str | None = None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("invalid_url")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigurationError("invalid_url")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("unencrypted_non_loopback_url")
        if not self.bearer_token or self.bearer_token != self.bearer_token.strip():
            raise ConfigurationError("invalid_bearer_token")
        if not is_uuid7(self.persona_id) or not is_uuid7(self.branch_id):
            raise ConfigurationError("invalid_scope_identifier")
        if self.canary_subject_id is not None and not is_uuid7(self.canary_subject_id):
            raise ConfigurationError("invalid_canary_subject_identifier")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ConfigurationError("invalid_timeout")
        if self.write_canary and self.write_confirmation != _WRITE_CONFIRMATION:
            raise ConfigurationError("write_confirmation_required")
        if self.write_canary and self.canary_subject_id is None:
            raise ConfigurationError("canary_subject_required")
        if not self.write_canary and self.write_confirmation is not None:
            raise ConfigurationError("write_confirmation_without_canary")


@dataclass(frozen=True, slots=True)
class InitializedServer:
    name: str
    instructions_present: bool


class DiagnosticSession(Protocol):
    """Minimal MCP client seam used by the deterministic diagnostic runner."""

    async def initialize(self) -> InitializedServer: ...

    async def list_tools(self) -> frozenset[str]: ...

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    name: str
    status: CheckStatus
    code: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "code": self.code}


@dataclass(frozen=True, slots=True)
class RecoveryReference:
    """Synthetic identifier needed only after an anomalous durable nomination."""

    memory_id: str
    expected_revision: int

    def as_dict(self) -> dict[str, str | int]:
        return {
            "memory_id": self.memory_id,
            "expected_revision": self.expected_revision,
        }


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    checks: tuple[DiagnosticCheck, ...]
    recovery_reference: RecoveryReference | None = None

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "ok": self.ok,
            "checks": [check.as_dict() for check in self.checks],
        }
        if self.recovery_reference is not None:
            result["recovery_required"] = self.recovery_reference.as_dict()
        return result


type SessionFactory = Callable[[DiagnosticConfig], AbstractAsyncContextManager[DiagnosticSession]]


class _McpSessionAdapter:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def initialize(self) -> InitializedServer:
        result = await self._session.initialize()
        return InitializedServer(
            name=result.serverInfo.name,
            instructions_present=bool(result.instructions),
        )

    async def list_tools(self) -> frozenset[str]:
        result = await self._session.list_tools()
        return frozenset(tool.name for tool in result.tools)

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        result = await self._session.call_tool(name, dict(arguments))
        if not isinstance(result.structuredContent, dict):
            return {}
        return result.structuredContent


@asynccontextmanager
async def connect_mcp(config: DiagnosticConfig) -> AsyncIterator[DiagnosticSession]:
    """Connect without redirects, ambient proxies, or credential-bearing logs."""

    headers = {"Authorization": f"Bearer {config.bearer_token}"}
    timeout = httpx.Timeout(config.timeout_seconds)
    async with (
        httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as http_client,
        streamable_http_client(config.url, http_client=http_client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=config.timeout_seconds),
        ) as session,
    ):
        yield _McpSessionAdapter(session)


def _safe_remote_error(response: Mapping[str, Any]) -> str:
    error = response.get("error")
    if not isinstance(error, Mapping):
        return "invalid_response"
    code = error.get("code")
    if code in {
        "unauthenticated",
        "forbidden",
        "not_found",
        "dependency_unavailable",
        "internal_error",
        "serialization_exhausted",
    }:
        return str(code)
    return "remote_error"


def _success(response: Mapping[str, Any]) -> bool:
    return response.get("ok") is True


def _valid_memory_receipt(response: Mapping[str, Any], operation: str) -> tuple[str, int] | None:
    if not _success(response) or response.get("operation") != operation:
        return None
    memory_id = response.get("memory_id")
    revision = response.get("revision")
    if (
        not isinstance(memory_id, str)
        or isinstance(revision, bool)
        or not isinstance(revision, int)
    ):
        return None
    try:
        parsed = UUID(memory_id)
    except ValueError:
        return None
    if str(parsed) != memory_id or not is_uuid7(parsed) or revision < 1:
        return None
    return memory_id, revision


def _transport_check(response: Mapping[str, Any], expected: TransportKind) -> DiagnosticCheck:
    if not _success(response):
        return DiagnosticCheck("transport_identity", "fail", _safe_remote_error(response))
    result = response.get("result")
    if not isinstance(result, Mapping):
        return DiagnosticCheck("transport_identity", "fail", "invalid_response")
    actual = result.get("transport_kind")
    if actual not in {"direct_private", "secure_tunnel", "relay"}:
        return DiagnosticCheck("transport_identity", "fail", "invalid_response")
    if actual != expected:
        return DiagnosticCheck("transport_identity", "fail", "unexpected_transport")
    expected_installation = "not_applicable" if expected == "direct_private" else "active"
    if result.get("installation_state") != expected_installation:
        return DiagnosticCheck("transport_identity", "fail", "unexpected_installation_state")
    return DiagnosticCheck("transport_identity", "pass", "expected_transport_active")


def _nomination_arguments(config: DiagnosticConfig) -> dict[str, Any]:
    if config.canary_subject_id is None:  # guarded by DiagnosticConfig
        raise ConfigurationError("canary_subject_required")
    return {
        "contract_version": "mcp-mutation-v2",
        "idempotency_key": f"diagnostic-nominate:{new_uuid7()}",
        "logical_session_id": None,
        "persona_id": str(config.persona_id),
        "branch_id": str(config.branch_id),
        "reason": "Verify an explicitly authorized, non-persisting nomination.",
        "proposal": {
            "subject_id": str(config.canary_subject_id),
            "subject_kind": "project",
            "category": "project_state",
            "ontological_status": "literal_technical_fact",
            "scope": "project",
            "visibility": "private_root",
            "statement": "Synthetic diagnostic banter.",
            "reason_to_remember": "Exercise the omission policy path.",
            "interpretation_limits": ["Synthetic diagnostic; must be omitted."],
            "confidence": 1.0,
            "salience": 0.0,
            "durability": 0.0,
            "sensitivity": 0,
            "origin_session_id": None,
            "metadata": {"diagnostic_canary": "v1"},
            "selection_basis": "routine_banter",
            "epistemic_qualifiers": [],
            "evidence_references": [],
        },
    }


async def _run_write_canary(
    session: DiagnosticSession,
    config: DiagnosticConfig,
) -> tuple[DiagnosticCheck, RecoveryReference | None]:
    try:
        nomination = await session.call_tool("memory_nominate", _nomination_arguments(config))
    except Exception:
        return DiagnosticCheck("write_canary", "fail", "write_request_failed"), None
    if not _success(nomination):
        return DiagnosticCheck("write_canary", "fail", _safe_remote_error(nomination)), None
    outcome = nomination.get("outcome")
    if outcome == "omit":
        linked_fields = ("event_id", "memory_id", "revision")
        if any(nomination.get(field_name) is not None for field_name in linked_fields):
            receipt = _valid_memory_receipt(nomination, "nominate")
            recovery = RecoveryReference(*receipt) if receipt is not None else None
            return DiagnosticCheck("write_canary", "fail", "invalid_omit_receipt"), recovery
        return DiagnosticCheck("write_canary", "pass", "write_omit_confirmed"), None
    if outcome == "reject":
        return DiagnosticCheck("write_canary", "fail", "nomination_reject"), None
    if outcome in {"candidate", "active", "promoted"}:
        receipt = _valid_memory_receipt(nomination, "nominate")
        if receipt is None:
            return DiagnosticCheck("write_canary", "fail", "invalid_response"), None
        memory_id, revision = receipt
        return (
            DiagnosticCheck("write_canary", "fail", "unexpected_durable_nomination"),
            RecoveryReference(memory_id, revision),
        )
    return DiagnosticCheck("write_canary", "fail", "invalid_response"), None


def _exception_status_code(error: BaseException) -> int | None:
    pending: list[BaseException] = [error]
    while pending:
        current = pending.pop()
        if isinstance(current, httpx.HTTPStatusError):
            return current.response.status_code
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return None


async def run_diagnostics(
    config: DiagnosticConfig,
    session_factory: SessionFactory = connect_mcp,
) -> DiagnosticReport:
    """Run ordered, fail-closed checks without rendering remote content or exceptions."""

    checks: list[DiagnosticCheck] = []
    recovery_reference: RecoveryReference | None = None
    try:
        async with session_factory(config) as session:
            initialized = await session.initialize()
            checks.append(DiagnosticCheck("authentication", "pass", "initialized"))

            if initialized.name != _EXPECTED_SERVER_NAME:
                checks.append(DiagnosticCheck("server_identity", "fail", "unexpected_server"))
                return DiagnosticReport(tuple(checks))
            if not initialized.instructions_present:
                checks.append(DiagnosticCheck("server_identity", "fail", "instructions_missing"))
                return DiagnosticReport(tuple(checks))
            checks.append(DiagnosticCheck("server_identity", "pass", "scalevault_initialized"))

            tools = await session.list_tools()
            if not tools >= _REQUIRED_TOOLS:
                checks.append(DiagnosticCheck("discovery", "fail", "required_tools_missing"))
                return DiagnosticReport(tuple(checks))
            checks.append(DiagnosticCheck("discovery", "pass", "required_tools_present"))

            transport = await session.call_tool(
                "memory_transport_status",
                {"contract_version": "mcp-read-v1"},
            )
            checks.append(_transport_check(transport, config.expected_transport))
            if checks[-1].status == "fail":
                return DiagnosticReport(tuple(checks))

            read_canary = await session.call_tool(
                "memory_get",
                {
                    "contract_version": "mcp-read-v1",
                    "persona_id": str(config.persona_id),
                    "branch_id": str(config.branch_id),
                    "memory_id": str(new_uuid7()),
                },
            )
            read_code = _safe_remote_error(read_canary)
            if _success(read_canary) or read_code == "not_found":
                checks.append(DiagnosticCheck("read_canary", "pass", "authorized_read_confirmed"))
            else:
                checks.append(DiagnosticCheck("read_canary", "fail", read_code))
                return DiagnosticReport(tuple(checks))

            if config.write_canary:
                write_check, recovery_reference = await _run_write_canary(session, config)
                checks.append(write_check)
            else:
                checks.append(DiagnosticCheck("write_canary", "skipped", "not_requested"))
    except Exception as error:
        status_code = _exception_status_code(error)
        code = "authentication_rejected" if status_code in {401, 403} else "connection_failed"
        check_name = "authentication" if not checks or status_code in {401, 403} else "connection"
        checks.append(DiagnosticCheck(check_name, "fail", code))

    return DiagnosticReport(tuple(checks), recovery_reference)


def _env_name(value: str) -> str:
    if not _ENV_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError("must be an uppercase environment variable name")
    return value


def _uuid7_from_env(environment: Mapping[str, str], name: str) -> UUID:
    raw = environment.get(name)
    try:
        value = UUID(raw) if raw is not None else None
    except ValueError:
        value = None
    if value is None or str(value) != raw or not is_uuid7(value):
        raise ConfigurationError("invalid_scope_identifier")
    return value


def _optional_uuid7_from_env(environment: Mapping[str, str], name: str) -> UUID | None:
    if name not in environment:
        return None
    try:
        return _uuid7_from_env(environment, name)
    except ConfigurationError:
        raise ConfigurationError("invalid_canary_subject_identifier") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kivra-memory-diagnose",
        description="Safely diagnose a Codex-to-ScaleVault MCP connection.",
    )
    parser.add_argument("--url-env", type=_env_name, default="KIVRA_MEMORY_MCP_URL")
    parser.add_argument("--token-env", type=_env_name, default="KIVRA_MEMORY_TOKEN")
    parser.add_argument("--persona-id-env", type=_env_name, default="KIVRA_MEMORY_PERSONA_ID")
    parser.add_argument("--branch-id-env", type=_env_name, default="KIVRA_MEMORY_BRANCH_ID")
    parser.add_argument(
        "--canary-subject-id-env",
        type=_env_name,
        default="KIVRA_MEMORY_CANARY_SUBJECT_ID",
    )
    parser.add_argument(
        "--expected-transport",
        choices=("direct_private", "secure_tunnel", "relay"),
        default="direct_private",
    )
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--write-canary", action="store_true")
    parser.add_argument(
        "--confirm-write-canary",
        choices=(_WRITE_CONFIRMATION,),
        help="Required with --write-canary; the nomination must be omitted without an event.",
    )
    return parser


def _config_from_args(args: argparse.Namespace, environment: Mapping[str, str]) -> DiagnosticConfig:
    url = environment.get(args.url_env, "")
    token = environment.get(args.token_env, "")
    return DiagnosticConfig(
        url=url,
        bearer_token=token,
        persona_id=_uuid7_from_env(environment, args.persona_id_env),
        branch_id=_uuid7_from_env(environment, args.branch_id_env),
        expected_transport=cast(TransportKind, args.expected_transport),
        canary_subject_id=_optional_uuid7_from_env(environment, args.canary_subject_id_env),
        timeout_seconds=args.timeout_seconds,
        write_canary=args.write_canary,
        write_confirmation=args.confirm_write_canary,
    )


def main(argv: Sequence[str] | None = None) -> None:
    """CLI entrypoint with stable JSON and no remote exception or payload rendering."""

    args = build_parser().parse_args(argv)
    try:
        config = _config_from_args(args, os.environ)
    except ConfigurationError as error:
        result = {
            "ok": False,
            "checks": [
                DiagnosticCheck("configuration", "fail", str(error)).as_dict(),
            ],
        }
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        raise SystemExit(2) from None

    report = asyncio.run(run_diagnostics(config))
    print(json.dumps(report.as_dict(), separators=(",", ":"), sort_keys=True))
    raise SystemExit(0 if report.ok else 1)


__all__ = [
    "ConfigurationError",
    "DiagnosticCheck",
    "DiagnosticConfig",
    "DiagnosticReport",
    "DiagnosticSession",
    "InitializedServer",
    "RecoveryReference",
    "build_parser",
    "connect_mcp",
    "main",
    "run_diagnostics",
]
