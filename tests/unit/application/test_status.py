from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.application.status import (
    IngressStatusQuery,
    IngressStatusResult,
    StatusEngine,
    StatusError,
    TransportStatusQuery,
    TransportStatusResult,
    _current_transport_statement,
)
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal
from pydantic import ValidationError

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def principal(*, scopes: frozenset[str], ingress_id: UUID | None = None) -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=uid(1),
        actor_id=uid(2),
        client_id=uid(3),
        transport_binding_id=uid(4),
        scopes=scopes,
        allowed_memory_scopes=frozenset(MemoryScope),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=4,
        ingress_id=ingress_id,
    )


def session_factory(*rows: object) -> tuple[Any, MagicMock]:
    session = MagicMock()
    session.execute = AsyncMock()
    results = [MagicMock()]
    for row in rows:
        result = MagicMock()
        result.one_or_none.return_value = row
        results.append(result)
    session.execute.side_effect = results
    session.begin.return_value.__aenter__ = AsyncMock(return_value=None)
    session.begin.return_value.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    return factory, session


def transport_row(*, installed: bool = True) -> MagicMock:
    row = MagicMock()
    row.transport_kind = "github_ingress" if installed else "direct_private"
    row.installation_id = uid(5) if installed else None
    row.health_state = "healthy" if installed else None
    row.last_seen_at = NOW if installed else None
    return row


def ingress_row(*, state: str = "accepted", error_code: str | None = None) -> MagicMock:
    row = MagicMock()
    row.ingress_id = uid(10)
    row.state = state
    row.result_event_id = uid(11) if state == "accepted" else None
    row.result_memory_id = uid(12) if state == "accepted" else None
    row.error_code = error_code
    row.discovered_at = NOW
    row.validated_at = NOW if state != "discovered" else None
    row.processed_at = NOW if state not in {"discovered", "validated"} else None
    return row


def test_status_queries_are_strict_and_transport_has_no_selector() -> None:
    assert (
        IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10)).contract_version
        == "mcp-read-v1"
    )
    assert TransportStatusQuery(contract_version="mcp-read-v1").model_dump() == {
        "contract_version": "mcp-read-v1"
    }
    with pytest.raises(ValidationError, match="Field required"):
        TransportStatusQuery.model_validate({})
    with pytest.raises(ValidationError, match="Extra inputs"):
        TransportStatusQuery.model_validate(
            {"contract_version": "mcp-read-v1", "installation_id": str(uid(5))}
        )


def test_transport_statement_selects_no_sensitive_columns() -> None:
    statement = _current_transport_statement(
        principal(scopes=frozenset({"memory.status.transport"})), NOW
    )
    selected = {column.key for column in statement.selected_columns}

    assert selected == {"transport_kind", "installation_id", "health_state", "last_seen_at"}
    assert selected.isdisjoint(
        {
            "relay_hostname",
            "route_key",
            "node_certificate_sha256",
            "capability_profile",
            "authorized_operations",
            "disclosure_boundary",
        }
    )


async def test_proposal_status_requires_exact_principal_ingress_without_querying() -> None:
    factory, session = session_factory()
    engine = StatusEngine(cast(Any, factory), clock=lambda: NOW)

    response = await engine.ingress_status(
        principal(scopes=frozenset({"memory:propose"}), ingress_id=uid(20)),
        IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10)),
    )

    assert isinstance(response, StatusError)
    assert response.error.code == "not_found"
    session.execute.assert_not_awaited()


async def test_proposal_status_projects_only_allowlisted_fields() -> None:
    factory, session = session_factory(transport_row(), ingress_row())
    engine = StatusEngine(cast(Any, factory), clock=lambda: NOW)

    response = await engine.ingress_status(
        principal(scopes=frozenset({"memory:propose"}), ingress_id=uid(10)),
        IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10)),
    )

    assert isinstance(response, IngressStatusResult)
    assert response.result.result_event_id == uid(11)
    assert response.result.result_memory_id == uid(12)
    assert set(response.model_dump()) == {
        "ok",
        "contract_version",
        "tool",
        "result",
        "warnings",
        "metadata",
    }
    ingress_statement = session.execute.await_args_list[2].args[0]
    assert {column.key for column in ingress_statement.selected_columns} == {
        "ingress_id",
        "state",
        "result_event_id",
        "result_memory_id",
        "error_code",
        "discovered_at",
        "validated_at",
        "processed_at",
    }


async def test_internal_ingress_error_is_reduced_to_state_allowlist() -> None:
    factory, _ = session_factory(
        transport_row(), ingress_row(state="quarantined", error_code="PRIVATE_HOST_FAILURE")
    )
    engine = StatusEngine(cast(Any, factory), clock=lambda: NOW)

    response = await engine.ingress_status(
        principal(scopes=frozenset({"memory.status.ingress"})),
        IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10)),
    )

    assert isinstance(response, IngressStatusResult)
    assert response.result.error_code == "quarantined"
    assert "PRIVATE_HOST_FAILURE" not in response.model_dump_json()


async def test_missing_and_inaccessible_ingress_have_identical_response() -> None:
    first_factory, _ = session_factory(transport_row(), None)
    second_factory, _ = session_factory(transport_row(), None)
    context = principal(scopes=frozenset({"memory.status.ingress"}))

    missing = await StatusEngine(cast(Any, first_factory), clock=lambda: NOW).ingress_status(
        context, IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10))
    )
    inaccessible = await StatusEngine(cast(Any, second_factory), clock=lambda: NOW).ingress_status(
        context, IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=uid(10))
    )

    assert missing == inaccessible
    assert isinstance(missing, StatusError)
    assert missing.error.code == "not_found"


async def test_transport_status_is_coarse_and_selector_free() -> None:
    factory, _ = session_factory(transport_row())
    engine = StatusEngine(cast(Any, factory), clock=lambda: NOW)

    response = await engine.transport_status(
        principal(scopes=frozenset({"memory.status.transport"})),
        TransportStatusQuery(contract_version="mcp-read-v1"),
    )

    assert isinstance(response, TransportStatusResult)
    assert response.model_dump() == {
        "ok": True,
        "contract_version": "mcp-read-v1",
        "tool": "memory_transport_status",
        "result": {
            "transport_kind": "github_ingress",
            "binding_state": "active",
            "installation_state": "active",
            "health_state": "healthy",
            "freshness": "recent",
        },
        "warnings": (),
        "metadata": {"pagination": None, "retrieval": None, "budget": None},
    }


@pytest.mark.parametrize(
    "scope", [frozenset(), frozenset({"memory:write"}), frozenset({"memory:read"})]
)
async def test_transport_status_requires_read_scope(scope: frozenset[str]) -> None:
    factory, session = session_factory()
    response = await StatusEngine(cast(Any, factory), clock=lambda: NOW).transport_status(
        principal(scopes=scope), TransportStatusQuery(contract_version="mcp-read-v1")
    )

    assert isinstance(response, StatusError)
    assert response.error.code == "forbidden"
    session.execute.assert_not_awaited()
