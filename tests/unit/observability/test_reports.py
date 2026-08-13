from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from kivra_memory.observability.reports import (
    FORBIDDEN_REPORT_COLUMNS,
    MAX_REPORT_ROWS,
    REPORT_QUERIES,
    OperatorReportRepository,
)

TENANT_ID = UUID("01970000-0000-7000-8000-000000000001")


class FakeMappings:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def all(self) -> list[dict[str, object]]:
        return self._rows


class FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> FakeMappings:
        return FakeMappings(self._rows)


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def execute(self, statement: object, parameters: dict[str, object]) -> FakeResult:
        query = str(statement)
        self.calls.append((query, parameters))
        if "AS check_name" in query:
            return FakeResult([{"check_name": "memory_last_event", "state": "ok"}])
        return FakeResult([])


class FakeDatabase:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.tenant_ids: list[UUID] = []

    @asynccontextmanager
    async def tenant_session(self, tenant_id: UUID) -> AsyncIterator[Any]:
        self.tenant_ids.append(tenant_id)
        yield self.session


def test_report_queries_have_explicit_payload_silent_column_lists() -> None:
    assert len(REPORT_QUERIES) == len({query.name for query in REPORT_QUERIES}) == 9
    for query in REPORT_QUERIES:
        statement = str(query.statement).lower()
        assert "select *" not in statement
        identifiers = set(re.findall(r"[a-z][a-z0-9_]*", statement))
        assert identifiers.isdisjoint(FORBIDDEN_REPORT_COLUMNS), query.name
        assert query.tenant_qualifiers
        for qualifier in query.tenant_qualifiers:
            assert f"{qualifier} = :tenant_id" in statement, query.name


@pytest.mark.asyncio
async def test_report_is_tenant_scoped_bounded_and_content_free() -> None:
    session = FakeSession()
    report = await OperatorReportRepository(FakeDatabase(session)).collect(
        TENANT_ID,
        now=datetime(2026, 8, 12, tzinfo=UTC),
    )

    rendered = report.as_dict()
    assert rendered["tenant_id"] == str(TENANT_ID)
    assert rendered["external_status"] == {
        "backup": "status_artifact_required",
        "recovery": "status_artifact_required",
    }
    assert len(session.calls) == len(REPORT_QUERIES)
    assert all(parameters["limit"] == MAX_REPORT_ROWS for _, parameters in session.calls)
    assert all(parameters["tenant_id"] == TENANT_ID for _, parameters in session.calls)


@pytest.mark.asyncio
async def test_report_rejects_unbounded_windows() -> None:
    with pytest.raises(ValueError, match="invalid_report_window"):
        await OperatorReportRepository(FakeDatabase(FakeSession())).collect(
            TENANT_ID, window_days=91
        )
