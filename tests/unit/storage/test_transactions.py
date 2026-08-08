from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.storage.transactions import (
    SerializableTransactionError,
    run_serializable_transaction,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class PostgreSQLError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("content-bearing database detail")
        self.sqlstate = sqlstate


def database_error(sqlstate: str) -> DBAPIError:
    return DBAPIError("private statement", {}, PostgreSQLError(sqlstate), False)


class SessionFactory:
    def __init__(self) -> None:
        self.sessions: list[Mock] = []

    def __call__(self) -> Any:
        raw = Mock(spec=AsyncSession)
        raw.execute = AsyncMock()

        @asynccontextmanager
        async def begin() -> AsyncIterator[None]:
            yield

        raw.begin = Mock(side_effect=begin)
        self.sessions.append(raw)

        @asynccontextmanager
        async def context() -> AsyncIterator[AsyncSession]:
            yield cast(AsyncSession, raw)

        return context()


async def test_runner_uses_fresh_serializable_tenant_transaction_per_attempt() -> None:
    factory = SessionFactory()
    calls = 0

    async def operation(session: AsyncSession) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise database_error("40001")
        assert session is factory.sessions[1]
        return "committed"

    sleep = AsyncMock()
    result = await run_serializable_transaction(
        cast(async_sessionmaker[AsyncSession], factory),
        UUID(int=1),
        operation,
        sleep=sleep,
        jitter=lambda: 0.5,
        base_delay=0.1,
    )

    assert result == "committed"
    assert len(factory.sessions) == 2
    assert factory.sessions[0] is not factory.sessions[1]
    sleep.assert_awaited_once_with(0.05)
    for session in factory.sessions:
        assert str(session.execute.await_args_list[0].args[0]) == (
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
        )
        assert session.execute.await_args_list[1].args[1] == {"tenant_id": str(UUID(int=1))}


async def test_runner_exhaustion_raises_safe_error_without_database_detail() -> None:
    factory = SessionFactory()

    async def operation(_session: AsyncSession) -> None:
        raise database_error("40001")

    with pytest.raises(SerializableTransactionError) as raised:
        await run_serializable_transaction(
            cast(async_sessionmaker[AsyncSession], factory),
            UUID(int=1),
            operation,
            sleep=AsyncMock(),
            jitter=lambda: 0,
        )

    assert raised.value.code == "serialization_exhausted"
    assert raised.value.retryable is True
    assert raised.value.attempts == 4
    assert raised.value.retry_after_ms == 100
    assert "private statement" not in str(raised.value)
    assert raised.value.__cause__ is None


async def test_runner_default_full_jitter_ceilings_are_25_50_100_ms() -> None:
    factory = SessionFactory()

    async def operation(_session: AsyncSession) -> None:
        raise database_error("40001")

    sleep = AsyncMock()
    with pytest.raises(SerializableTransactionError):
        await run_serializable_transaction(
            cast(async_sessionmaker[AsyncSession], factory),
            UUID(int=1),
            operation,
            sleep=sleep,
            jitter=lambda: 1,
        )

    assert [call.args[0] for call in sleep.await_args_list] == [0.025, 0.05, 0.1]


@pytest.mark.parametrize("sqlstate", ["40P01", "23505", "08006"])
async def test_runner_does_not_retry_non_serialization_failures(sqlstate: str) -> None:
    factory = SessionFactory()
    expected = database_error(sqlstate)

    async def operation(_session: AsyncSession) -> None:
        raise expected

    with pytest.raises(DBAPIError) as raised:
        await run_serializable_transaction(
            cast(async_sessionmaker[AsyncSession], factory),
            UUID(int=1),
            operation,
            sleep=AsyncMock(),
        )

    assert raised.value is expected
    assert len(factory.sessions) == 1


async def test_runner_validates_retry_configuration() -> None:
    factory = cast(async_sessionmaker[AsyncSession], SessionFactory())

    async def operation(_session: AsyncSession) -> None:
        return None

    with pytest.raises(ValueError, match="max_attempts"):
        await run_serializable_transaction(factory, UUID(int=1), operation, max_attempts=0)
    with pytest.raises(ValueError, match="retry delays"):
        await run_serializable_transaction(
            factory, UUID(int=1), operation, base_delay=0.2, max_delay=0.1
        )
