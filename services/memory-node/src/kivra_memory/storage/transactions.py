"""Bounded SERIALIZABLE transaction execution for tenant commands."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

type TransactionOperation[T] = Callable[[AsyncSession], Awaitable[T]]
Sleep = Callable[[float], Awaitable[None]]
Jitter = Callable[[], float]


class SerializableTransactionError(RuntimeError):
    """A safe error raised after bounded serialization retries are exhausted."""

    code = "serialization_exhausted"
    retryable = True

    def __init__(self, attempts: int, *, retry_after_ms: int) -> None:
        super().__init__("transaction could not be completed after bounded retries")
        self.attempts = attempts
        self.retry_after_ms = retry_after_ms

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, attempts={self.attempts}, "
            f"retry_after_ms={self.retry_after_ms})"
        )


def database_sqlstate(error: DBAPIError) -> str | None:
    """Extract a PostgreSQL SQLSTATE without rendering database diagnostics."""

    original = error.orig
    value = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    return value if isinstance(value, str) else None


async def run_serializable_transaction[T](
    session_factory: async_sessionmaker[AsyncSession],
    tenant_id: UUID,
    operation: TransactionOperation[T],
    *,
    max_attempts: int = 4,
    base_delay: float = 0.025,
    max_delay: float = 0.1,
    sleep: Sleep = asyncio.sleep,
    jitter: Jitter = random.random,
) -> T:
    """Run a tenant command in a fresh SERIALIZABLE transaction per attempt.

    PostgreSQL serialization failures (SQLSTATE ``40001``) are retried. Deadlocks
    (``40P01``) and every other failure propagate unchanged; deterministic advisory
    lock ordering is used to prevent command-level deadlocks.
    """

    if max_attempts < 1:
        raise ValueError("max_attempts must be at least one")
    if base_delay < 0 or max_delay < 0 or max_delay < base_delay:
        raise ValueError("retry delays must satisfy 0 <= base_delay <= max_delay")

    for attempt in range(1, max_attempts + 1):
        try:
            async with session_factory() as session, session.begin():
                await session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
                await session.execute(
                    text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
                    {"tenant_id": str(tenant_id)},
                )
                return await operation(session)
        except DBAPIError as error:
            if database_sqlstate(error) != "40001":
                raise
            if attempt == max_attempts:
                raise SerializableTransactionError(
                    attempt, retry_after_ms=round(max_delay * 1000)
                ) from None

            jitter_fraction = jitter()
            if not 0 <= jitter_fraction <= 1:
                raise ValueError("jitter must return a value between zero and one") from None
            ceiling = min(max_delay, base_delay * (2 ** (attempt - 1)))
            await sleep(ceiling * jitter_fraction)

    raise AssertionError("bounded retry loop did not return or raise")
