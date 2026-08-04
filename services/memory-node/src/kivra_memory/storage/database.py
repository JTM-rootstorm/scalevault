"""Async SQLAlchemy engine and fail-closed tenant transaction boundaries."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def _async_postgresql_url(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return database_url
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    raise ValueError("database URL must use PostgreSQL with psycopg")


class Database:
    """Own the connection pool and create transaction-scoped tenant sessions."""

    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        self.engine: AsyncEngine = create_async_engine(
            _async_postgresql_url(database_url),
            echo=echo,
            hide_parameters=True,
            pool_pre_ping=True,
        )
        self._sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def tenant_session(self, tenant_id: UUID) -> AsyncIterator[AsyncSession]:
        """Open a transaction whose RLS tenant setting disappears at commit."""

        async with self._sessions() as session, session.begin():
            await session.execute(
                text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            yield session

    async def dispose(self) -> None:
        """Close every pooled connection."""

        await self.engine.dispose()
