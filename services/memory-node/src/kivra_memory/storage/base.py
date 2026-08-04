"""Shared SQLAlchemy metadata for the canonical PostgreSQL store."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import MetaData, Table
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

TENANT_OWNED_INFO_KEY = "scalevault_tenant_owned"


class Base(DeclarativeBase):
    """Declarative base used by every Memory Node relation."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


metadata = Base.metadata


def tenant_table_names(tables: Iterable[Table] | None = None) -> frozenset[str]:
    """Return relations that require forced row-level tenant isolation."""

    candidates = metadata.tables.values() if tables is None else tables
    return frozenset(
        table.name for table in candidates if table.info.get(TENANT_OWNED_INFO_KEY) is True
    )
