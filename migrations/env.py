"""Alembic environment for the canonical PostgreSQL schema."""

from logging.config import fileConfig

from alembic import context
from kivra_memory.storage import metadata
from sqlalchemy.engine import Connection

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("offline migrations require an explicitly configured database URL")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    injected_connection = config.attributes.get("connection")
    if not isinstance(injected_connection, Connection):
        raise RuntimeError("online migrations require an injected SQLAlchemy connection")

    context.configure(
        connection=injected_connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
