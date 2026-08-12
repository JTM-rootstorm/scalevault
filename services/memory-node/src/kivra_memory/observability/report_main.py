"""Root-local CLI for tenant-scoped metadata-only operator reports."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from collections.abc import Mapping, Sequence
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.observability.reports import OperatorReportRepository
from kivra_memory.storage.database import Database

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kivra-memory-operator-report",
        description="Render a root-local, tenant-scoped metadata report.",
    )
    parser.add_argument("--tenant-id", type=UUID, required=True)
    parser.add_argument("--window-days", type=int, choices=range(1, 91), default=30)
    parser.add_argument("--database-url-env", default="SCALEVAULT_DATABASE_URL")
    return parser


async def _run(arguments: argparse.Namespace, environment: Mapping[str, str]) -> bytes:
    env_name = arguments.database_url_env
    if not isinstance(env_name, str) or _ENV_NAME.fullmatch(env_name) is None:
        raise ValueError("invalid_database_url_environment")
    database_url = environment.get(env_name)
    if not database_url:
        raise ValueError("database_url_unavailable")
    database = Database(database_url)
    try:
        report = await OperatorReportRepository(database).collect(
            arguments.tenant_id,
            window_days=arguments.window_days,
        )
        return canonical_json_bytes(report.as_dict())
    finally:
        await database.dispose()


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _parser().parse_args(argv)
    if os.geteuid() != 0:
        print("ScaleVault operator report requires root", file=sys.stderr)
        raise SystemExit(77)
    try:
        rendered = asyncio.run(_run(arguments, os.environ))
    except Exception:
        print("ScaleVault operator report failed", file=sys.stderr)
        raise SystemExit(1) from None
    sys.stdout.buffer.write(rendered + b"\n")


__all__ = ["main"]
