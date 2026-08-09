"""Operator-only one-shot CLI for the exact protected Genesis import."""

from __future__ import annotations

import argparse
import asyncio
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from kivra_memory.application.genesis_apply import (
    GenesisApplyError,
    GenesisApplyStatus,
    GenesisOperatorConfig,
    apply_genesis_import,
    genesis_import_status,
    prepare_genesis_import,
    stage_genesis_import,
    verify_genesis_import,
)
from kivra_memory.application.genesis_plan import plan_genesis_import
from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.errors import CanonicalJsonError
from kivra_memory.ingress.snapshot import LocalGitObjectReader
from kivra_memory.storage.database import Database
from pydantic import ValidationError
from sqlalchemy.engine import make_url

_DATABASE_URL_ENV = "KIVRA_MEMORY_DATABASE_URL"
_MAX_CONFIG_BYTES = 128 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate the exact digest-bound Genesis first import."
    )
    parser.add_argument("mode", choices=("plan", "stage", "apply", "verify"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    return parser


def _read_operator_config(path: Path) -> GenesisOperatorConfig:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise GenesisApplyError("unsafe_operator_config")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
    except GenesisApplyError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise GenesisApplyError("operator_config_unavailable") from None
    if not raw or len(raw) > _MAX_CONFIG_BYTES:
        raise GenesisApplyError("invalid_operator_config")
    try:
        document = parse_json_strict(raw)
    except CanonicalJsonError:
        raise GenesisApplyError("invalid_operator_config") from None
    if not isinstance(document, dict):
        raise GenesisApplyError("invalid_operator_config")
    try:
        return GenesisOperatorConfig.model_validate_json(raw)
    except ValidationError:
        raise GenesisApplyError("invalid_operator_config") from None


def _database_url(environment: Mapping[str, str]) -> str:
    value = environment.get(_DATABASE_URL_ENV)
    if not value:
        raise GenesisApplyError("database_url_unavailable")
    try:
        url = make_url(value)
    except (TypeError, ValueError):
        raise GenesisApplyError("invalid_database_url") from None
    if (
        url.drivername not in {"postgresql", "postgresql+psycopg"}
        or url.username != "kivra_memory_genesis_importer"
    ):
        raise GenesisApplyError("invalid_database_role")
    return value


def _safe_result(mode: str, status: GenesisApplyStatus | None) -> dict[str, object]:
    result: dict[str, object] = {"ok": True, "mode": mode}
    if status is not None:
        result["status"] = {
            "sources": status.source_count,
            "planned_records": status.planned_record_count,
            "terminal_records": status.terminal_record_count,
            "completed": status.completed,
            "canonical_mapping_sha256": status.canonical_mapping_sha256,
        }
    return result


async def _run(arguments: argparse.Namespace, environment: Mapping[str, str]) -> dict[str, object]:
    config = _read_operator_config(arguments.config)
    plan = plan_genesis_import(LocalGitObjectReader(arguments.repository))
    prepared = prepare_genesis_import(plan, config)
    if arguments.mode == "plan":
        return {
            "ok": True,
            "mode": "plan",
            "plan_sha256": plan.manifest.digest,
            "canonical_mapping_sha256": bytes(prepared.run.canonical_mapping_sha256).hex(),
        }

    database = Database(_database_url(environment))
    try:
        if arguments.mode == "stage":
            status = await stage_genesis_import(database, prepared, config)
        elif arguments.mode == "apply":
            status = await apply_genesis_import(database, prepared, config)
        elif arguments.mode == "verify":
            status = await verify_genesis_import(database, prepared, config)
        else:
            status = await genesis_import_status(database, prepared)
    finally:
        await database.dispose()
    return _safe_result(arguments.mode, status)


def main(
    argv: list[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = asyncio.run(_run(arguments, os.environ if environment is None else environment))
    except Exception:
        sys.stderr.buffer.write(
            canonical_json_bytes({"ok": False, "error": "genesis_import_failed"}) + b"\n"
        )
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
