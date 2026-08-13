"""Systemd-only adapter for one protected operator-report instance."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final
from uuid import UUID

from kivra_memory.domain.identifiers import is_uuid7
from kivra_memory.observability import report_main
from kivra_memory.security.credential_files import read_systemd_credential_text

TENANT_CREDENTIAL_NAME: Final = "tenant-id"
REPORT_DIRECTORY: Final = Path("/var/lib/kivra-memory/operator-reports")
_REPORT_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


def _report_id(value: str) -> str:
    if _REPORT_ID.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("invalid report id")
    return value


def _tenant_id() -> UUID:
    try:
        value = read_systemd_credential_text(
            TENANT_CREDENTIAL_NAME,
            minimum_bytes=36,
            maximum_bytes=36,
        )
        tenant_id = UUID(value)
        if str(tenant_id) != value or not is_uuid7(tenant_id):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("operator_report_tenant_credential_invalid") from None
    return tenant_id


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kivra-memory-operator-report-run",
        description="Run one systemd-credential-bound operator report.",
    )
    parser.add_argument("--report-id", type=_report_id, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _parser().parse_args(argv)
    try:
        tenant_id = _tenant_id()
    except ValueError:
        print("ScaleVault operator report failed", file=sys.stderr)
        raise SystemExit(1) from None
    report_main.main(
        [
            "--tenant-id",
            str(tenant_id),
            "--output",
            str(REPORT_DIRECTORY / f"{arguments.report_id}.json"),
        ]
    )


__all__ = ["REPORT_DIRECTORY", "TENANT_CREDENTIAL_NAME", "main"]
