"""Create or verify a content-free, zero-write Genesis import plan."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

from kivra_memory.application.genesis_plan import (
    GenesisPlanError,
    GenesisPlanReport,
    plan_genesis_import,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.ingress.snapshot import LocalGitObjectReader, SnapshotError

_OUTPUT_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    _OUTPUT_FLAGS |= os.O_NOFOLLOW


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan the exact pinned Genesis import without database access."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    plan = subcommands.add_parser("plan", help="write a new content-free plan report")
    plan.add_argument("--repository", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)

    verify = subcommands.add_parser(
        "verify-plan", help="recompute and verify an existing content-free plan report"
    )
    verify.add_argument("--repository", type=Path, required=True)
    verify.add_argument("--expected-manifest", type=Path, required=True)
    return parser


def _read_expected(path: Path) -> GenesisPlanReport:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise GenesisPlanError("invalid_expected_manifest")
        with os.fdopen(descriptor, "rb", closefd=True) as expected_file:
            descriptor = None
            raw = expected_file.read(64 * 1024 + 2)
    except GenesisPlanError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise GenesisPlanError("invalid_expected_manifest") from None
    return GenesisPlanReport.from_bytes(raw)


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, _OUTPUT_FLAGS, 0o600)
        created = True
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if path.stat().st_mode & 0o777 != 0o600:
            raise GenesisPlanError("unsafe_plan_output_mode")
    except GenesisPlanError:
        if created:
            path.unlink(missing_ok=True)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise GenesisPlanError("plan_output_failed") from None


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        reader = LocalGitObjectReader(arguments.repository)
        plan = plan_genesis_import(reader)
        if arguments.command == "plan":
            _write_exclusive(arguments.output, plan.report.canonical_bytes + b"\n")
            result = {"ok": True, "verified": False, "digest": plan.manifest.digest}
        elif arguments.command == "verify-plan":
            expected = _read_expected(arguments.expected_manifest)
            plan.verify_report(expected)
            result = {"ok": True, "verified": True, "digest": plan.manifest.digest}
        else:  # argparse constrains this, but retain a fail-closed boundary.
            raise GenesisPlanError("invalid_command")
    except (GenesisPlanError, SnapshotError, OSError, ValueError):
        sys.stderr.buffer.write(
            canonical_json_bytes({"ok": False, "error": "genesis_plan_failed"}) + b"\n"
        )
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
