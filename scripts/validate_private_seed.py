"""Validate and render a content-free plan for an ignored private seed bundle."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.seeding.private_seed import (
    PrivateSeedError,
    load_private_seed_bundle,
    plan_private_seed,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _assert_safe_source_location(path: Path) -> None:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(_REPOSITORY_ROOT)
    except ValueError:
        return
    try:
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", str(resolved)],
            cwd=_REPOSITORY_ROOT,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        raise PrivateSeedError("seed_ignore_check_unavailable") from None
    if result.returncode != 0:
        raise PrivateSeedError("repository_seed_path_not_ignored")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a private seed and print a content-free zero-write plan."
    )
    parser.add_argument("bundle", type=Path)
    return parser


def main() -> None:
    supplied_path = _parser().parse_args().bundle
    path = supplied_path if supplied_path.is_absolute() else Path.cwd() / supplied_path
    try:
        _assert_safe_source_location(path)
        plan = plan_private_seed(load_private_seed_bundle(path))
    except PrivateSeedError as error:
        sys.stderr.buffer.write(canonical_json_bytes({"ok": False, "error": str(error)}) + b"\n")
        raise SystemExit(2) from None
    sys.stdout.buffer.write(
        canonical_json_bytes({"ok": True, "plan": plan.model_dump(mode="python")}) + b"\n"
    )


if __name__ == "__main__":
    main()
