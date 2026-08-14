"""Read-only validation of the fixed M10 operational retention-cap manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.security.credential_files import read_protected_file

SURFACE_MAXIMUM_DAYS: Final = {
    "application_service_journals": 30,
    "local_alert_state": 30,
    "npm_container_logs": 30,
    "postgresql_logs": 30,
    "prometheus_history": 30,
    "protected_operator_recovery_acceptance_reports": 400,
    "tunnel_json": 30,
}
MAXIMUM_MANIFEST_BYTES: Final = 8192


def validate_retention_cap_manifest(value: object) -> dict[str, object]:
    """Validate only fixed surfaces, bounded ages, and positive local byte caps."""

    if not isinstance(value, dict) or set(value) != {"surfaces", "version"}:
        raise ValueError("retention_cap_manifest_invalid")
    if value["version"] != 1 or not isinstance(value["surfaces"], dict):
        raise ValueError("retention_cap_manifest_invalid")
    surfaces = value["surfaces"]
    if set(surfaces) != set(SURFACE_MAXIMUM_DAYS):
        raise ValueError("retention_cap_manifest_invalid")
    for name, maximum_days in SURFACE_MAXIMUM_DAYS.items():
        selected = surfaces[name]
        if not isinstance(selected, dict) or set(selected) != {
            "maximum_age_days",
            "maximum_bytes",
        }:
            raise ValueError("retention_cap_manifest_invalid")
        days = selected["maximum_age_days"]
        maximum_bytes = selected["maximum_bytes"]
        if (
            isinstance(days, bool)
            or not isinstance(days, int)
            or not 1 <= days <= maximum_days
            or isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or not 1 <= maximum_bytes <= (1 << 53) - 1
        ):
            raise ValueError("retention_cap_manifest_invalid")
    normalized = canonical_json_bytes(value)
    return {
        "ok": True,
        "result": "retention_cap_manifest_valid",
        "config_sha256": hashlib.sha256(normalized).hexdigest(),
        "counts": {"surfaces": len(SURFACE_MAXIMUM_DAYS)},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a protected ScaleVault retention-cap manifest"
    )
    parser.add_argument("--manifest", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        raw = read_protected_file(
            arguments.manifest,
            minimum_bytes=1,
            maximum_bytes=MAXIMUM_MANIFEST_BYTES,
            required_owner_uid=0,
            allowed_modes=frozenset({0o600}),
        )
        parsed = parse_json_strict(raw)
        result = validate_retention_cap_manifest(parsed)
    except Exception:
        result = {
            "ok": False,
            "result": "retention_cap_manifest_invalid",
            "config_sha256": "0" * 64,
            "counts": {"surfaces": 0},
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["SURFACE_MAXIMUM_DAYS", "main", "validate_retention_cap_manifest"]
