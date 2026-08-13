"""Bounded canary-only scans of protected operational captures.

This is deliberately separate from the public-artifact leakage scanner.  An
operator capture may legitimately contain configuration field names and
credential-shaped, redacted text; this gate answers only whether one of the
supplied synthetic canaries (or a common encoding of one) crossed a process
boundary.  Output is restricted to fixed result codes and bounded counts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from kivra_memory.security.credential_files import read_protected_file

MAXIMUM_INPUTS: Final = 64
MAXIMUM_INPUT_BYTES: Final = 8 * 1024 * 1024
MAXIMUM_TOTAL_BYTES: Final = 64 * 1024 * 1024
MAXIMUM_CANARIES: Final = 64
MINIMUM_CANARY_BYTES: Final = 8
MAXIMUM_CANARY_BYTES: Final = 4096


@dataclass(frozen=True, slots=True)
class OperationalCanaryResult:
    """A content-free result suitable for the protected acceptance record."""

    ok: bool
    result: str
    inputs_scanned: int
    bytes_scanned: int
    matches: int

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "result": self.result,
            "counts": {
                "bytes_scanned": self.bytes_scanned,
                "inputs_scanned": self.inputs_scanned,
                "matches": self.matches,
            },
        }


def _read_root_owned_lines(path: Path, *, maximum_bytes: int) -> tuple[bytes, ...]:
    raw = read_protected_file(
        path,
        minimum_bytes=1,
        maximum_bytes=maximum_bytes,
        required_owner_uid=0,
        allowed_modes=frozenset({0o600}),
    )
    values = tuple(raw.splitlines())
    if not values or any(not value for value in values):
        raise ValueError
    return values


def _read_canaries(path: Path) -> tuple[bytes, ...]:
    values = _read_root_owned_lines(
        path, maximum_bytes=MAXIMUM_CANARIES * (MAXIMUM_CANARY_BYTES + 1)
    )
    if (
        len(values) > MAXIMUM_CANARIES
        or len(set(values)) != len(values)
        or any(not MINIMUM_CANARY_BYTES <= len(value) <= MAXIMUM_CANARY_BYTES for value in values)
    ):
        raise ValueError
    return values


def _read_input_paths(path: Path) -> tuple[Path, ...]:
    encoded = _read_root_owned_lines(path, maximum_bytes=MAXIMUM_INPUTS * 4097)
    if len(encoded) > MAXIMUM_INPUTS or len(set(encoded)) != len(encoded):
        raise ValueError
    try:
        values = tuple(Path(value.decode("utf-8")) for value in encoded)
    except UnicodeDecodeError:
        raise ValueError from None
    if any(
        not value.is_absolute()
        or value == Path("/")
        or any(part in {"", ".", ".."} for part in value.parts[1:])
        for value in values
    ):
        raise ValueError
    return values


def _encoded_forms(canary: bytes) -> frozenset[bytes]:
    forms = {
        canary,
        base64.b64encode(canary),
        base64.b64encode(canary).rstrip(b"="),
        base64.urlsafe_b64encode(canary),
        base64.urlsafe_b64encode(canary).rstrip(b"="),
        canary.hex().encode("ascii"),
        canary.hex().upper().encode("ascii"),
        hashlib.sha256(canary).hexdigest().encode("ascii"),
        hashlib.sha256(canary).hexdigest().upper().encode("ascii"),
    }
    try:
        text = canary.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        forms.add(unicodedata.normalize("NFC", text).encode("utf-8"))
        forms.add(unicodedata.normalize("NFKC", text).encode("utf-8"))
    return frozenset(value for value in forms if value)


def scan_operational_captures(
    paths: Sequence[Path], canaries: Sequence[bytes]
) -> OperationalCanaryResult:
    """Scan exact protected files, counting a matching file at most once."""

    if (
        not paths
        or len(paths) > MAXIMUM_INPUTS
        or len(set(paths)) != len(paths)
        or not canaries
        or len(canaries) > MAXIMUM_CANARIES
        or len(set(canaries)) != len(canaries)
        or any(
            not isinstance(canary, bytes)
            or not MINIMUM_CANARY_BYTES <= len(canary) <= MAXIMUM_CANARY_BYTES
            for canary in canaries
        )
    ):
        return OperationalCanaryResult(False, "incomplete", 0, 0, 0)
    forms = frozenset(form for canary in canaries for form in _encoded_forms(canary))
    inputs_scanned = 0
    bytes_scanned = 0
    matches = 0
    try:
        for path in paths:
            content = read_protected_file(
                path,
                minimum_bytes=0,
                maximum_bytes=MAXIMUM_INPUT_BYTES,
                required_owner_uid=0,
                allowed_modes=frozenset({0o400, 0o600}),
            )
            if bytes_scanned + len(content) > MAXIMUM_TOTAL_BYTES:
                raise ValueError
            inputs_scanned += 1
            bytes_scanned += len(content)
            matched = any(form in content for form in forms)
            if not matched:
                try:
                    normalized = unicodedata.normalize("NFKC", content.decode("utf-8")).encode(
                        "utf-8"
                    )
                except UnicodeDecodeError:
                    normalized = b""
                matched = any(form in normalized for form in forms)
            matches += int(matched)
    except Exception:
        return OperationalCanaryResult(False, "incomplete", inputs_scanned, bytes_scanned, matches)
    return OperationalCanaryResult(
        matches == 0,
        "clean" if matches == 0 else "match",
        inputs_scanned,
        bytes_scanned,
        matches,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan protected operational captures for synthetic canaries"
    )
    parser.add_argument("--artifact-list", required=True, type=Path)
    parser.add_argument("--canary-file", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        paths = _read_input_paths(arguments.artifact_list)
        canaries = _read_canaries(arguments.canary_file)
        result = scan_operational_captures(paths, canaries)
    except Exception:
        result = OperationalCanaryResult(False, "incomplete", 0, 0, 0)
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["OperationalCanaryResult", "main", "scan_operational_captures"]
