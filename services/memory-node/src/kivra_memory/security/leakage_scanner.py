"""Bounded, content-safe scanning for already-materialized public candidates.

This module deliberately does not select, transform, sign, or publish artifacts.
Its report is restricted to a digest and fixed-vocabulary counts so a failed scan
cannot become another channel for the private material it detected.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import unicodedata
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from kivra_memory.domain.canonical_json import parse_json_strict


class LeakageReason(StrEnum):
    """The complete, stable scanner finding vocabulary."""

    CANARY_RAW = "canary_raw"
    CANARY_NORMALIZED = "canary_normalized"
    CANARY_BASE64 = "canary_base64"
    CANARY_HEX = "canary_hex"
    CANARY_DIGEST = "canary_digest"
    FORBIDDEN_FIELD = "forbidden_field"
    CREDENTIAL_GRAMMAR = "credential_grammar"
    PATH_INVALID = "path_invalid"
    DUPLICATE_PATH = "duplicate_path"
    FILE_TYPE_FORBIDDEN = "file_type_forbidden"
    FILE_TOO_LARGE = "file_too_large"
    TREE_TOO_LARGE = "tree_too_large"
    MALFORMED_ENCODING = "malformed_encoding"
    LINK_OR_SPECIAL_FILE = "link_or_special_file"
    CANARY_INPUT_INVALID = "canary_input_invalid"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class CandidateFile:
    """One candidate path, immutable bytes, and its materialization provenance."""

    path: str
    content: bytes
    source_kind: Literal["regular", "link", "special"] = "regular"


@dataclass(frozen=True, slots=True)
class LeakageScannerPolicy:
    """Fixed resource and input bounds for an offline scan."""

    maximum_files: int = 1_024
    maximum_directories: int = 64
    maximum_file_bytes: int = 8_388_608
    maximum_tree_bytes: int = 67_108_864
    maximum_path_bytes: int = 240
    maximum_path_depth: int = 16
    maximum_canaries: int = 64
    minimum_canary_bytes: int = 8
    maximum_canary_bytes: int = 4_096
    allowed_suffixes: frozenset[str] = frozenset({".json", ".jsonl", ".md", ".txt"})


DEFAULT_LEAKAGE_SCANNER_POLICY: Final = LeakageScannerPolicy()


@dataclass(frozen=True, slots=True)
class LeakageScanResult:
    """A content-free scanner result safe for operator reports."""

    ok: bool
    artifact_sha256: str
    counts: Mapping[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "artifact_sha256": self.artifact_sha256,
            "counts": dict(self.counts),
        }


_FORBIDDEN_FIELDS: Final = frozenset(
    {
        "aad_hash",
        "aad_sha256",
        "access_token",
        "api_key",
        "archive_manifest_digest",
        "archive_previous_digest",
        "authorization",
        "bearer_token",
        "ciphertext",
        "client_secret",
        "content_key_id",
        "content_key_reference",
        "database_url",
        "deployment_id",
        "deployment_identifier",
        "evidence",
        "evidence_key",
        "evidence_references",
        "evidence_summary",
        "evidence_text",
        "git_commit_sha",
        "installation_id",
        "key_reference",
        "manifest_linkage",
        "nonce",
        "password",
        "postgres_timeline_id",
        "private_key",
        "private_manifest_linkage",
        "private_source_reference",
        "previous_manifest_sha256",
        "provider_key_reference",
        "source_archive_path",
        "source_high_water_sequence",
        "source_ref",
        "source_reference",
        "token_pepper",
    }
)
_TEXT_FIELD = re.compile(rb"(?im)^[ \t]*[\"']?([a-zA-Z][a-zA-Z0-9_-]{0,63})[\"']?[ \t]*[:=]")
_CREDENTIAL_PATTERNS: Final = (
    re.compile(rb"(?i)\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{32,}"),
    re.compile(rb"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(rb"(?i)\bpostgres(?:ql)?://[^\s/:@]+:[^\s/@]+@"),
    re.compile(
        rb"(?i)[\"']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
        rb"[\"']?\s*[:=]\s*[\"'][^\s\"']{8,}[\"']"
    ),
)
_INCOMPLETE_ARTIFACT_SHA256: Final = hashlib.sha256(
    b"scalevault-incomplete-public-candidate-v1"
).hexdigest()


def _artifact_digest(files: Sequence[CandidateFile]) -> str:
    digest = hashlib.sha256()
    digest.update(b"scalevault-public-candidate-v1\0")
    for candidate in sorted(files, key=lambda item: item.path.encode("utf-8", "surrogatepass")):
        path = candidate.path.encode("utf-8", "surrogatepass")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(candidate.content).to_bytes(8, "big"))
        digest.update(candidate.content)
    return digest.hexdigest()


def _safe_result(
    files: Sequence[CandidateFile],
    counts: Counter[LeakageReason],
    *,
    artifact_complete: bool = True,
) -> LeakageScanResult:
    rendered = {reason.value: counts[reason] for reason in LeakageReason if counts[reason] > 0}
    return LeakageScanResult(
        ok=not rendered,
        artifact_sha256=_artifact_digest(files)
        if artifact_complete
        else _INCOMPLETE_ARTIFACT_SHA256,
        counts=rendered,
    )


def _valid_relative_path(path: str, policy: LeakageScannerPolicy) -> bool:
    if not path or "\\" in path or "\x00" in path or unicodedata.normalize("NFC", path) != path:
        return False
    parsed = PurePosixPath(path)
    return (
        path == parsed.as_posix()
        and len(path.encode("utf-8")) <= policy.maximum_path_bytes
        and len(parsed.parts) <= policy.maximum_path_depth
        and not parsed.is_absolute()
        and all(part not in {"", ".", ".."} for part in parsed.parts)
    )


def _canary_forms(
    canary: bytes,
) -> tuple[bytes, frozenset[bytes], frozenset[bytes], frozenset[bytes]]:
    base64_forms = {
        base64.b64encode(canary),
        base64.urlsafe_b64encode(canary),
        base64.b64encode(canary).rstrip(b"="),
        base64.urlsafe_b64encode(canary).rstrip(b"="),
    }
    hex_forms = {canary.hex().encode("ascii"), canary.hex().upper().encode("ascii")}
    digest_forms: set[bytes] = set()
    value = hashlib.sha256(canary)
    digest_forms.update(
        {
            value.hexdigest().encode("ascii"),
            value.hexdigest().upper().encode("ascii"),
            base64.b64encode(value.digest()),
            base64.urlsafe_b64encode(value.digest()).rstrip(b"="),
        }
    )
    return canary, frozenset(base64_forms), frozenset(hex_forms), frozenset(digest_forms)


def _structured_fields(document: bytes, suffix: str) -> set[str]:
    fields = {
        match.group(1).decode("ascii").lower().replace("-", "_")
        for match in _TEXT_FIELD.finditer(document)
    }
    if suffix not in {".json", ".jsonl"}:
        return fields
    values: list[object]
    if suffix == ".json":
        values = [parse_json_strict(document)]
    else:
        lines = [line for line in document.splitlines() if line.strip()]
        values = [parse_json_strict(line) for line in lines]

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                fields.add(key.lower().replace("-", "_"))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for value in values:
        visit(value)
    return fields


def scan_candidate_files(
    files: Iterable[CandidateFile],
    *,
    canaries: Iterable[str | bytes],
    policy: LeakageScannerPolicy = DEFAULT_LEAKAGE_SCANNER_POLICY,
) -> LeakageScanResult:
    """Scan a bounded materialized file map without exposing matched content."""

    materialized: list[CandidateFile] = []
    counts: Counter[LeakageReason] = Counter()
    artifact_complete = True
    try:
        materialized_bytes = 0
        for candidate in files:
            materialized.append(candidate)
            if len(materialized) > policy.maximum_files:
                counts[LeakageReason.TREE_TOO_LARGE] += 1
                artifact_complete = False
                break
            if isinstance(candidate, CandidateFile) and isinstance(candidate.content, bytes):
                materialized_bytes += len(candidate.content)
                if materialized_bytes > policy.maximum_tree_bytes:
                    counts[LeakageReason.TREE_TOO_LARGE] += 1
                    artifact_complete = False
                    break
        supplied_canaries: list[str | bytes] = []
        canary_overflow = False
        for canary in canaries:
            supplied_canaries.append(canary)
            if len(supplied_canaries) > policy.maximum_canaries:
                counts[LeakageReason.CANARY_INPUT_INVALID] += 1
                supplied_canaries = []
                canary_overflow = True
                break
        if not supplied_canaries and not canary_overflow:
            counts[LeakageReason.CANARY_INPUT_INVALID] += 1

        canary_bytes: list[bytes] = []
        for canary in supplied_canaries:
            encoded = canary.encode("utf-8") if isinstance(canary, str) else canary
            if not policy.minimum_canary_bytes <= len(encoded) <= policy.maximum_canary_bytes:
                counts[LeakageReason.CANARY_INPUT_INVALID] += 1
                continue
            canary_bytes.append(encoded)
        if len(set(canary_bytes)) != len(canary_bytes):
            counts[LeakageReason.CANARY_INPUT_INVALID] += 1
        forms = [_canary_forms(canary) for canary in set(canary_bytes)]

        total_bytes = 0
        normalized_paths: set[str] = set()
        for candidate in materialized:
            if not isinstance(candidate, CandidateFile) or not isinstance(candidate.content, bytes):
                counts[LeakageReason.INTERNAL_ERROR] += 1
                continue
            if candidate.source_kind != "regular":
                counts[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
            path = candidate.path
            normalized_path = unicodedata.normalize("NFC", path)
            if not _valid_relative_path(path, policy):
                counts[LeakageReason.PATH_INVALID] += 1
            if normalized_path in normalized_paths:
                counts[LeakageReason.DUPLICATE_PATH] += 1
            normalized_paths.add(normalized_path)
            suffix = PurePosixPath(path).suffix
            if suffix not in policy.allowed_suffixes:
                counts[LeakageReason.FILE_TYPE_FORBIDDEN] += 1
            if len(candidate.content) > policy.maximum_file_bytes:
                counts[LeakageReason.FILE_TOO_LARGE] += 1
            total_bytes += len(candidate.content)

            try:
                text = candidate.content.decode("utf-8")
            except UnicodeDecodeError:
                counts[LeakageReason.MALFORMED_ENCODING] += 1
                text = ""
            if "\x00" in text or any(
                ord(character) < 0x20 and character not in "\n\r\t" for character in text
            ):
                counts[LeakageReason.MALFORMED_ENCODING] += 1

            per_file: set[LeakageReason] = set()
            normalized_text = unicodedata.normalize("NFKC", text)
            for raw, base64_forms, hex_forms, digest_forms in forms:
                if raw in candidate.content:
                    per_file.add(LeakageReason.CANARY_RAW)
                try:
                    raw_text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    raw_text = ""
                if (
                    raw_text
                    and unicodedata.normalize("NFKC", raw_text) in normalized_text
                    and raw not in candidate.content
                ):
                    per_file.add(LeakageReason.CANARY_NORMALIZED)
                if any(value and value in candidate.content for value in base64_forms):
                    per_file.add(LeakageReason.CANARY_BASE64)
                if any(value and value in candidate.content for value in hex_forms):
                    per_file.add(LeakageReason.CANARY_HEX)
                if any(value and value in candidate.content for value in digest_forms):
                    per_file.add(LeakageReason.CANARY_DIGEST)
            for reason in per_file:
                counts[reason] += 1

            if any(pattern.search(candidate.content) for pattern in _CREDENTIAL_PATTERNS):
                counts[LeakageReason.CREDENTIAL_GRAMMAR] += 1
            if suffix in policy.allowed_suffixes and text:
                try:
                    fields = _structured_fields(candidate.content, suffix)
                except Exception:
                    counts[LeakageReason.MALFORMED_ENCODING] += 1
                else:
                    if fields & _FORBIDDEN_FIELDS:
                        counts[LeakageReason.FORBIDDEN_FIELD] += 1

        if total_bytes > policy.maximum_tree_bytes:
            counts[LeakageReason.TREE_TOO_LARGE] += 1
        return _safe_result(materialized, counts, artifact_complete=artifact_complete)
    except Exception:
        counts[LeakageReason.INTERNAL_ERROR] += 1
        try:
            return _safe_result(materialized, counts, artifact_complete=False)
        except Exception:
            return LeakageScanResult(
                ok=False,
                artifact_sha256=_INCOMPLETE_ARTIFACT_SHA256,
                counts={LeakageReason.INTERNAL_ERROR.value: 1},
            )


def scan_candidate_tree(
    root: Path,
    *,
    canaries: Iterable[str | bytes],
    policy: LeakageScannerPolicy = DEFAULT_LEAKAGE_SCANNER_POLICY,
) -> LeakageScanResult:
    """Materialize a directory without following links, then run the pure scanner."""

    candidates: list[CandidateFile] = []
    structural: Counter[LeakageReason] = Counter()
    selected = Path(root)
    root_descriptor = -1
    try:
        if not selected.is_absolute():
            raise ValueError
        root_stat = selected.lstat()
        if (
            stat.S_ISLNK(root_stat.st_mode)
            or not stat.S_ISDIR(root_stat.st_mode)
            or selected.resolve(strict=True) != selected
        ):
            structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
        else:
            root_descriptor = os.open(
                selected, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            opened_root = os.fstat(root_descriptor)
            if (opened_root.st_dev, opened_root.st_ino) != (root_stat.st_dev, root_stat.st_ino):
                raise ValueError
            directory_count = 0
            file_count = 0
            materialized_bytes = 0
            stopped = False

            def materialize(directory_descriptor: int, prefix: str) -> None:
                nonlocal directory_count, file_count, materialized_bytes, stopped
                directory_count += 1
                if directory_count > policy.maximum_directories:
                    structural[LeakageReason.TREE_TOO_LARGE] += 1
                    stopped = True
                    return
                with os.scandir(directory_descriptor) as entries:
                    for entry in entries:
                        if stopped:
                            return
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        before = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                            if not _valid_relative_path(relative, policy):
                                structural[LeakageReason.PATH_INVALID] += 1
                                continue
                            child_descriptor = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=directory_descriptor,
                            )
                            try:
                                opened_directory = os.fstat(child_descriptor)
                                if (opened_directory.st_dev, opened_directory.st_ino) != (
                                    before.st_dev,
                                    before.st_ino,
                                ):
                                    structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                                    continue
                                materialize(child_descriptor, relative)
                            finally:
                                os.close(child_descriptor)
                            continue
                        file_count += 1
                        if file_count > policy.maximum_files:
                            structural[LeakageReason.TREE_TOO_LARGE] += 1
                            stopped = True
                            return
                        if (
                            stat.S_ISLNK(before.st_mode)
                            or not stat.S_ISREG(before.st_mode)
                            or before.st_nlink != 1
                        ):
                            structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                            continue
                        if before.st_size > policy.maximum_file_bytes:
                            structural[LeakageReason.FILE_TOO_LARGE] += 1
                            candidates.append(CandidateFile(relative, b""))
                            continue
                        if materialized_bytes + before.st_size > policy.maximum_tree_bytes:
                            structural[LeakageReason.TREE_TOO_LARGE] += 1
                            stopped = True
                            return
                        descriptor = os.open(
                            entry.name,
                            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_descriptor,
                        )
                        try:
                            opened = os.fstat(descriptor)
                            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                                structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                                continue
                            content = os.read(descriptor, policy.maximum_file_bytes + 1)
                            if len(content) > policy.maximum_file_bytes or os.read(descriptor, 1):
                                structural[LeakageReason.FILE_TOO_LARGE] += 1
                                content = b""
                        finally:
                            os.close(descriptor)
                        materialized_bytes += len(content)
                        candidates.append(CandidateFile(relative, content))

            materialize(root_descriptor, "")
    except Exception:
        structural[LeakageReason.INTERNAL_ERROR] += 1
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)

    result = scan_candidate_files(candidates, canaries=canaries, policy=policy)
    combined: Counter[LeakageReason] = Counter(
        {LeakageReason(key): value for key, value in result.counts.items()}
    )
    combined.update(structural)
    return _safe_result(candidates, combined, artifact_complete=not structural)


def _read_protected_canaries(path: Path, policy: LeakageScannerPolicy) -> tuple[bytes, ...]:
    selected = Path(path)
    if not selected.is_absolute() or selected.resolve(strict=True) != selected:
        raise ValueError
    metadata = selected.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size > policy.maximum_canaries * (policy.maximum_canary_bytes + 1)
    ):
        raise ValueError
    descriptor = os.open(selected, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError
        content = os.read(descriptor, metadata.st_size + 1)
    finally:
        os.close(descriptor)
    if len(content) != metadata.st_size:
        raise ValueError
    return tuple(line for line in content.splitlines() if line)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline scanner and print only its content-free JSON result."""

    parser = argparse.ArgumentParser(description="Scan a bounded public candidate offline")
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--canary-file", required=True, type=Path)
    arguments = parser.parse_args(argv)
    policy = LeakageScannerPolicy()
    try:
        canaries = _read_protected_canaries(arguments.canary_file, policy)
        result = scan_candidate_tree(arguments.candidate_root, canaries=canaries, policy=policy)
    except Exception:
        result = LeakageScanResult(
            ok=False,
            artifact_sha256=_INCOMPLETE_ARTIFACT_SHA256,
            counts={LeakageReason.INTERNAL_ERROR.value: 1},
        )
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
