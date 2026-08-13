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
from kivra_memory.security.credential_files import read_protected_file


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


class _UnsafeCandidateTree(Exception):
    """Internal control flow after a fixed structural rejection is recorded."""


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


_FORBIDDEN_FIELD_SPELLINGS: Final = frozenset(
    {
        # Sealed envelope and authenticated-content material.
        "aad",
        "aad_hash",
        "aad_sha256",
        "additional_authenticated_data",
        "authentication_tag",
        "auth_tag",
        "sealed_aad_sha256",
        "sealed_algorithm",
        "sealed_ciphertext",
        "sealed_envelope",
        "sealed_envelope_version",
        "sealed_nonce",
        "tag",
        # Content-key provider material and destruction proof.
        "content_key",
        "archive_manifest_digest",
        "ciphertext",
        "content_key_id",
        "content_key_identifier",
        "content_key_reference",
        "destruction_receipt",
        "destruction_receipt_sha256",
        "destruction_tombstone",
        "key_destruction_receipt",
        "key_provider",
        "key_provider_name",
        "key_reference",
        "provider",
        "provider_key_reference",
        "provider_name",
        # Canonical statement, rationale, evidence, and content metadata.
        "evidence",
        "evidence_excerpt",
        "evidence_key",
        "evidence_references",
        "evidence_summary",
        "evidence_text",
        "excerpt",
        "interpretation_limits",
        "metadata",
        "memory_statement",
        "payload",
        "payload_canonical",
        "rationale",
        "reason",
        "reason_to_remember",
        "resolution_rationale",
        "statement",
        # Private source, transcript, manifest, and canonical event linkage.
        "archive_source_path",
        "archive_path",
        "archive_previous_digest",
        "causation_event_id",
        "canonical_event_id",
        "canonical_event_sequence",
        "command_sha256",
        "correlation_id",
        "content_sha256",
        "event_id",
        "event_sequence",
        "git_commit_sha",
        "manifest_linkage",
        "manifest_digest",
        "manifest_id",
        "manifest_path",
        "manifest_sha256",
        "nonce",
        "origin_session_id",
        "payload_sha256",
        "postgres_timeline_id",
        "private_manifest_linkage",
        "private_source",
        "private_path",
        "private_source_reference",
        "previous_manifest_sha256",
        "previous_event_id",
        "source_archive_path",
        "source_high_water_sequence",
        "source_ref",
        "source_reference",
        "transcript",
        "transcript_id",
        "transcript_reference",
        # Private identity and installation linkage.
        "actor",
        "actor_id",
        "archive_target_id",
        "branch",
        "branch_id",
        "client",
        "client_id",
        "credential",
        "credential_id",
        "deployment",
        "deployment_id",
        "deployment_identifier",
        "host",
        "host_id",
        "host_identifier",
        "host_name",
        "hostname",
        "ingress",
        "ingress_id",
        "installation",
        "installation_id",
        "lineage",
        "lineage_id",
        "memory_id",
        "repository",
        "repository_external_id",
        "repository_id",
        "repository_name",
        "repository_owner",
        "repository_url",
        "session_id",
        "source_memory_id",
        "subject_id",
        "target_memory_id",
        "tenant",
        "tenant_id",
        "transport_binding_id",
        "transport_installation_id",
        # Credential-bearing structured fields are rejected independently of value.
        "access_token",
        "api_key",
        "authorization",
        "bearer_token",
        "certificate_sha256",
        "client_secret",
        "database_url",
        "password",
        "private_key",
        "secret_hash",
        "secret_hash_key_id",
        "secret_verifier",
        "token_pepper",
    }
)
_TEXT_FIELD = re.compile(r"(?m)^[ \t]*[\"']?([^:=\r\n]{1,128}?)[\"']?[ \t]*[:=]")
_CREDENTIAL_PATTERNS: Final = (
    re.compile(rb"(?i)\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{32,}"),
    re.compile(rb"(?i)\bbasic\s+[A-Za-z0-9+/]{12,}={0,2}\b"),
    re.compile(rb"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\b(?:glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(
        rb"\bsvb1\.[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
        rb"[0-9a-f]{12}\.[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
        rb"[0-9a-f]{12}\.[A-Za-z0-9_-]{43}\b"
    ),
    re.compile(rb"\bhmac-sha256-v1:[A-Za-z0-9_-]{43}\b"),
    re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(rb"(?i)\bpostgres(?:ql)?://[^\s/:@]+:[^\s/@]+@"),
    re.compile(rb"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
    re.compile(
        rb"(?i)[\"']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|"
        rb"client[_-]?secret|password|private[_-]?key|secret|token)[\"']?\s*[:=]\s*"
        rb"(?:[\"'][^\s\"']{8,}[\"']|[A-Za-z0-9._~+/=-]{16,})"
    ),
)
_INCOMPLETE_ARTIFACT_SHA256: Final = hashlib.sha256(
    b"scalevault-incomplete-public-candidate-v1"
).hexdigest()
_MOUNTINFO_MAXIMUM_BYTES: Final = 2 * 1024 * 1024


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


def _stable_directory_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _directory_names(directory_descriptor: int, *, maximum_entries: int) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(directory_descriptor) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > maximum_entries:
                raise ValueError
    names.sort()
    return tuple(names)


def _unescape_mountinfo_path(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _mountinfo_snapshot() -> tuple[tuple[str, str, str, str, str], ...]:
    descriptor = os.open("/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, _MOUNTINFO_MAXIMUM_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MOUNTINFO_MAXIMUM_BYTES:
                raise ValueError
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError from None
    mounts: list[tuple[str, str, str, str, str]] = []
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) < 10 or "-" not in fields[6:]:
            raise ValueError
        mount_id, parent_id, device, mount_root, mount_point = fields[:5]
        if not mount_id.isdecimal() or not parent_id.isdecimal() or ":" not in device:
            raise ValueError
        mounts.append(
            (
                mount_id,
                parent_id,
                device,
                _unescape_mountinfo_path(mount_root),
                _unescape_mountinfo_path(mount_point),
            )
        )
    if not mounts:
        raise ValueError
    mounts.sort()
    return tuple(mounts)


def _contains_nested_mount(root: Path, mounts: Sequence[tuple[str, str, str, str, str]]) -> bool:
    root_text = str(root)
    prefix = root_text.rstrip("/") + "/"
    return any(mount_point.startswith(prefix) for *_, mount_point in mounts)


@dataclass(frozen=True, slots=True)
class _CanaryForms:
    exact: bytes
    normalized: frozenset[bytes]
    base64: frozenset[bytes]
    hexadecimal: frozenset[bytes]
    digest: frozenset[bytes]


def _canary_forms(canary: bytes) -> _CanaryForms:
    byte_forms = {canary}
    try:
        text = canary.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        byte_forms.add(unicodedata.normalize("NFC", text).encode("utf-8"))
        byte_forms.add(unicodedata.normalize("NFKC", text).encode("utf-8"))
    normalized = byte_forms - {canary}
    base64_forms: set[bytes] = set()
    hex_forms: set[bytes] = set()
    digest_forms: set[bytes] = set()
    for value in byte_forms:
        standard = base64.b64encode(value)
        urlsafe = base64.urlsafe_b64encode(value)
        base64_forms.update({standard, standard.rstrip(b"="), urlsafe, urlsafe.rstrip(b"=")})
        hexadecimal = value.hex()
        hex_forms.update({hexadecimal.encode("ascii"), hexadecimal.upper().encode("ascii")})
        digest = hashlib.sha256(value).hexdigest()
        digest_forms.update({digest.encode("ascii"), digest.upper().encode("ascii")})
    return _CanaryForms(
        exact=canary,
        normalized=frozenset(normalized),
        base64=frozenset(base64_forms),
        hexadecimal=frozenset(hex_forms),
        digest=frozenset(digest_forms),
    )


def _normalized_field_name(value: str) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFKC", value).casefold()
        if character.isalnum()
    )


_FORBIDDEN_FIELDS: Final = frozenset(
    _normalized_field_name(value) for value in _FORBIDDEN_FIELD_SPELLINGS
)
_PRIVATE_IDENTIFIER_ROOTS: Final = (
    "actor",
    "archivetarget",
    "branch",
    "client",
    "conflict",
    "credential",
    "deployment",
    "evidence",
    "host",
    "ingress",
    "installation",
    "lineage",
    "link",
    "memory",
    "repository",
    "session",
    "subject",
    "tenant",
    "transportbinding",
    "transportinstallation",
)
_PRIVATE_IDENTIFIER_SUFFIXES: Final = (
    "externalid",
    "id",
    "identifier",
    "name",
    "owner",
    "url",
    "uuid",
)


def _is_forbidden_field(value: str) -> bool:
    normalized = _normalized_field_name(value)
    if normalized in _FORBIDDEN_FIELDS:
        return True
    return any(root in normalized for root in _PRIVATE_IDENTIFIER_ROOTS) and normalized.endswith(
        _PRIVATE_IDENTIFIER_SUFFIXES
    )


def _structured_content(document: bytes, suffix: str) -> tuple[set[str], str]:
    text = document.decode("utf-8")
    fields = {
        match.group(1).strip() for match in _TEXT_FIELD.finditer(text) if match.group(1).strip()
    }
    if suffix not in {".json", ".jsonl"}:
        return fields, ""
    values: list[object]
    if suffix == ".json":
        values = [parse_json_strict(document)]
    else:
        lines = [line for line in document.splitlines() if line.strip()]
        values = [parse_json_strict(line) for line in lines]

    strings: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                fields.add(_normalized_field_name(key))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str):
            if "\x00" in value or any(
                ord(character) < 0x20 and character not in "\n\r\t" for character in value
            ):
                raise ValueError
            strings.append(value)

    for value in values:
        visit(value)
    return fields, "\x00".join(strings)


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
                artifact_complete = False
                supplied_canaries = []
                canary_overflow = True
                break
        if not supplied_canaries and not canary_overflow:
            counts[LeakageReason.CANARY_INPUT_INVALID] += 1
            artifact_complete = False

        canary_bytes: list[bytes] = []
        for canary in supplied_canaries:
            encoded = canary.encode("utf-8") if isinstance(canary, str) else canary
            if not policy.minimum_canary_bytes <= len(encoded) <= policy.maximum_canary_bytes:
                counts[LeakageReason.CANARY_INPUT_INVALID] += 1
                artifact_complete = False
                continue
            canary_bytes.append(encoded)
        if len(set(canary_bytes)) != len(canary_bytes):
            counts[LeakageReason.CANARY_INPUT_INVALID] += 1
            artifact_complete = False
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

            fields: set[str] = set()
            structured_strings = ""
            if suffix in policy.allowed_suffixes and text:
                try:
                    fields, structured_strings = _structured_content(candidate.content, suffix)
                except Exception:
                    counts[LeakageReason.MALFORMED_ENCODING] += 1
                else:
                    if any(_is_forbidden_field(field) for field in fields):
                        counts[LeakageReason.FORBIDDEN_FIELD] += 1

            byte_segments = (candidate.content, structured_strings.encode("utf-8"))
            text_segments = (text, structured_strings)
            per_file: set[LeakageReason] = set()
            normalized_text_segments = tuple(
                unicodedata.normalize("NFKC", value) for value in text_segments
            )
            for canary_forms in forms:
                if any(canary_forms.exact in segment for segment in byte_segments):
                    per_file.add(LeakageReason.CANARY_RAW)
                try:
                    exact_text = canary_forms.exact.decode("utf-8")
                except UnicodeDecodeError:
                    exact_text = ""
                if any(
                    value and any(value in segment for segment in byte_segments)
                    for value in canary_forms.normalized
                ) or (
                    exact_text
                    and any(
                        unicodedata.normalize("NFKC", exact_text) in segment
                        for segment in normalized_text_segments
                    )
                    and not any(canary_forms.exact in segment for segment in byte_segments)
                ):
                    per_file.add(LeakageReason.CANARY_NORMALIZED)
                if any(
                    value and any(value in segment for segment in byte_segments)
                    for value in canary_forms.base64
                ):
                    per_file.add(LeakageReason.CANARY_BASE64)
                if any(
                    value and any(value in segment for segment in byte_segments)
                    for value in canary_forms.hexadecimal
                ):
                    per_file.add(LeakageReason.CANARY_HEX)
                if any(
                    value and any(value in segment for segment in byte_segments)
                    for value in canary_forms.digest
                ):
                    per_file.add(LeakageReason.CANARY_DIGEST)
            for reason in per_file:
                counts[reason] += 1

            if any(
                pattern.search(segment)
                for pattern in _CREDENTIAL_PATTERNS
                for segment in byte_segments
            ):
                counts[LeakageReason.CREDENTIAL_GRAMMAR] += 1

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
    mountinfo_before: tuple[tuple[str, str, str, str, str], ...] = ()
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
            mountinfo_before = _mountinfo_snapshot()
            if _contains_nested_mount(selected, mountinfo_before):
                structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                raise _UnsafeCandidateTree
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
                directory_before = os.fstat(directory_descriptor)
                names_before = _directory_names(
                    directory_descriptor,
                    maximum_entries=policy.maximum_files + policy.maximum_directories,
                )
                for name in names_before:
                    if stopped:
                        return
                    relative = f"{prefix}/{name}" if prefix else name
                    before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                        if before.st_dev != opened_root.st_dev:
                            structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                            continue
                        if not _valid_relative_path(relative, policy):
                            structural[LeakageReason.PATH_INVALID] += 1
                            continue
                        child_descriptor = os.open(
                            name,
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
                        or before.st_dev != opened_root.st_dev
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
                        name,
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
                        after = os.fstat(descriptor)
                        if (
                            after.st_mode != before.st_mode
                            or after.st_nlink != before.st_nlink
                            or after.st_size != before.st_size
                            or after.st_mtime_ns != before.st_mtime_ns
                            or after.st_ctime_ns != before.st_ctime_ns
                        ):
                            structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                            continue
                    finally:
                        os.close(descriptor)
                    materialized_bytes += len(content)
                    candidates.append(CandidateFile(relative, content))
                names_after = _directory_names(
                    directory_descriptor,
                    maximum_entries=policy.maximum_files + policy.maximum_directories,
                )
                directory_after = os.fstat(directory_descriptor)
                if names_before != names_after or not _stable_directory_metadata(
                    directory_before, directory_after
                ):
                    structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
                    stopped = True

            materialize(root_descriptor, "")
            final_root_path = selected.lstat()
            final_root_descriptor = os.fstat(root_descriptor)
            if (final_root_path.st_dev, final_root_path.st_ino) != (
                root_stat.st_dev,
                root_stat.st_ino,
            ) or not _stable_directory_metadata(opened_root, final_root_descriptor):
                structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
            mountinfo_after = _mountinfo_snapshot()
            if mountinfo_before != mountinfo_after or _contains_nested_mount(
                selected, mountinfo_after
            ):
                structural[LeakageReason.LINK_OR_SPECIAL_FILE] += 1
    except _UnsafeCandidateTree:
        pass
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
    return _safe_result(
        candidates,
        combined,
        artifact_complete=(
            not structural and result.artifact_sha256 != _INCOMPLETE_ARTIFACT_SHA256
        ),
    )


def _read_protected_canaries(path: Path, policy: LeakageScannerPolicy) -> tuple[bytes, ...]:
    content = read_protected_file(
        Path(path),
        minimum_bytes=0,
        maximum_bytes=policy.maximum_canaries * (policy.maximum_canary_bytes + 1),
        required_owner_uid=0,
        allowed_modes=frozenset({0o600}),
    )
    return tuple(content.splitlines())


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
            counts={LeakageReason.CANARY_INPUT_INVALID.value: 1},
        )
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
