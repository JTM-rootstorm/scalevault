"""Exact Git snapshot enumeration and content-free import manifests.

The Genesis importer deliberately has no branch or revision parameter.  Its source
boundary is the single reviewed commit below; authorization recorded by later Git
history cannot widen the import set.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from kivra_memory.domain.canonical_json import canonical_json_bytes

GENESIS_SOURCE_REPOSITORY = "JTM-rootstorm/scalevault-memory-ingress"
GENESIS_SOURCE_SNAPSHOT_COMMIT = "7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9"
GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT = "f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d"
IMPORT_MANIFEST_VERSION = "scalevault.genesis-import-manifest.v1"

_OBJECT_ID = re.compile(r"[0-9a-f]{40}")
_PROPOSAL_PATH = re.compile(
    r"ingress/v1/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/"
    r"[0-9]{4}/(?:0[1-9]|1[0-2])/(?P<source_id>[0-9a-f-]{36})\.json"
)
_CHECKPOINT_V1_PATH = re.compile(
    r"ingress/checkpoints/v1/genesis/[0-9]{4}/(?:0[1-9]|1[0-2])/"
    r"(?P<source_id>[A-Za-z0-9_.-]+)\.json"
)
_CHECKPOINT_V2_PATH = re.compile(
    r"ingress/checkpoints/v2/genesis/[0-9]{4}/(?:0[1-9]|1[0-2])/"
    r"(?P<source_id>[A-Za-z0-9_.-]+)\.json"
)
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,127}")
_SAFE_PLAN_KIND = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SAFE_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_SAFE_IDEMPOTENCY_KEY = re.compile(r"[\x21-\x7e]{1,255}")


class SnapshotError(RuntimeError):
    """Raised when the pinned Git snapshot cannot be proven or enumerated."""


class ManifestError(ValueError):
    """Raised when a content-free import manifest is incomplete or ambiguous."""


class SourceContract(StrEnum):
    """Versioned source contract selected solely from a live ingress path."""

    PROPOSAL_V1 = "scalevault.ingress.proposal.v1"
    CHECKPOINT_V1 = "scalevault.ingress.genesis-checkpoint.v1"
    CHECKPOINT_V2 = "scalevault.ingress.genesis-checkpoint.v2"


@dataclass(frozen=True, slots=True)
class GitTreeEntry:
    """One blob reachable from an exact Git tree."""

    path: str
    blob_sha: str


class GitObjectReader(Protocol):
    """Minimal read-only Git object seam used by the snapshot enumerator."""

    def resolve_commit(self, commit: str) -> str:
        """Resolve an object ID as a commit and return its full object ID."""

    def list_tree(self, commit: str) -> tuple[GitTreeEntry, ...]:
        """List blobs reachable from exactly ``commit``."""

    def read_blob(self, blob_sha: str) -> bytes:
        """Read an exact blob by object ID without consulting a worktree."""


class LocalGitObjectReader:
    """Read objects from a local Git repository without using its HEAD/worktree."""

    def __init__(self, repository_path: Path) -> None:
        path = repository_path.resolve(strict=True)
        if not path.is_dir():
            raise ValueError("repository_path must be a directory")
        self._repository_path = path

    def resolve_commit(self, commit: str) -> str:
        self._require_object_id(commit, "commit")
        result = self._git("rev-parse", "--verify", f"{commit}^{{commit}}")
        try:
            resolved = result.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SnapshotError("git returned an invalid commit object ID") from None
        self._require_object_id(resolved, "resolved commit")
        return resolved

    def list_tree(self, commit: str) -> tuple[GitTreeEntry, ...]:
        self._require_object_id(commit, "commit")
        raw = self._git("ls-tree", "-rz", "--full-tree", commit)
        entries: list[GitTreeEntry] = []
        seen_paths: set[str] = set()
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, raw_sha = metadata.split(b" ", 2)
                path = raw_path.decode("utf-8")
                blob_sha = raw_sha.decode("ascii")
            except (UnicodeDecodeError, ValueError):
                raise SnapshotError("git tree output was invalid") from None
            if path.startswith("ingress/") and (mode != b"100644" or object_type != b"blob"):
                raise SnapshotError("ingress tree entry was not a regular blob")
            if mode != b"100644" or object_type != b"blob":
                continue
            self._require_object_id(blob_sha, "blob")
            if path in seen_paths:
                raise SnapshotError("git tree contained a duplicate path")
            seen_paths.add(path)
            entries.append(GitTreeEntry(path=path, blob_sha=blob_sha))
        return tuple(entries)

    def read_blob(self, blob_sha: str) -> bytes:
        self._require_object_id(blob_sha, "blob")
        return self._git("cat-file", "blob", blob_sha)

    def _git(self, *arguments: str) -> bytes:
        try:
            result = subprocess.run(
                (
                    "git",
                    "--no-replace-objects",
                    "-C",
                    str(self._repository_path),
                    *arguments,
                ),
                check=True,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            raise SnapshotError("local Git object read failed") from None
        return result.stdout

    @staticmethod
    def _require_object_id(value: str, name: str) -> None:
        if _OBJECT_ID.fullmatch(value) is None:
            raise SnapshotError(f"{name} object ID was invalid")


@dataclass(frozen=True, slots=True)
class SnapshotSourceItem:
    """Raw source bytes and immutable provenance for one importable Git blob."""

    source_repository: str
    source_snapshot_commit: str
    source_path: str
    source_git_blob_sha: str
    source_raw_sha256: str
    source_contract: SourceContract
    source_id: str
    raw_bytes: bytes


class GenesisSnapshotSource:
    """Enumerate importable records from only the authorized Genesis commit."""

    def __init__(self, reader: GitObjectReader) -> None:
        self._reader = reader

    def enumerate(self) -> tuple[SnapshotSourceItem, ...]:
        resolved = self._reader.resolve_commit(GENESIS_SOURCE_SNAPSHOT_COMMIT)
        if resolved != GENESIS_SOURCE_SNAPSHOT_COMMIT:
            raise SnapshotError("Genesis source commit did not match the authorized pin")

        entries = self._reader.list_tree(GENESIS_SOURCE_SNAPSHOT_COMMIT)
        items: list[SnapshotSourceItem] = []
        seen_paths: set[str] = set()
        for entry in entries:
            if entry.path in seen_paths:
                raise SnapshotError("snapshot contained a duplicate source path")
            seen_paths.add(entry.path)
            matched = _source_contract(entry.path)
            if matched is None:
                if entry.path.startswith("ingress/"):
                    raise SnapshotError("snapshot contained an unknown ingress source path")
                continue
            contract, source_id = matched
            if _OBJECT_ID.fullmatch(entry.blob_sha) is None:
                raise SnapshotError("snapshot contained an invalid Git blob object ID")
            raw = self._reader.read_blob(entry.blob_sha)
            actual_blob_sha = hashlib.sha1(
                f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
            ).hexdigest()
            if actual_blob_sha != entry.blob_sha:
                raise SnapshotError("snapshot blob bytes did not match Git provenance")
            items.append(
                SnapshotSourceItem(
                    source_repository=GENESIS_SOURCE_REPOSITORY,
                    source_snapshot_commit=GENESIS_SOURCE_SNAPSHOT_COMMIT,
                    source_path=entry.path,
                    source_git_blob_sha=entry.blob_sha,
                    source_raw_sha256=hashlib.sha256(raw).hexdigest(),
                    source_contract=contract,
                    source_id=source_id,
                    raw_bytes=raw,
                )
            )
        return tuple(sorted(items, key=lambda item: item.source_path))


@dataclass(frozen=True, slots=True)
class PlannedImportRecord:
    """Content-free identity of one derived nomination or preserved constraint."""

    source_path: str
    record_kind: str
    source_record_id: str
    owner_actor_id: str | None
    derived_record_sha256: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class ImportPlanManifest:
    """Canonical content-free description of an exact snapshot import plan."""

    value: Mapping[str, object]
    canonical_bytes: bytes
    digest: str


def build_import_plan_manifest(
    source_items: Sequence[SnapshotSourceItem],
    planned_records: Sequence[PlannedImportRecord],
    *,
    parser_schema_versions: Mapping[SourceContract, str],
    mapping_version: str,
    selection_policy_version: str,
    selection_policy_sha256: str,
) -> ImportPlanManifest:
    """Build and hash a deterministic manifest containing no source statements."""

    _require_version(mapping_version, "mapping_version")
    _require_version(selection_policy_version, "selection_policy_version")
    _require_sha256(selection_policy_sha256, "selection_policy_sha256")

    items_by_path: dict[str, SnapshotSourceItem] = {}
    for item in source_items:
        _validate_source_item(item)
        if item.source_path in items_by_path:
            raise ManifestError("source_items contained a duplicate source path")
        items_by_path[item.source_path] = item

    contracts = {item.source_contract for item in source_items}
    if set(parser_schema_versions) != contracts:
        raise ManifestError("parser_schema_versions must exactly cover enumerated contracts")
    version_map: dict[str, str] = {}
    for contract, version in parser_schema_versions.items():
        if not isinstance(contract, SourceContract):
            raise ManifestError("parser_schema_versions contained an unknown source contract")
        _require_version(version, "parser_schema_version")
        version_map[contract.value] = version

    plan_values: list[dict[str, object]] = []
    plan_identities: set[tuple[str, str, str]] = set()
    for record in planned_records:
        if record.source_path not in items_by_path:
            raise ManifestError("planned record referenced an unenumerated source path")
        if _SAFE_PLAN_KIND.fullmatch(record.record_kind) is None:
            raise ManifestError("planned record kind was invalid")
        if _SAFE_SOURCE_ID.fullmatch(record.source_record_id) is None:
            raise ManifestError("planned source record ID was invalid")
        if (
            record.owner_actor_id is not None
            and _SAFE_SOURCE_ID.fullmatch(record.owner_actor_id) is None
        ):
            raise ManifestError("planned owner actor ID was invalid")
        _require_sha256(record.derived_record_sha256, "derived_record_sha256")
        if _SAFE_IDEMPOTENCY_KEY.fullmatch(record.idempotency_key) is None:
            raise ManifestError("planned idempotency key was invalid")
        identity = (record.source_path, record.record_kind, record.source_record_id)
        if identity in plan_identities:
            raise ManifestError("planned_records contained a duplicate source identity")
        plan_identities.add(identity)
        plan_values.append(
            {
                "source_path": record.source_path,
                "record_kind": record.record_kind,
                "source_record_id": record.source_record_id,
                "owner_actor_id": record.owner_actor_id,
                "derived_record_sha256": record.derived_record_sha256,
                "idempotency_key": record.idempotency_key,
            }
        )

    source_values = [
        {
            "source_repository": item.source_repository,
            "source_snapshot_commit": item.source_snapshot_commit,
            "source_path": item.source_path,
            "source_git_blob_sha": item.source_git_blob_sha,
            "source_raw_sha256": item.source_raw_sha256,
            "source_contract": item.source_contract.value,
            "source_id": item.source_id,
        }
        for item in sorted(source_items, key=lambda candidate: candidate.source_path)
    ]
    value: dict[str, object] = {
        "manifest_version": IMPORT_MANIFEST_VERSION,
        "source_repository": GENESIS_SOURCE_REPOSITORY,
        "source_snapshot_commit": GENESIS_SOURCE_SNAPSHOT_COMMIT,
        "parser_schema_versions": version_map,
        "mapping_version": mapping_version,
        "selection_policy_version": selection_policy_version,
        "selection_policy_sha256": selection_policy_sha256,
        "source_items": source_values,
        "planned_records": sorted(
            plan_values,
            key=lambda candidate: (
                str(candidate["source_path"]),
                str(candidate["record_kind"]),
                str(candidate["source_record_id"]),
            ),
        ),
    }
    canonical = canonical_json_bytes(value)
    return ImportPlanManifest(
        value=value,
        canonical_bytes=canonical,
        digest=hashlib.sha256(canonical).hexdigest(),
    )


def _source_contract(path: str) -> tuple[SourceContract, str] | None:
    for pattern, contract in (
        (_PROPOSAL_PATH, SourceContract.PROPOSAL_V1),
        (_CHECKPOINT_V1_PATH, SourceContract.CHECKPOINT_V1),
        (_CHECKPOINT_V2_PATH, SourceContract.CHECKPOINT_V2),
    ):
        match = pattern.fullmatch(path)
        if match is not None:
            return contract, match.group("source_id")
    return None


def _validate_source_item(item: SnapshotSourceItem) -> None:
    if (
        item.source_repository != GENESIS_SOURCE_REPOSITORY
        or item.source_snapshot_commit != GENESIS_SOURCE_SNAPSHOT_COMMIT
    ):
        raise ManifestError("source item was outside the authorized Genesis snapshot")
    matched = _source_contract(item.source_path)
    if matched != (item.source_contract, item.source_id):
        raise ManifestError("source item path did not match its source contract identity")
    if _OBJECT_ID.fullmatch(item.source_git_blob_sha) is None:
        raise ManifestError("source Git blob SHA was invalid")
    _require_sha256(item.source_raw_sha256, "source_raw_sha256")
    if hashlib.sha256(item.raw_bytes).hexdigest() != item.source_raw_sha256:
        raise ManifestError("source raw bytes did not match source_raw_sha256")
    blob_sha = hashlib.sha1(
        f"blob {len(item.raw_bytes)}\0".encode() + item.raw_bytes, usedforsecurity=False
    ).hexdigest()
    if blob_sha != item.source_git_blob_sha:
        raise ManifestError("source raw bytes did not match source_git_blob_sha")


def _require_sha256(value: str, name: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ManifestError(f"{name} was invalid")


def _require_version(value: str, name: str) -> None:
    if _SAFE_VERSION.fullmatch(value) is None:
        raise ManifestError(f"{name} was invalid")
