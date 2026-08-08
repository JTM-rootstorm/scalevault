"""Content-safe loading, planning, and gated application of private seed bundles."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections.abc import Awaitable, Iterator
from pathlib import Path
from typing import Annotated, Literal, Protocol

from pydantic import Field, ValidationError

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.seeding.contracts import (
    Digest,
    PrivateSeedBundle,
    PrivateSeedRecord,
    SeedContract,
)

_MAXIMUM_BUNDLE_BYTES = 2 * 1024 * 1024
_BUNDLE_DIGEST_DOMAIN = b"scalevault.private-seed.bundle.v1\x00"
_RECORD_DIGEST_DOMAIN = b"scalevault.private-seed.record.v1\x00"
_IDEMPOTENCY_DOMAIN = b"scalevault.private-seed.idempotency.v1\x00"
_SPACE_PATTERN = re.compile(r"\s+")
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:sk-(?:proj-)?|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]", re.I),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_SECRET_KEY_PATTERN = re.compile(
    r"(?:password|passwd|authorization|private[_-]?key|api[_-]?key|access[_-]?token|secret)",
    re.IGNORECASE,
)


class PrivateSeedError(RuntimeError):
    """Content-free private-seed failure suitable for operator output."""


class SeedPlanItem(SeedContract):
    ordinal: Annotated[int, Field(ge=1, le=512)]
    record_sha256: Digest
    idempotency_key: Annotated[str, Field(pattern=r"^private-seed-v1:[0-9a-f]{64}$")]


class PrivateSeedPlan(SeedContract):
    contract_version: Literal["scalevault-private-seed-plan-v1"]
    bundle_sha256: Digest
    record_count: Annotated[int, Field(ge=1, le=512)]
    items: tuple[SeedPlanItem, ...]


class SeedNomination(SeedContract):
    """Full private nomination passed only across the injected service boundary."""

    idempotency_key: Annotated[str, Field(pattern=r"^private-seed-v1:[0-9a-f]{64}$")]
    record_sha256: Digest
    record: PrivateSeedRecord


class SeedApplyRequest(SeedContract):
    contract_version: Literal["scalevault-private-seed-apply-v1"]
    bundle_sha256: Digest
    nominations: tuple[SeedNomination, ...]


class SeedApplyResult(SeedContract):
    """Content-free result returned by an atomic nomination service."""

    contract_version: Literal["scalevault-private-seed-result-v1"]
    bundle_sha256: Digest
    outcome: Literal["applied", "already_applied"]
    nominated_count: Annotated[int, Field(ge=0, le=512)]


class SeedNominationService(Protocol):
    """Resolve atomically, reject key/hash reuse, and never log request content."""

    def nominate_private_seed(self, request: SeedApplyRequest, /) -> Awaitable[SeedApplyResult]: ...


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _iter_strings(value: object) -> Iterator[tuple[str, str]]:
    pending: list[tuple[str, object]] = [("bundle", value)]
    while pending:
        path, item = pending.pop()
        if isinstance(item, str):
            yield path, item
        elif isinstance(item, dict):
            for key, member in item.items():
                if _SECRET_KEY_PATTERN.search(str(key)) is not None:
                    raise PrivateSeedError("secret_named_field_rejected")
                pending.append((f"{path}.{key}", member))
        elif isinstance(item, list | tuple):
            pending.extend((f"{path}[]", member) for member in item)


def _screen_bundle(bundle: PrivateSeedBundle) -> None:
    material = bundle.model_dump(mode="python")
    for _path, value in _iter_strings(material):
        if any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS):
            raise PrivateSeedError("secret_material_rejected")

    semantic_keys: set[tuple[bytes, str]] = set()
    for record in bundle.records:
        selector = canonical_json_bytes(record.selector.model_dump(mode="python"))
        statement = _SPACE_PATTERN.sub(
            " ", unicodedata.normalize("NFKC", record.memory.statement).casefold()
        ).strip()
        semantic_key = (selector, statement)
        if semantic_key in semantic_keys:
            raise PrivateSeedError("duplicate_seed_memory")
        semantic_keys.add(semantic_key)


def load_private_seed_bundle(path: Path) -> PrivateSeedBundle:
    """Load and fully validate a bounded regular file without emitting its content."""

    if not path.is_absolute():
        raise PrivateSeedError("invalid_seed_bundle_path")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise PrivateSeedError("invalid_seed_bundle_path") from None
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_uid != os.geteuid()
        ):
            raise PrivateSeedError("unsafe_seed_bundle_permissions")
        if not 1 <= status.st_size <= _MAXIMUM_BUNDLE_BYTES:
            raise PrivateSeedError("invalid_seed_bundle_size")
        chunks: list[bytes] = []
        remaining = _MAXIMUM_BUNDLE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not 1 <= len(raw) <= _MAXIMUM_BUNDLE_BYTES or os.read(descriptor, 1):
            raise PrivateSeedError("invalid_seed_bundle_size")
        final_status = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != status.st_size or any(
            getattr(status, field) != getattr(final_status, field) for field in stable_fields
        ):
            raise PrivateSeedError("seed_bundle_changed_during_read")
    except OSError:
        raise PrivateSeedError("seed_bundle_unreadable") from None
    finally:
        os.close(descriptor)
    try:
        parsed = parse_json_strict(raw)
        bundle = PrivateSeedBundle.model_validate_json(canonical_json_bytes(parsed), strict=True)
    except (ValidationError, ValueError, TypeError):
        raise PrivateSeedError("seed_bundle_schema_invalid") from None
    _screen_bundle(bundle)
    return bundle


def plan_private_seed(bundle: PrivateSeedBundle) -> PrivateSeedPlan:
    """Render a deterministic, content-free, zero-write application plan."""

    _screen_bundle(bundle)
    bundle_value = bundle.model_dump(mode="python")
    bundle_sha256 = _digest(_BUNDLE_DIGEST_DOMAIN, bundle_value)
    items: list[SeedPlanItem] = []
    for ordinal, record in enumerate(bundle.records, start=1):
        record_value = record.model_dump(mode="python")
        record_sha256 = _digest(_RECORD_DIGEST_DOMAIN, record_value)
        idempotency_digest = _digest(
            _IDEMPOTENCY_DOMAIN,
            {
                "contract_version": bundle.contract_version,
                "bundle_key": bundle.bundle_key,
                "record_key": record.record_key,
            },
        )
        items.append(
            SeedPlanItem(
                ordinal=ordinal,
                record_sha256=record_sha256,
                idempotency_key=f"private-seed-v1:{idempotency_digest}",
            )
        )
    return PrivateSeedPlan(
        contract_version="scalevault-private-seed-plan-v1",
        bundle_sha256=bundle_sha256,
        record_count=len(items),
        items=tuple(items),
    )


async def apply_private_seed(
    bundle: PrivateSeedBundle,
    *,
    expected_digest: str,
    approved: bool,
    nomination_service: SeedNominationService,
) -> SeedApplyResult:
    """Apply through one injected service call after both explicit safety gates."""

    if approved is not True:
        raise PrivateSeedError("seed_apply_not_approved")
    plan = plan_private_seed(bundle)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or expected_digest != plan.bundle_sha256:
        raise PrivateSeedError("seed_bundle_digest_mismatch")
    request = SeedApplyRequest(
        contract_version="scalevault-private-seed-apply-v1",
        bundle_sha256=plan.bundle_sha256,
        nominations=tuple(
            SeedNomination(
                idempotency_key=item.idempotency_key,
                record_sha256=item.record_sha256,
                record=record,
            )
            for item, record in zip(plan.items, bundle.records, strict=True)
        ),
    )
    try:
        result = await nomination_service.nominate_private_seed(request)
    except Exception:
        raise PrivateSeedError("seed_nomination_failed") from None
    if not isinstance(result, SeedApplyResult):
        raise PrivateSeedError("seed_service_result_invalid")
    if result.bundle_sha256 != plan.bundle_sha256:
        raise PrivateSeedError("seed_service_digest_mismatch")
    if result.nominated_count > len(bundle.records):
        raise PrivateSeedError("seed_service_result_invalid")
    return result
