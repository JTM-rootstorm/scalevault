"""Privacy-safe exact-memory fingerprints for synchronous duplicate prevention.

Version 1 fingerprints identify an *exact semantic claim*, not a merely similar
sentence.  The digest binds the statement, category, ontological status, scope,
and interpretation limits.  It deliberately excludes mutable presentation and
retrieval fields such as confidence, evidence, timestamps, and reason-to-
remember.

Only conservative text presentation normalization is performed before hashing:
ASCII horizontal whitespace runs are collapsed, leading/trailing ASCII space,
tab, CR, and LF are removed, and CR/CRLF are made LF.  Text is case-sensitive;
all non-ASCII code points (including Unicode whitespace) are preserved exactly.
In particular, this module must not apply Unicode normalization (ADR 0009).

The returned lock material contains hashes and public aggregate identifiers
only.  It never retains the statement or the canonical digest preimage, so it
is suitable for advisory-lock inputs and diagnostic-safe representations.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import MemoryCategory, MemoryScope, OntologicalStatus
from kivra_memory.domain.errors import DomainValidationError
from kivra_memory.domain.identifiers import require_uuid7

FINGERPRINT_VERSION = 1
_SHA256_HEX_LENGTH = 64
_ASCII_HORIZONTAL_WHITESPACE = re.compile(r"[ \t]+")


@dataclass(frozen=True, slots=True)
class ExactMemoryFingerprint:
    """A v1 digest and its statement-free canonical fingerprint lock token."""

    sha256_hex: str
    canonical_lock_input: bytes

    def __repr__(self) -> str:
        """Render only the digest; raw memory content is never representable here."""

        return f"{type(self).__name__}(sha256_hex={self.sha256_hex!r})"


def _normalize_text(value: str, *, field_name: str) -> str:
    """Apply only v1's explicitly safe ASCII presentation normalization."""

    if not isinstance(value, str):
        raise DomainValidationError(f"{field_name} must be a string")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _ASCII_HORIZONTAL_WHITESPACE.sub(" ", normalized).strip(" \t\r\n")
    if not normalized:
        raise DomainValidationError(f"{field_name} must not be blank")
    return normalized


def _enum_value(
    value: MemoryCategory | MemoryScope | OntologicalStatus | str, *, field_name: str
) -> str:
    enum_type: type[MemoryCategory] | type[MemoryScope] | type[OntologicalStatus]
    if field_name == "category":
        enum_type = MemoryCategory
    elif field_name == "ontological_status":
        enum_type = OntologicalStatus
    else:
        enum_type = MemoryScope
    try:
        return enum_type(value).value
    except (TypeError, ValueError):
        raise DomainValidationError(f"{field_name} is invalid") from None


def _normalized_interpretation_limits(limits: Iterable[str]) -> tuple[str, ...]:
    """Canonicalize interpretation limits as a set-like semantic dimension."""

    if isinstance(limits, (str, bytes, bytearray)):
        raise DomainValidationError("interpretation_limits must be a collection of strings")
    try:
        normalized = {_normalize_text(limit, field_name="interpretation limit") for limit in limits}
    except TypeError:
        raise DomainValidationError("interpretation_limits must be iterable") from None
    if len(normalized) > 32:
        raise DomainValidationError("interpretation_limits cannot exceed 32 entries")
    return tuple(sorted(normalized))


def exact_memory_fingerprint(
    *,
    statement: str,
    category: MemoryCategory | str,
    ontological_status: OntologicalStatus | str,
    scope: MemoryScope | str,
    interpretation_limits: Iterable[str] = (),
) -> ExactMemoryFingerprint:
    """Return the v1 SHA-256 fingerprint and statement-free lock token.

    Interpretation limits are a set-like dimension: their input order and
    repeated identical limits do not change identity.  Case changes do change
    identity, because v1 does not case-fold user-authored text.
    """

    fingerprint_preimage = canonical_json_bytes(
        {
            "fingerprint_version": FINGERPRINT_VERSION,
            "statement": _normalize_text(statement, field_name="statement"),
            "category": _enum_value(category, field_name="category"),
            "ontological_status": _enum_value(ontological_status, field_name="ontological_status"),
            "scope": _enum_value(scope, field_name="scope"),
            "interpretation_limits": _normalized_interpretation_limits(interpretation_limits),
        }
    )
    digest = sha256(fingerprint_preimage).hexdigest()
    return ExactMemoryFingerprint(
        sha256_hex=digest,
        canonical_lock_input=canonical_json_bytes(
            {
                "fingerprint_version": FINGERPRINT_VERSION,
                "normalized_fingerprint": digest,
            }
        ),
    )


def advisory_lock_input(
    *,
    tenant_id: UUID,
    lineage_id: UUID,
    branch_id: UUID,
    subject_id: UUID,
    fingerprint: ExactMemoryFingerprint | str,
) -> bytes:
    """Return canonical, statement-free advisory-lock bytes required by plan §8.4."""

    digest = (
        fingerprint.sha256_hex if isinstance(fingerprint, ExactMemoryFingerprint) else fingerprint
    )
    if not isinstance(digest, str) or not re.fullmatch(
        rf"[0-9a-f]{{{_SHA256_HEX_LENGTH}}}", digest
    ):
        raise DomainValidationError("normalized fingerprint must be lowercase SHA-256 hexadecimal")
    return canonical_json_bytes(
        {
            "tenant_id": str(require_uuid7(tenant_id, field_name="tenant_id")),
            "lineage_id": str(require_uuid7(lineage_id, field_name="lineage_id")),
            "branch_id": str(require_uuid7(branch_id, field_name="branch_id")),
            "subject_id": str(require_uuid7(subject_id, field_name="subject_id")),
            "normalized_fingerprint": digest,
        }
    )
