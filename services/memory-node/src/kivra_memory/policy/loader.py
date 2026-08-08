"""Fail-closed loading for checked-in deterministic selection policy profiles."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.policy.contracts import SelectionPolicyProfile


@dataclass(frozen=True, slots=True)
class LoadedSelectionPolicy:
    """Validated policy plus the canonical bytes that identify its exact semantics."""

    profile: SelectionPolicyProfile
    canonical_bytes: bytes
    sha256_hex: str


def load_selection_policy(path: Path) -> LoadedSelectionPolicy:
    """Load one strict JSON profile and hash its fully validated canonical form."""

    parsed = parse_json_strict(path.read_bytes())
    parsed_canonical = canonical_json_bytes(parsed)
    profile = SelectionPolicyProfile.model_validate_json(parsed_canonical)
    canonical = canonical_json_bytes(profile.model_dump(mode="python"))
    return LoadedSelectionPolicy(
        profile=profile,
        canonical_bytes=canonical,
        sha256_hex=sha256(canonical).hexdigest(),
    )


SELECTION_V1_PATH = Path(__file__).with_name("profiles") / "selection-v1.json"
SELECTION_V1 = load_selection_policy(SELECTION_V1_PATH)
SELECTION_V1_PROFILE = SELECTION_V1.profile
SELECTION_V1_PROFILE_SHA256 = SELECTION_V1.sha256_hex
