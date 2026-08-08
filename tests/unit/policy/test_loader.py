from __future__ import annotations

import json
from pathlib import Path

import pytest
from kivra_memory.policy import (
    SELECTION_V1,
    SELECTION_V1_PROFILE_SHA256,
    load_selection_policy,
)
from pydantic import ValidationError


def test_checked_in_selection_v1_digest_is_stable() -> None:
    assert SELECTION_V1_PROFILE_SHA256 == (
        "b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"
    )


def test_profile_hash_is_independent_of_json_formatting_and_key_order(tmp_path: Path) -> None:
    parsed = json.loads(SELECTION_V1.canonical_bytes)
    reformatted = tmp_path / "selection-v1.json"
    reformatted.write_text(json.dumps(parsed, indent=7, sort_keys=False), encoding="utf-8")

    loaded = load_selection_policy(reformatted)

    assert loaded.profile == SELECTION_V1.profile
    assert loaded.canonical_bytes == SELECTION_V1.canonical_bytes
    assert loaded.sha256_hex == SELECTION_V1.sha256_hex


def test_loader_rejects_duplicate_names_unknown_fields_and_incomplete_rules(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"profile_version":"selection-v1","profile_version":"selection-v1"}')
    with pytest.raises(Exception, match="unique"):
        load_selection_policy(duplicate)

    document = json.loads(SELECTION_V1.canonical_bytes)
    document["unexpected"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        load_selection_policy(unknown)

    document = json.loads(SELECTION_V1.canonical_bytes)
    document["basis_rules"] = document["basis_rules"][:-1]
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="every basis exactly once"):
        load_selection_policy(incomplete)


def test_loader_rejects_precedence_changes_and_candidate_ttl_mismatch(tmp_path: Path) -> None:
    document = json.loads(SELECTION_V1.canonical_bytes)
    document["precedence"] = list(reversed(document["precedence"]))
    precedence = tmp_path / "precedence.json"
    precedence.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="deterministic order"):
        load_selection_policy(precedence)

    document = json.loads(SELECTION_V1.canonical_bytes)
    candidate = next(
        rule for rule in document["basis_rules"] if rule["outcome"] == "candidate"
    )
    candidate["candidate_ttl_days"] = None
    ttl = tmp_path / "ttl.json"
    ttl.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="candidate rules require a TTL"):
        load_selection_policy(ttl)
