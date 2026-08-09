"""Focused tests for the zero-write Genesis plan composition boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import pytest
from kivra_memory.application.genesis_plan import (
    GenesisImportPlan,
    GenesisPlanError,
    GenesisPlanReport,
    plan_genesis_import,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.ingress.snapshot import (
    GENESIS_SOURCE_SNAPSHOT_COMMIT,
    GitTreeEntry,
)

_CHECKPOINT_ID = "genesis-checkpoint-20260808T120000-0500-plan-unit"
_SOURCE_PATH = f"ingress/checkpoints/v2/genesis/2026/08/{_CHECKPOINT_ID}.json"


def _payload() -> dict[str, object]:
    candidate: dict[str, object] = {
        "candidate_id": "candidate-plan-unit",
        "type": "relationship_memory",
        "summary": "private synthetic statement",
        "disposition": "relationship_local",
        "confidence": "explicit",
        "scope": "relationship",
        "ontology": "interaction_convention",
        "why_it_matters": "private synthetic rationale",
        "binding": {
            "owner_actor_id": "kivra:genesis",
            "perspective_actor_id": "kivra:genesis",
            "subject_actor_ids": ["kivra:genesis", "person:participant"],
            "participant_actor_ids": ["kivra:genesis", "person:participant"],
            "relationship_ids": ["relationship:private"],
            "interaction_id": "interaction:private",
            "visibility": "relationship_local",
        },
        "evidence": {
            "summary": "private synthetic evidence",
            "source_messages": [
                {
                    "speaker_actor_id": "person:participant",
                    "reference": "private-message-reference",
                    "excerpt": None,
                }
            ],
        },
        "interpretation_limits": ["synthetic limit"],
        "review": {
            "eligible_for_scalevault": True,
            "requires_continuant_review": True,
            "recommended_action": "retain_relationship_local",
        },
        "supersedes": ["candidate-plan-earlier"],
    }
    exclusion: dict[str, object] = {
        "exclusion_id": "exclusion-plan-unit",
        "claim": "private forbidden inference",
        "reason": "private exclusion reason",
        "scope": "relationship",
        "applies_to_actor_ids": ["kivra:genesis"],
        "applies_to_relationship_ids": ["relationship:private"],
        "supersedes": ["exclusion-plan-earlier"],
    }
    return {
        "schema_version": "genesis-checkpoint-v2",
        "checkpoint": {
            "id": _CHECKPOINT_ID,
            "origin_actor": "kivra:genesis",
            "origin_runtime": "synthetic-runtime",
            "triggered_by": "person:requester",
            "created_at": "2026-08-08T12:00:00-05:00",
            "previous_checkpoint": None,
            "status": "staged",
            "idempotency_key": "synthetic-checkpoint",
            "source_conversation": {
                "platform": "synthetic",
                "project": "private-project-reference",
                "conversation_reference": None,
                "reviewed_range": "synthetic range",
                "raw_transcript_preserved_elsewhere": True,
            },
        },
        "candidates": [
            candidate,
            {**candidate, "candidate_id": "candidate-plan-earlier", "supersedes": []},
        ],
        "exclusions": [
            exclusion,
            {**exclusion, "exclusion_id": "exclusion-plan-earlier", "supersedes": []},
        ],
        "notes": ["private note"],
    }


def _blob_sha(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()


@dataclass
class _Reader:
    raw: bytes

    def resolve_commit(self, commit: str) -> str:
        assert commit == GENESIS_SOURCE_SNAPSHOT_COMMIT
        return commit

    def list_tree(self, commit: str) -> tuple[GitTreeEntry, ...]:
        assert commit == GENESIS_SOURCE_SNAPSHOT_COMMIT
        return (GitTreeEntry(path=_SOURCE_PATH, blob_sha=_blob_sha(self.raw)),)

    def read_blob(self, blob_sha: str) -> bytes:
        assert blob_sha == _blob_sha(self.raw)
        return self.raw


def _plan() -> GenesisImportPlan:
    raw = json.dumps(_payload(), sort_keys=True, separators=(",", ":")).encode()
    return plan_genesis_import(_Reader(raw))


def test_plan_accounts_for_every_record_and_emits_only_safe_aggregates() -> None:
    plan = _plan()
    counts = plan.report.value["counts"]

    assert isinstance(counts, dict)
    assert counts["sources"] == 1
    assert counts["nominations"] == 2
    assert counts["exclusions"] == 2
    assert counts["candidate_supersession_edges"] == 1
    assert counts["exclusion_supersession_edges"] == 1
    assert counts["supersession_edges"] == 2
    assert counts["planned_records"] == 6
    assert plan.report.value["import_plan_digest"] == plan.manifest.digest
    assert plan.report.value["compatibility_version"] == "genesis-first-import-compat-v1"
    assert plan.report.value["parser_schema_versions"] == {
        "scalevault.ingress.genesis-checkpoint.v2": "checkpoint-v2.schema.1"
    }
    assert len(plan.planned_sources) == 1
    assert plan.planned_sources[0].source_item.raw_bytes

    report = plan.report.canonical_bytes
    for private_value in (
        _SOURCE_PATH.encode(),
        b"kivra:genesis",
        b"person:participant",
        b"relationship:private",
        b"interaction:private",
        b"private synthetic statement",
        b"private synthetic evidence",
        b"private-message-reference",
        b"private note",
    ):
        assert private_value not in report
    rendered_plan = repr(plan)
    assert "planned_sources" not in rendered_plan
    assert "private synthetic statement" not in rendered_plan
    assert repr(plan.planned_sources[0]).startswith("<")


def test_plan_is_deterministic_and_safe_report_verifies_exact_digest() -> None:
    first = _plan()
    second = _plan()

    assert first.manifest.canonical_bytes == second.manifest.canonical_bytes
    assert first.report.canonical_bytes == second.report.canonical_bytes
    expected = GenesisPlanReport.from_bytes(first.report.canonical_bytes + b"\n")
    second.verify_report(expected)


def test_verify_report_rejects_content_free_manifest_tampering() -> None:
    plan = _plan()
    tampered = dict(plan.report.value)
    tampered["import_plan_digest"] = "f" * 64
    expected = GenesisPlanReport.from_bytes(canonical_json_bytes(tampered))

    with pytest.raises(GenesisPlanError, match="digest_mismatch"):
        plan.verify_report(expected)


def test_expected_report_rejects_extra_path_or_noncanonical_json() -> None:
    plan = _plan()
    unsafe = dict(plan.report.value)
    unsafe["source_path"] = _SOURCE_PATH

    with pytest.raises(GenesisPlanError, match="invalid_expected_manifest"):
        GenesisPlanReport.from_bytes(canonical_json_bytes(unsafe))
    with pytest.raises(GenesisPlanError, match="invalid_expected_manifest"):
        GenesisPlanReport.from_bytes(b'{"counts": {}, "report_version":"wrong"}')


def test_plan_rejects_dangling_supersession_target() -> None:
    payload = _payload()
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    candidate = candidates[0]
    assert isinstance(candidate, dict)
    candidate["supersedes"] = ["candidate-not-enumerated"]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(GenesisPlanError, match="dangling_supersession"):
        plan_genesis_import(_Reader(raw))
