from __future__ import annotations

import copy
import json
from collections.abc import Callable
from hashlib import sha256
from typing import Any, cast

import kivra_memory.ingress.validator as validator_module
import pytest
from kivra_memory.ingress.validator import (
    FROZEN_FEDERATION_COMPAT_BLOB_SHA,
    FROZEN_FEDERATION_COMPAT_PATH,
    MAX_INGRESS_BYTES,
    CompatibilityCode,
    IngressFormat,
    IngressValidationError,
    ValidationCode,
    validate_ingress,
)

type Payload = dict[str, Any]


def encoded(payload: Payload) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def proposal_v1() -> Payload:
    return {
        "schema_version": 1,
        "proposal_id": "5ea3ecf3-355e-4ac7-a902-81b09906e09a",
        "installation_id": "cfcdd788-6eba-4ba7-ab89-27536d8892a1",
        "idempotency_key": "synthetic-proposal",
        "operation": "observe",
        "category": "project_state",
        "scope": "project",
        "statement": "synthetic statement",
        "reason_to_remember": "synthetic reason",
        "confidence": "verified",
        "ontology": "literal_technical_fact",
        "interpretation_limits": [],
        "evidence_summary": "synthetic evidence",
        "created_at": "2026-08-06T08:01:00-05:00",
    }


def v1_candidate() -> Payload:
    return {
        "candidate_id": "candidate-v1-synthetic",
        "type": "relationship_memory",
        "summary": "synthetic summary",
        "disposition": "relationship_local",
        "confidence": "explicit",
        "scope": "relationship",
        "ontology": "interaction_convention",
        "why_it_matters": "synthetic reason",
        "evidence": {
            "summary": "synthetic evidence",
            "source_messages": [
                {"speaker": "assistant", "reference": "synthetic reference", "excerpt": None}
            ],
        },
        "interpretation_limits": ["synthetic limit"],
        "review": {
            "eligible_for_scalevault": True,
            "requires_continuant_review": True,
            "recommended_action": "retain_relationship_local",
        },
        "supersedes": [],
    }


def checkpoint_v1() -> Payload:
    return {
        "schema_version": "genesis-checkpoint-v1",
        "checkpoint": {
            "id": "genesis-checkpoint-v1-synthetic",
            "origin_actor": "kivra:genesis",
            "origin_runtime": "chatgpt-web",
            "triggered_by": "person:mike",
            "created_at": "2026-08-06T08:10:00-05:00",
            "previous_checkpoint": None,
            "status": "staged",
            "idempotency_key": "synthetic-v1",
            "source_conversation": {
                "platform": "chatgpt",
                "project": "synthetic",
                "conversation_reference": None,
                "reviewed_range": "synthetic range",
                "raw_transcript_preserved_elsewhere": True,
            },
        },
        "candidates": [v1_candidate()],
        "exclusions": [],
        "notes": ["synthetic only"],
    }


def checkpoint_v2() -> Payload:
    return {
        "schema_version": "genesis-checkpoint-v2",
        "checkpoint": {
            "id": "genesis-checkpoint-v2-synthetic",
            "origin_actor": "kivra:genesis",
            "origin_runtime": "chatgpt-web",
            "triggered_by": "person:requester",
            "created_at": "2026-08-06T10:05:00-05:00",
            "previous_checkpoint": None,
            "status": "staged",
            "idempotency_key": "synthetic-v2",
            "source_conversation": {
                "platform": "chatgpt",
                "project": "synthetic",
                "conversation_reference": None,
                "reviewed_range": "synthetic range",
                "raw_transcript_preserved_elsewhere": True,
            },
        },
        "candidates": [
            {
                "candidate_id": "candidate-v2-synthetic",
                "type": "relationship_memory",
                "summary": "synthetic summary",
                "disposition": "relationship_local",
                "confidence": "explicit",
                "scope": "relationship",
                "ontology": "interaction_convention",
                "why_it_matters": "synthetic reason",
                "binding": {
                    "owner_actor_id": "kivra:genesis",
                    "perspective_actor_id": "kivra:observer",
                    "subject_actor_ids": ["kivra:genesis", "person:participant"],
                    "participant_actor_ids": ["kivra:genesis", "person:participant"],
                    "relationship_ids": ["relationship:synthetic"],
                    "interaction_id": "interaction:synthetic",
                    "visibility": "relationship_local",
                },
                "evidence": {
                    "summary": "synthetic evidence",
                    "source_messages": [
                        {
                            "speaker_actor_id": "person:participant",
                            "reference": "synthetic reference",
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
                "supersedes": [],
            }
        ],
        "exclusions": [
            {
                "exclusion_id": "exclusion-v2-synthetic",
                "claim": "synthetic excluded claim",
                "reason": "synthetic reason",
                "scope": "relationship",
                "applies_to_actor_ids": ["kivra:genesis", "person:participant"],
                "applies_to_relationship_ids": ["relationship:synthetic"],
                "supersedes": [],
            }
        ],
        "notes": ["synthetic only"],
    }


PROPOSAL_PATH = (
    "ingress/v1/cfcdd788-6eba-4ba7-ab89-27536d8892a1/2026/08/"
    "5ea3ecf3-355e-4ac7-a902-81b09906e09a.json"
)
V1_PATH = "ingress/checkpoints/v1/genesis/2026/08/genesis-checkpoint-v1-synthetic.json"
V2_PATH = "ingress/checkpoints/v2/genesis/2026/08/genesis-checkpoint-v2-synthetic.json"


def test_validates_proposal_v1_and_preserves_exact_raw_bytes() -> None:
    raw = b"\n" + encoded(proposal_v1()) + b"\n"

    result = validate_ingress(raw, PROPOSAL_PATH)

    assert result.format is IngressFormat.PROPOSAL_V1
    assert result.source_id == "5ea3ecf3-355e-4ac7-a902-81b09906e09a"
    assert result.raw_bytes is raw


def test_v1_relationship_binding_is_flagged_without_triggered_by_inference() -> None:
    raw = encoded(checkpoint_v1())

    result = validate_ingress(raw, V1_PATH)

    assert result.format is IngressFormat.GENESIS_CHECKPOINT_V1
    assert result.unresolved_legacy_binding_candidate_ids == ("candidate-v1-synthetic",)
    candidates = cast(list[Payload], result.payload["candidates"])
    assert "binding" not in candidates[0]


def test_v2_preserves_distinct_perspective_and_does_not_add_triggered_by() -> None:
    payload = checkpoint_v2()
    result = validate_ingress(
        encoded(payload),
        V2_PATH,
        known_actor_ids={
            "kivra:genesis",
            "kivra:observer",
            "person:participant",
            "person:requester",
        },
        relationship_participants={
            "relationship:synthetic": {"kivra:genesis", "person:participant"}
        },
    )

    candidates = cast(list[Payload], result.payload["candidates"])
    binding = cast(Payload, candidates[0]["binding"])
    assert result.format is IngressFormat.GENESIS_CHECKPOINT_V2
    assert binding["perspective_actor_id"] == "kivra:observer"
    assert binding["participant_actor_ids"] == ["kivra:genesis", "person:participant"]
    assert "person:requester" not in binding["participant_actor_ids"]


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda payload: payload.update(schema_version="future-v9"), ValidationCode.UNKNOWN_FORMAT),
        (
            lambda payload: payload["candidates"][0]["binding"].update(relationship_ids=[]),
            ValidationCode.SCHEMA_INVALID,
        ),
        (
            lambda payload: payload["candidates"][0].update(
                disposition="federation_shared_candidate"
            ),
            ValidationCode.SCHEMA_INVALID,
        ),
    ],
)
def test_unknown_or_out_of_contract_v2_fails_closed(
    mutate: Callable[[Payload], None], code: ValidationCode
) -> None:
    payload = checkpoint_v2()
    mutate(payload)

    with pytest.raises(IngressValidationError) as caught:
        validate_ingress(encoded(payload), V2_PATH)

    assert caught.value.code is code


def test_path_and_payload_version_must_match() -> None:
    with pytest.raises(IngressValidationError) as caught:
        validate_ingress(encoded(checkpoint_v2()), V1_PATH)

    assert caught.value.code is ValidationCode.VERSION_PATH_MISMATCH


def test_frozen_compatibility_is_exact_path_blob_hash_pointer_and_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = checkpoint_v2()
    payload["checkpoint"]["id"] = FROZEN_FEDERATION_COMPAT_PATH.removesuffix(".json").rsplit(
        "/", 1
    )[1]
    payload["candidates"].append(copy.deepcopy(payload["candidates"][0]))
    payload["candidates"][1]["disposition"] = "federation_shared_candidate"
    payload["candidates"][1]["scope"] = "federation"
    payload["candidates"][1]["binding"]["visibility"] = "federation_shared_candidate"
    payload["exclusions"].append(copy.deepcopy(payload["exclusions"][0]))
    payload["exclusions"][0]["scope"] = "federation"
    payload["exclusions"][1]["scope"] = "federation"
    raw = encoded(payload)
    monkeypatch.setattr(
        validator_module,
        "FROZEN_FEDERATION_COMPAT_RAW_SHA256",
        sha256(raw).hexdigest(),
    )

    result = validate_ingress(
        raw,
        FROZEN_FEDERATION_COMPAT_PATH,
        source_git_blob_sha=FROZEN_FEDERATION_COMPAT_BLOB_SHA,
    )

    assert result.compatibility_codes == (CompatibilityCode.FROZEN_FEDERATION_VOCABULARY,)
    candidates = cast(list[Payload], result.payload["candidates"])
    assert candidates[1]["scope"] == "federation"
    with pytest.raises(IngressValidationError) as changed_blob:
        validate_ingress(raw, FROZEN_FEDERATION_COMPAT_PATH, source_git_blob_sha="0" * 40)
    assert changed_blob.value.code is ValidationCode.SCHEMA_INVALID


def test_registry_checks_fail_closed_without_exposing_actor_value() -> None:
    payload = checkpoint_v2()
    sentinel = "person:private-sentinel"
    payload["candidates"][0]["binding"]["perspective_actor_id"] = sentinel

    with pytest.raises(IngressValidationError) as caught:
        validate_ingress(
            encoded(payload),
            V2_PATH,
            known_actor_ids={"kivra:genesis", "person:participant", "person:requester"},
        )

    assert caught.value.code is ValidationCode.ACTOR_UNKNOWN
    assert sentinel not in str(caught.value)
    assert sentinel not in repr(caught.value)


def test_rejects_size_duplicate_names_and_source_id_mismatch() -> None:
    with pytest.raises(IngressValidationError) as oversized:
        validate_ingress(b" " * (MAX_INGRESS_BYTES + 1), PROPOSAL_PATH)
    assert oversized.value.code is ValidationCode.PAYLOAD_TOO_LARGE

    with pytest.raises(IngressValidationError) as duplicate:
        validate_ingress(b'{"schema_version":1,"schema_version":1}', PROPOSAL_PATH)
    assert duplicate.value.code is ValidationCode.INVALID_JSON

    payload = copy.deepcopy(proposal_v1())
    payload["proposal_id"] = "e2ffdc83-20b5-407c-8d36-b75fb882006a"
    with pytest.raises(IngressValidationError) as mismatch:
        validate_ingress(encoded(payload), PROPOSAL_PATH)
    assert mismatch.value.code is ValidationCode.PATH_PAYLOAD_MISMATCH
