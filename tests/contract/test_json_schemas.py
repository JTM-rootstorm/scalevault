from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest
from jsonschema import ValidationError  # type: ignore[import-untyped]
from kivra_memory.domain.events import MemoryEvent
from kivra_memory.policy import SELECTION_V1_PROFILE_SHA256, SelectionPolicyProfile
from kivra_memory.retrieval.budgeting import estimate_utf8_upper_bound
from kivra_memory.retrieval.contracts import ContextPackResult
from kivra_memory.retrieval.ranking import RRF_V1_PROFILE_SHA256
from kivra_memory.seeding.contracts import PrivateSeedBundle

from scripts.validate_schemas import (
    FIXTURE_DIRECTORY,
    SELECTION_POLICY_PATH,
    SELECTION_POLICY_SHA256,
    build_registry,
    load_schema,
    load_schema_documents,
    validate_event_payload_identity,
    validate_references,
    validate_repository,
    validator_for,
)


def test_repository_schemas_and_representative_instances_are_valid() -> None:
    schema_names = {path.name for path in load_schema_documents()}

    assert "export-manifest-v2.schema.json" in schema_names
    assert validate_repository() == len(schema_names)


def test_export_manifest_v2_fixture_has_exact_range_and_canonical_order() -> None:
    manifest = load_schema(FIXTURE_DIRECTORY / "export-manifest-v2.schema.json")
    file_paths = [descriptor["path"] for descriptor in manifest["files"]]
    schema_ids = [descriptor["schema_id"] for descriptor in manifest["schemas"]]
    schema_paths = [descriptor["path"] for descriptor in manifest["schemas"]]

    assert manifest["event_count"] == (
        manifest["last_event_sequence"] - manifest["first_event_sequence"] + 1
    )
    assert manifest["source_high_water_sequence"] >= manifest["last_event_sequence"]
    assert file_paths == sorted(set(file_paths))
    assert schema_ids == sorted(set(schema_ids))
    assert len(schema_paths) == len(set(schema_paths))
    assert manifest["git_commit_sha"] is None


def test_selection_policy_schema_matches_the_canonical_profile() -> None:
    schema_documents = load_schema_documents()
    schema_path = next(
        path for path in schema_documents if path.name == "memory-selection-policy-v1.schema.json"
    )
    profile = load_schema(SELECTION_POLICY_PATH)
    registry = build_registry(schema_documents)

    validator_for(schema_documents[schema_path], registry).validate(profile)
    SelectionPolicyProfile.model_validate_json(SELECTION_POLICY_PATH.read_text(encoding="utf-8"))
    assert SELECTION_V1_PROFILE_SHA256 == SELECTION_POLICY_SHA256


@pytest.mark.parametrize(
    "mutation",
    [
        lambda profile: profile.update({"rules": []}),
        lambda profile: profile["precedence"].reverse(),
        lambda profile: profile["basis_rules"][0].update({"candidate_ttl_days": 10}),
        lambda profile: profile["signal_guardrails"][0].update({"expression": "scope == global"}),
    ],
)
def test_selection_policy_rejects_drift_and_expression_language(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    schema_documents = load_schema_documents()
    schema_path = next(
        path for path in schema_documents if path.name == "memory-selection-policy-v1.schema.json"
    )
    profile = load_schema(SELECTION_POLICY_PATH)
    mutation(profile)
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[schema_path], registry).validate(profile)


def test_private_seed_fixture_matches_strict_operator_local_contract() -> None:
    fixture = FIXTURE_DIRECTORY / "private-seed-v1.schema.json"

    bundle = PrivateSeedBundle.model_validate_json(fixture.read_text(encoding="utf-8"))
    assert bundle.contract_version == "scalevault-private-seed-v1"
    assert bundle.records[0].selector.tenant == "local_operator"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda bundle: bundle["records"][0]["selector"].update(
            {"tenant": "019b0080-0000-7000-8000-000000000102"}
        ),
        lambda bundle: bundle["records"][0]["memory"].update({"visibility": "public_seed"}),
        lambda bundle: bundle["records"][0]["memory"].update({"scope": "scene_local"}),
        lambda bundle: bundle.update({"reviewed": True}),
        lambda bundle: bundle["records"][0]["memory"].update(
            {"authority_class": "explicit_user_statement"}
        ),
    ],
)
def test_private_seed_rejects_deployment_identity_and_self_asserted_trust(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    schema_documents = load_schema_documents()
    schema_path = next(
        path for path in schema_documents if path.name == "private-seed-v1.schema.json"
    )
    bundle = load_schema(FIXTURE_DIRECTORY / schema_path.name)
    mutation(bundle)
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[schema_path], registry).validate(bundle)


def test_dangling_local_reference_is_rejected() -> None:
    schema_documents = load_schema_documents()
    event_path = next(path for path in schema_documents if path.name == "memory-event.schema.json")
    event_schema = deepcopy(schema_documents[event_path])
    event_schema["properties"]["event_id"]["$ref"] = "#/$defs/missing"
    schema_documents[event_path] = event_schema
    registry = build_registry(schema_documents)

    with pytest.raises(ValueError, match=r"cannot resolve \$ref"):
        validate_references(schema_documents, registry)


@pytest.mark.parametrize("field", ["proposal_id", "installation_id"])
def test_uuid_formats_are_enforced(field: str) -> None:
    schema_documents = load_schema_documents()
    proposal_path = next(
        path for path in schema_documents if path.name == "chatgpt-memory-proposal-v1.schema.json"
    )
    proposal = load_schema(FIXTURE_DIRECTORY / proposal_path.name)
    proposal[field] = "not-a-uuid"
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError, match="is not a 'uuid'"):
        validator_for(schema_documents[proposal_path], registry).validate(proposal)


def test_date_time_formats_are_enforced() -> None:
    schema_documents = load_schema_documents()
    proposal_path = next(
        path for path in schema_documents if path.name == "chatgpt-memory-proposal-v1.schema.json"
    )
    proposal = load_schema(FIXTURE_DIRECTORY / proposal_path.name)
    proposal["created_at"] = "03 August 2026"
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError, match="is not a 'date-time'"):
        validator_for(schema_documents[proposal_path], registry).validate(proposal)


@pytest.mark.parametrize(
    ("schema_name", "field"),
    [
        ("memory-event.schema.json", "event_id"),
        ("memory-event.schema.json", "transport_binding_id"),
        ("memory-projection.schema.json", "memory_id"),
    ],
)
def test_canonical_identifiers_require_uuidv7(schema_name: str, field: str) -> None:
    schema_documents = load_schema_documents()
    schema_path = next(path for path in schema_documents if path.name == schema_name)
    instance = load_schema(FIXTURE_DIRECTORY / schema_name)
    instance[field] = "fb881b02-19a2-45cf-b41e-6011ad486c14"
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[schema_path], registry).validate(instance)


def _context_pack_contract() -> tuple[dict[str, Any], dict[str, Any], Any]:
    schema_documents = load_schema_documents()
    schema_path = next(path for path in schema_documents if path.name == "context-pack.schema.json")
    instance = load_schema(FIXTURE_DIRECTORY / schema_path.name)
    return schema_documents[schema_path], instance, build_registry(schema_documents)


def test_context_pack_fixture_matches_transport_neutral_read_contract() -> None:
    fixture_path = FIXTURE_DIRECTORY / "context-pack.schema.json"

    result = ContextPackResult.model_validate_json(fixture_path.read_text(encoding="utf-8"))
    assert result.metadata.retrieval is not None
    assert result.metadata.retrieval.sha256 == RRF_V1_PROFILE_SHA256
    assert result.metadata.budget.used_units == estimate_utf8_upper_bound(result)
    schema, _, registry = _context_pack_contract()
    validator_for(schema, registry).validate(result.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("container_path", "field"),
    [
        (("result", "persona", 0, "score"), "unknown_score"),
        (("result", "persona", 0), "metadata"),
        (("metadata", "retrieval", "channels", "semantic"), "provider_details"),
        (("result",), "tenant_id"),
        (("metadata", "retrieval"), "relay_hostname"),
    ],
)
def test_context_pack_rejects_unknown_or_private_fields(
    container_path: tuple[str | int, ...], field: str
) -> None:
    schema, instance, registry = _context_pack_contract()
    container: Any = instance
    for part in container_path:
        container = container[part]
    container[field] = "forbidden"

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


@pytest.mark.parametrize(
    "identifier_path",
    [
        ("result", "context_pack_id"),
        ("result", "persona", 0, "memory_id"),
        ("result", "persona", 0, "evidence", 0, "evidence_id"),
        ("result", "provenance", 0, "event_id"),
        ("metadata", "retrieval", "active_embedding_model_id"),
    ],
)
def test_context_pack_requires_uuidv7(identifier_path: tuple[str | int, ...]) -> None:
    schema, instance, registry = _context_pack_contract()
    container: Any = instance
    for part in identifier_path[:-1]:
        container = container[part]
    container[identifier_path[-1]] = "fb881b02-19a2-45cf-b41e-6011ad486c14"

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


@pytest.mark.parametrize(
    "field",
    [
        "estimator",
        "requested_units",
        "used_units",
        "serialized_bytes",
        "byte_ceiling",
        "truncated",
        "omission_reasons",
    ],
)
def test_context_pack_requires_complete_budget_metadata(field: str) -> None:
    schema, instance, registry = _context_pack_contract()
    del instance["metadata"]["budget"][field]

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


@pytest.mark.parametrize(
    ("container_path", "field"),
    [
        (("result", "persona", 0), "excerpt"),
        (("result", "persona", 0, "evidence", 0), "statement"),
    ],
)
def test_context_pack_keeps_untrusted_evidence_separate(
    container_path: tuple[str | int, ...], field: str
) -> None:
    schema, instance, registry = _context_pack_contract()
    container: Any = instance
    for part in container_path:
        container = container[part]
    container[field] = "Blended evidence must be rejected."

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


def test_context_pack_requires_untrusted_evidence_marker() -> None:
    schema, instance, registry = _context_pack_contract()
    del instance["result"]["persona"][0]["evidence"][0]["trust"]

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda instance: instance["metadata"]["retrieval"].pop("active_embedding_model_id"),
        lambda instance: instance["metadata"]["retrieval"]["channels"].pop("semantic"),
        lambda instance: instance["metadata"]["retrieval"]["channels"]["semantic"].update(
            {"reason": "provider_internal_error"}
        ),
        lambda instance: instance["warnings"].append("private_diagnostic"),
    ],
)
def test_context_pack_closes_profile_channel_and_warning_vocabulary(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    schema, instance, registry = _context_pack_contract()
    mutation(instance)

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(instance)


def test_event_operation_vocabulary_includes_every_replayable_change() -> None:
    schema = load_schema(
        next(path for path in load_schema_documents() if path.name == "memory-event.schema.json")
    )

    assert set(schema["$defs"]["operation"]["enum"]) == {
        "observed",
        "remembered",
        "candidate_promoted",
        "candidate_expired",
        "revised",
        "evidence_attached",
        "evidence_redacted",
        "linked",
        "unlinked",
        "conflict_opened",
        "conflict_resolved",
        "superseded",
        "retired",
        "tombstoned",
        "branch_created",
        "visibility_changed",
        "payload_purge_completed",
    }


def test_event_payload_is_closed_for_its_operation() -> None:
    schema_documents = load_schema_documents()
    event_path = next(path for path in schema_documents if path.name == "memory-event.schema.json")
    event = load_schema(FIXTURE_DIRECTORY / event_path.name)
    event["payload"]["unexpected"] = True
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[event_path], registry).validate(event)


def test_event_v2_candidate_lifecycle_requires_its_closed_versioned_payload() -> None:
    schema_documents = load_schema_documents()
    event_path = next(path for path in schema_documents if path.name == "memory-event.schema.json")
    event = load_schema(FIXTURE_DIRECTORY / event_path.name)
    after = deepcopy(event["payload"]["memory"])
    after.update({"revision": 2, "status": "active", "candidate_expires_at": None})
    event.update(
        {
            "schema_version": 2,
            "payload_version": 2,
            "operation": "candidate_promoted",
            "expected_revision": 1,
            "payload": {
                "previous_revision": 1,
                "memory": after,
                "selection_decision_id": "01936d5a-8c4e-700c-8000-00000000000c",
                "policy_rule_code": "candidate_repeated_observation",
                "evidence": [],
            },
        }
    )
    registry = build_registry(schema_documents)
    validator = validator_for(schema_documents[event_path], registry)

    validator.validate(event)
    event["schema_version"] = 1
    with pytest.raises(ValidationError):
        validator.validate(event)


def test_event_fixture_canonical_payload_bytes_are_authoritative() -> None:
    fixture_path = FIXTURE_DIRECTORY / "memory-event.schema.json"
    event = load_schema(fixture_path)
    event["payload"]["memory"]["statement"] = "Tampered after canonicalization."

    with pytest.raises(ValueError, match="does not decode to payload"):
        validate_event_payload_identity(event, fixture_path)


def test_event_fixture_matches_the_strict_domain_envelope() -> None:
    fixture_path = FIXTURE_DIRECTORY / "memory-event.schema.json"

    MemoryEvent.model_validate_json(fixture_path.read_text(encoding="utf-8"))


def test_event_requires_canonical_timestamp_profile() -> None:
    schema_documents = load_schema_documents()
    event_path = next(path for path in schema_documents if path.name == "memory-event.schema.json")
    event = load_schema(FIXTURE_DIRECTORY / event_path.name)
    event["created_at"] = "2026-08-03T18:00:00Z"
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[event_path], registry).validate(event)


@pytest.mark.parametrize(
    "mutation",
    [
        {"scope": "scene_local", "origin_session_id": None},
        {
            "visibility": "public_seed",
            "status": "active",
            "sensitivity": 0,
            "publication_approved_at": None,
            "publication_approved_by_actor_id": None,
        },
        {"content_protection": "envelope_encrypted", "content_key_id": None},
        {"subject_kind": "persona"},
        {"visibility": "shareable", "sensitivity": 2},
        {
            "scope": "global",
            "subject_kind": "global",
            "category": "episodic_anchor",
            "ontological_status": "fictional_or_roleplayed_scene",
        },
        {
            "scope": "episodic",
            "subject_kind": "episode",
            "category": "episodic_anchor",
            "ontological_status": "literal_user_fact",
            "origin_session_id": None,
        },
        {"category": "project_decision", "ontological_status": "literal_user_fact"},
    ],
)
def test_projection_rejects_invalid_structural_combinations(mutation: dict[str, object]) -> None:
    schema_documents = load_schema_documents()
    projection_path = next(
        path for path in schema_documents if path.name == "memory-projection.schema.json"
    )
    projection = load_schema(FIXTURE_DIRECTORY / projection_path.name)
    projection.update(mutation)
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[projection_path], registry).validate(projection)


def test_imported_legacy_episode_may_omit_origin_session() -> None:
    schema_documents = load_schema_documents()
    projection_path = next(
        path for path in schema_documents if path.name == "memory-projection.schema.json"
    )
    projection = load_schema(FIXTURE_DIRECTORY / projection_path.name)
    projection.update(
        {
            "scope": "episodic",
            "subject_kind": "episode",
            "category": "episodic_anchor",
            "ontological_status": "literal_user_fact",
            "authority_class": "imported_legacy_memory",
            "origin_session_id": None,
        }
    )
    registry = build_registry(schema_documents)

    validator_for(schema_documents[projection_path], registry).validate(projection)


@pytest.mark.parametrize(
    "mutation",
    [
        {
            "scope": "global",
            "subject_kind": "global",
            "category": "episodic_anchor",
            "ontological_status": "fictional_or_roleplayed_scene",
        },
        {
            "scope": "episodic",
            "subject_kind": "episode",
            "category": "episodic_anchor",
            "ontological_status": "literal_user_fact",
            "origin_session_id": None,
        },
    ],
)
def test_event_after_image_rejects_invalid_scope_context(mutation: dict[str, object]) -> None:
    schema_documents = load_schema_documents()
    event_path = next(path for path in schema_documents if path.name == "memory-event.schema.json")
    event = load_schema(FIXTURE_DIRECTORY / event_path.name)
    event["payload"]["memory"].update(mutation)
    registry = build_registry(schema_documents)

    with pytest.raises(ValidationError):
        validator_for(schema_documents[event_path], registry).validate(event)


@pytest.mark.parametrize(
    ("collection", "stable_key"),
    [
        ("evidence", lambda item: item["evidence_id"]),
        (
            "links",
            lambda item: (
                item["link_type"],
                item["source_memory_id"],
                item["target_memory_id"],
                item["link_id"],
            ),
        ),
        ("conflicts", lambda item: item["conflict_id"]),
        ("conflict_members", lambda item: (item["conflict_id"], item["memory_id"])),
    ],
)
def test_representative_aggregate_uses_documented_stable_order(
    collection: str, stable_key: Callable[[dict[str, Any]], Any]
) -> None:
    aggregate = load_schema(FIXTURE_DIRECTORY / "memory-aggregate-v1.schema.json")
    values = aggregate[collection]

    assert values == sorted(values, key=stable_key)


def test_schema_version_is_a_projection_and_aggregate_boundary_field() -> None:
    projection = load_schema(FIXTURE_DIRECTORY / "memory-projection.schema.json")
    aggregate = load_schema(FIXTURE_DIRECTORY / "memory-aggregate-v1.schema.json")
    event = load_schema(FIXTURE_DIRECTORY / "memory-event.schema.json")

    assert projection["schema_version"] == 1
    assert aggregate["schema_version"] == 1
    assert aggregate["memory"]["schema_version"] == 1
    assert "schema_version" not in event["payload"]["memory"]


def test_event_memory_after_image_matches_projection_fields_without_boundary_version() -> None:
    schema_documents = load_schema_documents()
    projection_path = next(
        path for path in schema_documents if path.name == "memory-projection.schema.json"
    )
    aggregate_path = next(
        path for path in schema_documents if path.name == "memory-aggregate-v1.schema.json"
    )
    projection = schema_documents[projection_path]
    memory_state = schema_documents[aggregate_path]["$defs"]["memory_state"]

    assert set(memory_state["required"]) == set(projection["required"]) - {"schema_version"}
    assert set(memory_state["properties"]) == set(projection["properties"]) - {"schema_version"}
