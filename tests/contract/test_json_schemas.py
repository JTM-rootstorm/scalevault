from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest
from jsonschema import ValidationError  # type: ignore[import-untyped]
from kivra_memory.domain.events import MemoryEvent

from scripts.validate_schemas import (
    FIXTURE_DIRECTORY,
    build_registry,
    load_schema,
    load_schema_documents,
    validate_event_payload_identity,
    validate_references,
    validate_repository,
    validator_for,
)


def test_repository_schemas_and_representative_instances_are_valid() -> None:
    assert validate_repository() == 6


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


def test_event_operation_vocabulary_includes_every_replayable_change() -> None:
    schema = load_schema(
        next(path for path in load_schema_documents() if path.name == "memory-event.schema.json")
    )

    assert set(schema["$defs"]["operation"]["enum"]) == {
        "observed",
        "remembered",
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
