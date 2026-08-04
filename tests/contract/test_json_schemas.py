from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import ValidationError  # type: ignore[import-untyped]

from scripts.validate_schemas import (
    FIXTURE_DIRECTORY,
    build_registry,
    load_schema,
    load_schema_documents,
    validate_references,
    validate_repository,
    validator_for,
)


def test_repository_schemas_and_representative_instances_are_valid() -> None:
    assert validate_repository() == 5


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
