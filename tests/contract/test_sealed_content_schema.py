from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from jsonschema import ValidationError  # type: ignore[import-untyped]

from scripts.validate_schemas import (
    FIXTURE_DIRECTORY,
    build_registry,
    load_schema,
    load_schema_documents,
    validator_for,
)

SCHEMA_NAME = "sealed-content-envelope-v1.schema.json"


def _contract() -> tuple[dict[str, Any], dict[str, Any], Any]:
    schemas = load_schema_documents()
    path = next(path for path in schemas if path.name == SCHEMA_NAME)
    return schemas[path], load_schema(FIXTURE_DIRECTORY / SCHEMA_NAME), build_registry(schemas)


def test_sealed_content_fixture_matches_closed_v1_envelope() -> None:
    schema, fixture, registry = _contract()
    validator_for(schema, registry).validate(fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("contract_version", "scalevault.sealed-content-envelope.v2"),
        ("envelope_version", 2),
        ("algorithm", "AES-128-GCM"),
        ("content_key_id", "fb881b02-19a2-45cf-b41e-6011ad486c14"),
        ("nonce", "AAECAwQFBgcICQo="),
        ("ciphertext", "not-base64"),
        ("aad_sha256", "00"),
        ("safe_summary", ""),
    ],
)
def test_sealed_content_schema_rejects_unknown_versions_and_invalid_bounds(
    field: str, value: object
) -> None:
    schema, fixture, registry = _contract()
    changed = deepcopy(fixture)
    changed[field] = value

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(changed)


def test_sealed_content_schema_rejects_unknown_fields() -> None:
    schema, fixture, registry = _contract()
    fixture["provider_reference"] = "must-not-cross-envelope-boundary"

    with pytest.raises(ValidationError):
        validator_for(schema, registry).validate(fixture)
