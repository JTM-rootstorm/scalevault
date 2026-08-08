"""Validate checked-in JSON Schemas, references, and representative instances."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterator
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from rfc8785 import dumps as canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = REPOSITORY_ROOT / "schemas"
FIXTURE_DIRECTORY = REPOSITORY_ROOT / "tests" / "contract" / "fixtures" / "json_schemas"
SELECTION_POLICY_PATH = (
    REPOSITORY_ROOT
    / "services"
    / "memory-node"
    / "src"
    / "kivra_memory"
    / "policy"
    / "profiles"
    / "selection-v1.json"
)
SELECTION_POLICY_SHA256 = "b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"

Schema = dict[str, Any]
RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time")  # type: ignore[untyped-decorator]
def is_rfc3339_date_time(value: object) -> bool:
    """Check the RFC 3339 profile required by JSON Schema date-time."""

    if not isinstance(value, str):
        return True
    if RFC3339_DATE_TIME.fullmatch(value) is None:
        return False

    normalized = f"{value[:-1]}+00:00" if value[-1] in {"Z", "z"} else value
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def load_schema(path: Path) -> Schema:
    with path.open(encoding="utf-8") as source:
        # Decimal preserves JSON number semantics for exact multipleOf checks.
        value = json.load(source, parse_float=Decimal)
    if not isinstance(value, dict):
        raise TypeError(f"{path}: root must be an object")
    return value


def iter_references(value: Any) -> Iterator[str]:
    """Yield every JSON Reference declared in a schema document."""

    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            yield reference
        for child in value.values():
            yield from iter_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_references(child)


def load_schema_documents() -> dict[Path, Schema]:
    schema_paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    if not schema_paths:
        raise RuntimeError("no JSON schemas found")

    return {path: load_schema(path) for path in schema_paths}


def build_registry(schema_documents: dict[Path, Schema]) -> Registry[Any]:
    resources: list[tuple[str, Resource[Any]]] = []
    identifiers: set[str] = set()
    for path, schema in schema_documents.items():
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"{path}: non-empty $id is required")
        if identifier in identifiers:
            raise ValueError(f"{path}: duplicate $id {identifier}")
        identifiers.add(identifier)
        resources.append((identifier, Resource.from_contents(schema)))

    return Registry().with_resources(resources)


def validate_references(schema_documents: dict[Path, Schema], registry: Registry[Any]) -> None:
    """Resolve every reference without permitting network retrieval."""

    for path, schema in schema_documents.items():
        identifier = schema["$id"]
        resolver = registry.resolver(base_uri=identifier)
        for reference in iter_references(schema):
            try:
                resolver.lookup(reference)
            except Unresolvable as error:
                raise ValueError(f"{path}: cannot resolve $ref {reference!r}") from error


def validator_for(schema: Schema, registry: Registry[Any]) -> Draft202012Validator:
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FORMAT_CHECKER,
    )


def validate_representative_instances(
    schema_documents: dict[Path, Schema], registry: Registry[Any]
) -> None:
    for path, schema in schema_documents.items():
        fixture_path = (
            SELECTION_POLICY_PATH
            if path.name == "memory-selection-policy-v1.schema.json"
            else FIXTURE_DIRECTORY / path.name
        )
        if not fixture_path.is_file():
            raise RuntimeError(f"{path}: representative fixture is missing: {fixture_path}")

        instance = load_schema(fixture_path)
        errors = sorted(
            validator_for(schema, registry).iter_errors(instance),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            first = errors[0]
            location = "/".join(str(part) for part in first.absolute_path) or "<root>"
            raise ValueError(f"{fixture_path}: {location}: {first.message}")

        if path.name == "memory-event.schema.json":
            validate_event_payload_identity(instance, fixture_path)
        elif path.name == "memory-selection-policy-v1.schema.json":
            digest = hashlib.sha256(canonical_json_bytes(instance)).hexdigest()
            if digest != SELECTION_POLICY_SHA256:
                raise ValueError(f"{fixture_path}: selection policy digest does not match ADR 0013")


def validate_event_payload_identity(instance: Schema, fixture_path: Path) -> None:
    """Verify the representative event's recorded bytes and payload digest."""

    encoded = instance["payload_canonical"]
    if not isinstance(encoded, str):
        raise TypeError(f"{fixture_path}: payload_canonical must be a string")
    try:
        canonical = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{fixture_path}: payload_canonical is not valid base64") from error

    try:
        decoded = json.loads(canonical, parse_float=Decimal)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{fixture_path}: payload_canonical is not JSON") from error
    if decoded != instance["payload"]:
        raise ValueError(f"{fixture_path}: payload_canonical does not decode to payload")

    digest = hashlib.sha256(canonical).hexdigest()
    if digest != instance["payload_sha256"]:
        raise ValueError(f"{fixture_path}: payload_sha256 does not match payload_canonical")


def validate_repository() -> int:
    schema_documents = load_schema_documents()
    registry = build_registry(schema_documents)
    validate_references(schema_documents, registry)
    validate_representative_instances(schema_documents, registry)
    return len(schema_documents)


def main() -> None:
    schema_count = validate_repository()

    print(f"validated {schema_count} JSON schemas and representative instances")


if __name__ == "__main__":
    main()
