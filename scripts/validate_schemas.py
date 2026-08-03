"""Validate every checked-in JSON Schema and its local references."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / "schemas"


def load_schema(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise TypeError(f"{path}: root must be an object")
    return value


def main() -> None:
    schema_paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    if not schema_paths:
        raise RuntimeError("no JSON schemas found")

    identifiers: set[str] = set()
    for path in schema_paths:
        schema = load_schema(path)
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"{path}: non-empty $id is required")
        if identifier in identifiers:
            raise ValueError(f"{path}: duplicate $id {identifier}")
        identifiers.add(identifier)

    print(f"validated {len(schema_paths)} JSON schemas")


if __name__ == "__main__":
    main()
