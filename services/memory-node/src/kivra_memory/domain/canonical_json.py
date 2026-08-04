"""RFC 8785 canonical JSON with the ScaleVault v1 normalization profile."""

import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from uuid import UUID

import rfc8785

from kivra_memory.domain.errors import CanonicalJsonError
from kivra_memory.domain.values import format_utc_datetime

MAX_CANONICAL_JSON_DEPTH = 64
MAX_IJSON_INTEGER = (1 << 53) - 1

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


def _validate_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalJsonError("JSON strings cannot contain lone surrogate code points")
    return value


def _normalize_decimal(value: Decimal) -> int | float:
    if not value.is_finite():
        raise CanonicalJsonError("JSON numbers must be finite")
    integral = value.to_integral_value()
    if value == integral:
        return _normalize_integer(int(integral))
    converted = float(value)
    if not math.isfinite(converted) or Decimal(repr(converted)) != value.normalize():
        raise CanonicalJsonError("decimal cannot be represented as an interoperable JSON number")
    return converted


def _normalize_integer(value: int) -> int:
    if not -MAX_IJSON_INTEGER <= value <= MAX_IJSON_INTEGER:
        raise CanonicalJsonError("integer is outside the I-JSON interoperable range")
    return value


def normalize_json_value(value: object, *, max_depth: int = MAX_CANONICAL_JSON_DEPTH) -> JsonValue:
    """Normalize supported domain values into the strict RFC 8785 input model."""

    if isinstance(max_depth, bool) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative integer")
    active_containers: set[int] = set()

    def normalize(item: object, depth: int) -> JsonValue:
        if depth > max_depth:
            raise CanonicalJsonError("JSON value exceeds the maximum nesting depth")
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, UUID):
            return str(item).lower()
        if isinstance(item, datetime):
            return format_utc_datetime(item)
        if isinstance(item, Enum):
            return normalize(item.value, depth)
        if isinstance(item, str):
            return _validate_string(item)
        if isinstance(item, int):
            return _normalize_integer(item)
        if isinstance(item, Decimal):
            return _normalize_decimal(item)
        if isinstance(item, float):
            if not math.isfinite(item):
                raise CanonicalJsonError("JSON numbers must be finite")
            return item
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active_containers:
                raise CanonicalJsonError("cyclic objects are not valid JSON")
            active_containers.add(identity)
            try:
                normalized: dict[str, JsonValue] = {}
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise CanonicalJsonError("JSON object names must be strings")
                    normalized[_validate_string(key)] = normalize(child, depth + 1)
                return normalized
            finally:
                active_containers.remove(identity)
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            identity = id(item)
            if identity in active_containers:
                raise CanonicalJsonError("cyclic arrays are not valid JSON")
            active_containers.add(identity)
            try:
                return [normalize(child, depth + 1) for child in item]
            finally:
                active_containers.remove(identity)
        raise CanonicalJsonError("value is not supported by the canonical JSON profile")

    return normalize(value, 0)


def canonical_json_bytes(value: object) -> bytes:
    """Return ScaleVault-normalized RFC 8785 bytes."""

    normalized = normalize_json_value(value)
    try:
        # The package keeps its recursive JSON union private, while ``JsonValue``
        # above describes the same closed runtime shape.
        return rfc8785.dumps(normalized)
    except rfc8785.CanonicalizationError:
        raise CanonicalJsonError("RFC 8785 canonicalization failed") from None


def sha256_digest(value: bytes) -> bytes:
    """Return the raw SHA-256 digest of canonical or opaque bytes."""

    return sha256(value).digest()


def canonical_payload_hash(payload: Mapping[str, object]) -> bytes:
    """Hash a canonical JSON object payload."""

    return sha256_digest(canonical_json_bytes(payload))


def parse_json_strict(document: str | bytes) -> JsonValue:
    """Parse UTF-8 JSON while rejecting duplicate names and non-I-JSON numbers."""

    if isinstance(document, bytes):
        try:
            source = document.decode("utf-8")
        except UnicodeDecodeError:
            raise CanonicalJsonError("JSON input must be valid UTF-8") from None
    else:
        source = document

    def reject_constant(_: str) -> object:
        raise CanonicalJsonError("JSON numbers must be finite")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalJsonError("JSON object names must be unique")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            source,
            object_pairs_hook=unique_object,
            parse_float=Decimal,
            parse_int=int,
            parse_constant=reject_constant,
        )
    except CanonicalJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise CanonicalJsonError("JSON input is invalid") from None
    return normalize_json_value(parsed)
