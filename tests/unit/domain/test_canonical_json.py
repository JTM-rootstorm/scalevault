from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from uuid import UUID

import pytest
from kivra_memory.domain.canonical_json import (
    MAX_IJSON_INTEGER,
    canonical_json_bytes,
    canonical_payload_hash,
    normalize_json_value,
    parse_json_strict,
)
from kivra_memory.domain.enums import MemoryScope
from kivra_memory.domain.errors import CanonicalJsonError


def test_canonical_json_normalizes_domain_values_before_rfc8785() -> None:
    value = {
        "uuid": UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835cc"),
        "when": datetime(
            2026,
            8,
            3,
            12,
            45,
            0,
            123,
            tzinfo=timezone(-timedelta(hours=5)),
        ),
        "score": Decimal("0.500000"),
        "scope": MemoryScope.PROJECT,
    }

    assert canonical_json_bytes(value) == (
        b'{"scope":"project","score":0.5,'
        b'"uuid":"01936d5a-8c4e-7b12-ae6c-4a41a22835cc",'
        b'"when":"2026-08-03T17:45:00.000123Z"}'
    )


def test_payload_hash_uses_canonical_bytes() -> None:
    payload = {"z": 1, "a": [True, None]}

    assert canonical_payload_hash(payload) == sha256(b'{"a":[true,null],"z":1}').digest()


def test_arrays_preserve_order_while_object_names_are_canonicalized() -> None:
    assert canonical_json_bytes({"z": [3, 2, 1], "a": 0}) == b'{"a":0,"z":[3,2,1]}'


@pytest.mark.parametrize(
    "document",
    [
        '{"duplicate":1,"duplicate":2}',
        '{"number":NaN}',
        '{"number":Infinity}',
        f'{{"number":{MAX_IJSON_INTEGER + 1}}}',
    ],
)
def test_strict_parser_rejects_non_ijson_documents(document: str) -> None:
    with pytest.raises(CanonicalJsonError):
        parse_json_strict(document)


def test_strict_parser_does_not_retain_secret_document_in_exception_chain() -> None:
    secret = '{"statement":"PRIVATE_CANARY",}'

    with pytest.raises(CanonicalJsonError) as caught:
        parse_json_strict(secret)

    assert "PRIVATE_CANARY" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "value",
    [
        {1: "non-string key"},
        {"number": float("nan")},
        {"number": Decimal("0.10000000000000001")},
        {"string": "\ud800"},
        {"bytes": b"not-json"},
    ],
)
def test_normalization_rejects_values_outside_canonical_profile(value: object) -> None:
    with pytest.raises(CanonicalJsonError):
        normalize_json_value(value)


def test_normalization_rejects_cycles_and_excessive_nesting() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(CanonicalJsonError, match="cyclic"):
        normalize_json_value(cyclic)

    nested: object = None
    for _ in range(3):
        nested = [nested]
    with pytest.raises(CanonicalJsonError, match="nesting"):
        normalize_json_value(nested, max_depth=2)


def test_strict_parser_requires_utf8() -> None:
    with pytest.raises(CanonicalJsonError, match="UTF-8"):
        parse_json_strict(b'"\xff"')
