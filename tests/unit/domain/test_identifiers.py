from uuid import UUID

import pytest
from kivra_memory.domain.errors import InvalidIdentifierError
from kivra_memory.domain.identifiers import (
    MAX_UUID7_RANDOM,
    MAX_UUID7_TIMESTAMP_MS,
    is_uuid7,
    new_uuid7,
    require_uuid7,
)


def test_uuid7_has_expected_rfc_9562_layout() -> None:
    timestamp_ms = 0x0123456789AB
    random_bits = (0xABC << 62) | 0x0123456789ABCDEF

    identifier = new_uuid7(timestamp_ms=timestamp_ms, random_bits=random_bits)

    assert identifier.version == 7
    assert identifier.variant == "specified in RFC 4122"
    assert identifier.int >> 80 == timestamp_ms
    assert (identifier.int >> 64) & 0xFFF == 0xABC
    assert identifier.int & ((1 << 62) - 1) == 0x0123456789ABCDEF
    assert is_uuid7(identifier)
    assert require_uuid7(identifier) is identifier


@pytest.mark.parametrize(
    ("timestamp_ms", "random_bits"),
    [
        (-1, 0),
        (MAX_UUID7_TIMESTAMP_MS + 1, 0),
        (0, -1),
        (0, MAX_UUID7_RANDOM + 1),
        (True, 0),
        (0, False),
    ],
)
def test_uuid7_rejects_values_outside_its_bit_fields(
    timestamp_ms: int,
    random_bits: int,
) -> None:
    with pytest.raises(InvalidIdentifierError):
        new_uuid7(timestamp_ms=timestamp_ms, random_bits=random_bits)


def test_uuid7_validator_rejects_other_uuid_versions_without_rendering_value() -> None:
    uuid4 = UUID("12345678-1234-4234-9234-123456789abc")

    with pytest.raises(InvalidIdentifierError) as caught:
        require_uuid7(uuid4, field_name="event_id")

    assert repr(uuid4) not in str(caught.value)
    assert not is_uuid7(uuid4)
    assert not is_uuid7(str(uuid4))
