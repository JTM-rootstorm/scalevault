from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st
from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.identifiers import MAX_UUID7_RANDOM, is_uuid7, new_uuid7


@given(
    timestamp_ms=st.integers(min_value=0, max_value=(1 << 48) - 1),
    random_bits=st.integers(min_value=0, max_value=MAX_UUID7_RANDOM),
)
def test_uuid7_round_trips_all_bit_fields(timestamp_ms: int, random_bits: int) -> None:
    identifier = new_uuid7(timestamp_ms=timestamp_ms, random_bits=random_bits)

    assert is_uuid7(identifier)
    assert identifier.int >> 80 == timestamp_ms
    assert ((identifier.int >> 64) & 0xFFF) == random_bits >> 62
    assert identifier.int & ((1 << 62) - 1) == random_bits & ((1 << 62) - 1)


@given(score=st.integers(min_value=0, max_value=1_000_000))
def test_fixed_six_decimal_scores_have_stable_canonical_round_trip(score: int) -> None:
    value = Decimal(score).scaleb(-6)
    canonical = canonical_json_bytes({"score": value})

    assert canonical_json_bytes(parse_json_strict(canonical)) == canonical
