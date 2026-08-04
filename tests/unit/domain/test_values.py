from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from kivra_memory.domain.errors import DomainValidationError
from kivra_memory.domain.values import (
    UnitScore,
    format_utc_datetime,
    normalize_unit_score,
    normalize_utc_datetime,
)
from pydantic import TypeAdapter, ValidationError


def test_unit_score_is_bounded_normalized_and_fixed_precision() -> None:
    assert normalize_unit_score(Decimal("0.500000")) == Decimal("0.5")
    assert normalize_unit_score(Decimal("-0")) == Decimal(0)
    assert TypeAdapter(UnitScore).validate_python(Decimal("1")) == Decimal(1)


@pytest.mark.parametrize("value", [Decimal("-0.1"), Decimal("1.1"), Decimal("NaN")])
def test_unit_score_rejects_invalid_domain(value: Decimal) -> None:
    with pytest.raises((DomainValidationError, ValidationError)):
        TypeAdapter(UnitScore).validate_python(value)


def test_unit_score_rejects_more_than_six_decimal_places() -> None:
    with pytest.raises(DomainValidationError, match="six decimal"):
        normalize_unit_score(Decimal("0.1234567"))


def test_datetime_normalizes_to_utc_and_exact_microseconds() -> None:
    local = datetime(2026, 8, 3, 12, 45, 0, 12, tzinfo=timezone(-timedelta(hours=5)))

    assert normalize_utc_datetime(local) == datetime(2026, 8, 3, 17, 45, 0, 12, tzinfo=UTC)
    assert format_utc_datetime(local) == "2026-08-03T17:45:00.000012Z"


def test_datetime_rejects_naive_values() -> None:
    with pytest.raises(DomainValidationError, match="timezone"):
        normalize_utc_datetime(datetime(2026, 8, 3))
