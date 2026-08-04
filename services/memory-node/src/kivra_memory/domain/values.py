"""Normalized scalar values shared by events and projections."""

from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated

from pydantic import AfterValidator

from kivra_memory.domain.errors import DomainValidationError

MAX_SCORE_DECIMAL_PLACES = 6


def normalize_unit_score(value: Decimal) -> Decimal:
    """Validate and normalize a fixed-precision semantic score in ``[0, 1]``."""

    if not isinstance(value, Decimal) or not value.is_finite():
        raise DomainValidationError("score must be a finite decimal")
    if value < 0 or value > 1:
        raise DomainValidationError("score must be between zero and one")
    try:
        quantized = value.quantize(Decimal(1).scaleb(-MAX_SCORE_DECIMAL_PLACES))
    except InvalidOperation as error:
        raise DomainValidationError("score precision is invalid") from error
    if quantized != value:
        raise DomainValidationError("score supports at most six decimal places")
    return Decimal(0) if value.is_zero() else value.normalize()


UnitScore = Annotated[Decimal, AfterValidator(normalize_unit_score)]


def normalize_utc_datetime(value: datetime) -> datetime:
    """Require an aware datetime and normalize it to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainValidationError("datetime must include a timezone offset")
    return value.astimezone(UTC)


def format_utc_datetime(value: datetime) -> str:
    """Render a timestamp with exactly six fractional digits and a trailing ``Z``."""

    normalized = normalize_utc_datetime(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
