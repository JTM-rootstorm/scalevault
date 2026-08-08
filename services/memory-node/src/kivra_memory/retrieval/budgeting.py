"""Exact conservative model-facing JSON budgeting for read responses."""

from __future__ import annotations

from pydantic import BaseModel

from kivra_memory.domain.canonical_json import canonical_json_bytes

ESTIMATOR_VERSION = "utf8-bytes-upper-bound-v1"
HARD_RESPONSE_BYTE_CEILING = 262_144


class BudgetTooSmallError(ValueError):
    """Safe signal that the minimum valid response cannot fit."""

    code = "budget_too_small"

    def __init__(self) -> None:
        super().__init__("requested budget cannot fit the minimum valid response")


def model_facing_value(value: BaseModel | object) -> object:
    """Return the exact JSON-facing value used by the v1 estimator."""

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def canonical_model_facing_json(value: BaseModel | object) -> bytes:
    return canonical_json_bytes(model_facing_value(value))


def estimate_utf8_upper_bound(value: BaseModel | object) -> int:
    """Count canonical UTF-8 bytes; one byte is one conservative token unit."""

    return len(canonical_model_facing_json(value))


def fits_budget(value: BaseModel | object, *, requested_units: int) -> bool:
    if not 1 <= requested_units <= 1_000_000:
        raise ValueError("requested budget is out of bounds")
    size = estimate_utf8_upper_bound(value)
    return size <= requested_units and size <= HARD_RESPONSE_BYTE_CEILING
