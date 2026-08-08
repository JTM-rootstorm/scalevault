"""Safe ingress status projection boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kivra_memory.domain.identifiers import require_uuid7

IngressState = Literal[
    "discovered",
    "validated",
    "accepted",
    "duplicate",
    "conflict",
    "rejected",
    "quarantined",
]
IngressErrorCode = Literal["conflict", "rejected", "quarantined"]


class IngressStatusQuery(BaseModel):
    """Opaque ingress identifier supplied by an authenticated status caller."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"
    ingress_id: UUID

    @field_validator("ingress_id")
    @classmethod
    def validate_ingress_id(cls, value: UUID) -> UUID:
        require_uuid7(value, field_name="ingress_id")
        return value


class IngressStatusResult(BaseModel):
    """Allowlisted ingress lifecycle fields safe for transport disclosure."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"
    ingress_id: UUID
    state: IngressState
    result_event_id: UUID | None
    result_memory_id: UUID | None
    error_code: Annotated[IngressErrorCode, Field(min_length=1, max_length=64)] | None
    discovered_at: datetime
    validated_at: datetime | None
    processed_at: datetime | None

    @field_validator("ingress_id", "result_event_id", "result_memory_id")
    @classmethod
    def validate_identifiers(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value


__all__ = ["IngressErrorCode", "IngressState", "IngressStatusQuery", "IngressStatusResult"]
