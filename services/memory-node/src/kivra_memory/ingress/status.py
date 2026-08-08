"""Safe ingress status projection boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import format_utc_datetime, normalize_utc_datetime
from kivra_memory.retrieval.contracts import ReadResultMetadata, ReadWarningCode

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

    contract_version: Literal["mcp-read-v1"]
    ingress_id: UUID

    @field_validator("ingress_id")
    @classmethod
    def validate_ingress_id(cls, value: UUID) -> UUID:
        require_uuid7(value, field_name="ingress_id")
        return value


class IngressStatusPayload(BaseModel):
    """Allowlisted ingress lifecycle fields safe for transport disclosure."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

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

    @field_validator("discovered_at", "validated_at", "processed_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        return normalize_utc_datetime(value) if value is not None else None

    @field_serializer("discovered_at", "validated_at", "processed_at", when_used="json")
    def serialize_time(self, value: datetime | None) -> str | None:
        return format_utc_datetime(value) if value is not None else None


class IngressStatusResult(BaseModel):
    """Closed read success envelope for one ingress lifecycle projection."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"
    tool: Literal["memory_ingress_status"] = "memory_ingress_status"
    result: IngressStatusPayload
    warnings: Annotated[tuple[ReadWarningCode, ...], Field(max_length=8)] = ()
    metadata: ReadResultMetadata = ReadResultMetadata()


__all__ = [
    "IngressErrorCode",
    "IngressState",
    "IngressStatusPayload",
    "IngressStatusQuery",
    "IngressStatusResult",
]
