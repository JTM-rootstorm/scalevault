"""Safe transport status projection boundary."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from kivra_memory.domain.enums import TransportKind
from kivra_memory.retrieval.contracts import ReadResultMetadata, ReadWarningCode


class TransportStatusQuery(BaseModel):
    """Selector-free query for the authenticated caller's current transport."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["mcp-read-v1"]


class TransportStatusPayload(BaseModel):
    """Coarse transport health without routing or credential metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    transport_kind: TransportKind
    binding_state: Literal["active"] = "active"
    installation_state: Literal["not_applicable", "active"]
    health_state: Literal["unknown", "healthy", "degraded", "offline"] | None
    freshness: Literal["never", "recent", "stale"]


class TransportStatusResult(BaseModel):
    """Closed read success envelope for the caller's current transport."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"
    tool: Literal["memory_transport_status"] = "memory_transport_status"
    result: TransportStatusPayload
    warnings: tuple[ReadWarningCode, ...] = Field(default=(), max_length=8)
    metadata: ReadResultMetadata = ReadResultMetadata()


__all__ = [
    "TransportStatusPayload",
    "TransportStatusQuery",
    "TransportStatusResult",
]
