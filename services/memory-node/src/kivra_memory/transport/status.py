"""Safe transport status projection boundary."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from kivra_memory.domain.enums import TransportKind


class TransportStatusQuery(BaseModel):
    """Selector-free query for the authenticated caller's current transport."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"


class TransportStatusResult(BaseModel):
    """Coarse transport health without routing or credential metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ok: Literal[True] = True
    contract_version: Literal["mcp-read-v1"] = "mcp-read-v1"
    transport_kind: TransportKind
    binding_state: Literal["active"] = "active"
    installation_state: Literal["not_applicable", "active"]
    health_state: Literal["unknown", "healthy", "degraded", "offline"] | None
    freshness: Literal["never", "recent", "stale"]


__all__ = ["TransportStatusQuery", "TransportStatusResult"]
