"""Bounded canonical Unix-socket boundary for local query embeddings."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Final
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    EmbeddingRuntime,
    EmbeddingRuntimeError,
    validate_embeddings,
)

_REQUEST_VERSION: Final = "scalevault-query-embedding-v1"
_MAX_REQUEST_BYTES: Final = 12 * 1024
_MAX_RESPONSE_BYTES: Final = 32 * 1024


class QueryEmbeddingProtocolError(RuntimeError):
    """A safe failure at the local query-embedding boundary."""


def _decode_canonical_object(raw: bytes, *, maximum: int) -> dict[str, object]:
    if not raw or len(raw) > maximum or raw.endswith(b"\n"):
        raise QueryEmbeddingProtocolError("invalid_message")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise QueryEmbeddingProtocolError("invalid_message") from None
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise QueryEmbeddingProtocolError("invalid_message")
    return value


def encode_query_request(request_id: UUID, tenant_id: UUID, query: str) -> bytes:
    require_uuid7(request_id, field_name="request_id")
    require_uuid7(tenant_id, field_name="tenant_id")
    if not query or len(query) > 8192:
        raise QueryEmbeddingProtocolError("invalid_query")
    return canonical_json_bytes(
        {
            "contract_version": _REQUEST_VERSION,
            "query": query,
            "request_id": str(request_id),
            "tenant_id": str(tenant_id),
        }
    )


def decode_query_request(raw: bytes) -> tuple[UUID, UUID, str]:
    value = _decode_canonical_object(raw, maximum=_MAX_REQUEST_BYTES)
    if set(value) != {"contract_version", "query", "request_id", "tenant_id"}:
        raise QueryEmbeddingProtocolError("invalid_request")
    if value["contract_version"] != _REQUEST_VERSION or not isinstance(value["query"], str):
        raise QueryEmbeddingProtocolError("invalid_request")
    try:
        request_id = UUID(str(value["request_id"]))
        require_uuid7(request_id, field_name="request_id")
        tenant_id = UUID(str(value["tenant_id"]))
        require_uuid7(tenant_id, field_name="tenant_id")
    except (TypeError, ValueError):
        raise QueryEmbeddingProtocolError("invalid_request") from None
    query = value["query"]
    if not query or len(query) > 8192:
        raise QueryEmbeddingProtocolError("invalid_request")
    return request_id, tenant_id, query


def encode_query_response(request_id: UUID, embedding: tuple[float, ...]) -> bytes:
    validated = validate_embeddings((embedding,), expected_count=1)[0]
    return canonical_json_bytes(
        {
            "contract_version": _REQUEST_VERSION,
            "dimension": EMBEDDING_DIMENSION,
            "embedding": list(validated),
            "request_id": str(request_id),
        }
    )


def decode_query_response(raw: bytes, *, request_id: UUID) -> tuple[float, ...]:
    value = _decode_canonical_object(raw, maximum=_MAX_RESPONSE_BYTES)
    if set(value) != {"contract_version", "dimension", "embedding", "request_id"}:
        raise QueryEmbeddingProtocolError("invalid_response")
    if (
        value["contract_version"] != _REQUEST_VERSION
        or value["dimension"] != EMBEDDING_DIMENSION
        or value["request_id"] != str(request_id)
        or not isinstance(value["embedding"], list)
        or any(
            isinstance(item, bool) or not isinstance(item, int | float)
            for item in value["embedding"]
        )
    ):
        raise QueryEmbeddingProtocolError("invalid_response")
    try:
        embedding = tuple(float(item) for item in value["embedding"])
        return validate_embeddings((embedding,), expected_count=1)[0]
    except EmbeddingRuntimeError:
        raise QueryEmbeddingProtocolError("invalid_response") from None


async def query_embedding(
    socket_path: Path, tenant_id: UUID, query: str, *, timeout_seconds: float = 5.0
) -> tuple[float, ...]:
    """Request one embedding without importing the model runtime into the caller."""

    if not 0.1 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 0.1 and 30")
    request_id = new_uuid7()
    request = encode_query_request(request_id, tenant_id, query)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path), timeout=timeout_seconds
        )
        try:
            writer.write(len(request).to_bytes(4, "big") + request)
            await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
            size = int.from_bytes(
                await asyncio.wait_for(reader.readexactly(4), timeout=timeout_seconds), "big"
            )
            if not 1 <= size <= _MAX_RESPONSE_BYTES:
                raise QueryEmbeddingProtocolError("invalid_response")
            response = await asyncio.wait_for(reader.readexactly(size), timeout=timeout_seconds)
        finally:
            writer.close()
            await writer.wait_closed()
    except QueryEmbeddingProtocolError:
        raise
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        raise QueryEmbeddingProtocolError("query_embedding_unavailable") from None
    return decode_query_response(response, request_id=request_id)


class QueryEmbeddingServer:
    """Single-request framed server over a group-restricted Unix-domain socket."""

    def __init__(
        self, socket_path: Path, runtime_for_tenant: Callable[[UUID], EmbeddingRuntime]
    ) -> None:
        self._socket_path = socket_path
        self._runtime_for_tenant = runtime_for_tenant
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        if self._socket_path.exists():
            mode = self._socket_path.lstat().st_mode
            if not stat.S_ISSOCK(mode):
                raise QueryEmbeddingProtocolError("unsafe_socket_path")
            self._socket_path.unlink()
        self._server = await asyncio.start_unix_server(self._handle, path=self._socket_path)
        os.chmod(self._socket_path, 0o660)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._socket_path.exists() and stat.S_ISSOCK(self._socket_path.lstat().st_mode):
            self._socket_path.unlink()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            size = int.from_bytes(await reader.readexactly(4), "big")
            if not 1 <= size <= _MAX_REQUEST_BYTES:
                raise QueryEmbeddingProtocolError("invalid_request")
            raw = await reader.readexactly(size)
            request_id, tenant_id, query = decode_query_request(raw)
            embedding = self._runtime_for_tenant(tenant_id).embed_batch((query,))[0].vector
            response = encode_query_response(request_id, embedding)
            writer.write(len(response).to_bytes(4, "big") + response)
            await writer.drain()
        except (QueryEmbeddingProtocolError, EmbeddingRuntimeError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
