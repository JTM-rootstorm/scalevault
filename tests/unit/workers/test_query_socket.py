from __future__ import annotations

import stat
from pathlib import Path

from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    EmbeddingModelContract,
    EmbeddingOutput,
)
from kivra_memory.workers.query_socket import QueryEmbeddingServer, query_embedding


class FakeRuntime:
    contract = EmbeddingModelContract(
        artifact_sha256="00" * 32,
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        upstream_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    )

    def embed_batch(self, texts: object) -> tuple[EmbeddingOutput, ...]:
        del texts
        vector = (1.0,) + (0.0,) * (EMBEDDING_DIMENSION - 1)
        return (EmbeddingOutput(vector=vector, truncated=False),)


async def test_query_embedding_round_trips_over_group_restricted_socket(tmp_path: Path) -> None:
    tenant_id = new_uuid7()
    socket_path = tmp_path / "runtime" / "query.sock"
    server = QueryEmbeddingServer(socket_path, lambda selected: FakeRuntime())
    await server.start()
    try:
        embedding = await query_embedding(socket_path, tenant_id, "Synthetic bounded query.")
        assert len(embedding) == EMBEDDING_DIMENSION
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o660
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) & 0o007 == 0
    finally:
        await server.close()
    assert not socket_path.exists()
