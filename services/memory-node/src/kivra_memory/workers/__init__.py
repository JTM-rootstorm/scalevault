"""Idempotent outbox and embedding workers."""

from kivra_memory.workers.candidate_lifecycle import handle_candidate_lifecycle_job
from kivra_memory.workers.embedding_runtime import EmbeddingRuntime
from kivra_memory.workers.github_ingress import (
    GitHubIngressIdentity,
    GitHubIngressWorker,
    GitHubIngressWorkItem,
    work_item_from_proposal,
)
from kivra_memory.workers.query_socket import query_embedding

__all__ = [
    "EmbeddingRuntime",
    "GitHubIngressIdentity",
    "GitHubIngressWorkItem",
    "GitHubIngressWorker",
    "handle_candidate_lifecycle_job",
    "query_embedding",
    "work_item_from_proposal",
]
