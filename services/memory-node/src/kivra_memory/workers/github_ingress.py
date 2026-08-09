"""Bounded concurrent worker for immutable GitHub ingress objects."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from kivra_memory.application.github_ingress import GitHubIngressProcessResult
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.ingress.github_client import GitHubProposalObject
from kivra_memory.storage.github_ingress import GitHubIngressDiscovery


@dataclass(frozen=True, slots=True)
class GitHubIngressWorkItem:
    discovery: GitHubIngressDiscovery
    raw_bytes: bytes


@dataclass(frozen=True, slots=True)
class GitHubIngressIdentity:
    """Pinned local identity attached to every object from one poller."""

    tenant_id: UUID
    transport_binding_id: UUID
    installation_id: UUID
    actor_id: UUID
    client_id: UUID
    repository_id: int
    branch_name: str

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "transport_binding_id",
            "installation_id",
            "actor_id",
            "client_id",
        ):
            require_uuid7(getattr(self, name), field_name=name)
        if isinstance(self.repository_id, bool) or self.repository_id <= 0:
            raise ValueError("repository_id must be a positive integer")
        if not self.branch_name or len(self.branch_name) > 255:
            raise ValueError("branch_name is invalid")


def work_item_from_proposal(
    proposal: GitHubProposalObject,
    *,
    identity: GitHubIngressIdentity,
    discovered_at: datetime,
) -> GitHubIngressWorkItem:
    """Attach trusted local identity to exact bytes returned by the pinned poller."""

    if proposal.repository_id != identity.repository_id:
        raise ValueError("proposal repository does not match the worker pin")
    if hashlib.sha256(proposal.raw_bytes).hexdigest() != proposal.raw_sha256:
        raise ValueError("proposal bytes do not match immutable provenance")
    filename = proposal.path.rsplit("/", 1)[-1]
    if not filename.endswith(".json"):
        raise ValueError("proposal path does not identify a JSON object")
    try:
        ingress_id = UUID(filename.removesuffix(".json"))
    except ValueError:
        raise ValueError("proposal path does not identify an ingress UUID") from None
    require_uuid7(ingress_id, field_name="ingress_id")
    discovery = GitHubIngressDiscovery(
        ingress_id=ingress_id,
        tenant_id=identity.tenant_id,
        transport_binding_id=identity.transport_binding_id,
        installation_id=identity.installation_id,
        actor_id=identity.actor_id,
        client_id=identity.client_id,
        repository_external_id=str(identity.repository_id),
        branch_name=identity.branch_name,
        immutable_path=proposal.path,
        commit_id=proposal.commit_id,
        blob_id=proposal.blob_id,
        discovered_at=discovered_at,
    )
    discovery.validate()
    return GitHubIngressWorkItem(discovery=discovery, raw_bytes=proposal.raw_bytes)


class GitHubIngressProcessor(Protocol):
    async def process(
        self, discovery: GitHubIngressDiscovery, raw_bytes: bytes, /
    ) -> GitHubIngressProcessResult: ...


class GitHubIngressWorker:
    """Process one immutable snapshot batch with bounded fan-out."""

    def __init__(
        self,
        processor: GitHubIngressProcessor,
        *,
        concurrency: int = 8,
        max_process_attempts: int = 5,
        retry_delay_seconds: float = 0.01,
    ) -> None:
        if not 1 <= concurrency <= 50:
            raise ValueError("concurrency must be between one and fifty")
        if not 1 <= max_process_attempts <= 10:
            raise ValueError("max_process_attempts must be between one and ten")
        if retry_delay_seconds < 0 or retry_delay_seconds > 1:
            raise ValueError("retry_delay_seconds must be between zero and one")
        self._processor = processor
        self._concurrency = concurrency
        self._max_process_attempts = max_process_attempts
        self._retry_delay_seconds = retry_delay_seconds

    async def process_batch(
        self, items: tuple[GitHubIngressWorkItem, ...]
    ) -> tuple[GitHubIngressProcessResult, ...]:
        identities = [
            (
                item.discovery.repository_external_id,
                item.discovery.external_object_id,
            )
            for item in items
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("worker batch contains duplicate provider objects")
        semaphore = asyncio.Semaphore(self._concurrency)
        results: list[GitHubIngressProcessResult | None] = [None] * len(items)

        async def process_one(index: int, item: GitHubIngressWorkItem) -> None:
            async with semaphore:
                results[index] = await self._processor.process(item.discovery, item.raw_bytes)

        pending = tuple(range(len(items)))
        for attempt in range(1, self._max_process_attempts + 1):
            async with asyncio.TaskGroup() as tasks:
                for index in pending:
                    tasks.create_task(process_one(index, items[index]))
            retry_indexes: list[int] = []
            for index in pending:
                result = results[index]
                if result is not None and result.disposition == "retry":
                    retry_indexes.append(index)
            pending = tuple(retry_indexes)
            if not pending or attempt == self._max_process_attempts:
                break
            await asyncio.sleep(self._retry_delay_seconds * (2 ** (attempt - 1)))
        if any(result is None for result in results):  # pragma: no cover - TaskGroup invariant
            raise RuntimeError("ingress batch did not produce a result")
        return tuple(result for result in results if result is not None)


__all__ = [
    "GitHubIngressIdentity",
    "GitHubIngressProcessor",
    "GitHubIngressWorkItem",
    "GitHubIngressWorker",
    "work_item_from_proposal",
]
