"""Race-safe persistence for the verified GitHub ingress history head."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.storage.models import IngressProviderHead

GITHUB_INGRESS_BOOTSTRAP_COMMIT = "84233835924ade0e3cf26bb995717c880c75ff5c"
GITHUB_INGRESS_BOOTSTRAP_TREE = "2de813150fe3952e6538abc5db9c2254d835a70e"
_OBJECT_ID = re.compile(r"[0-9a-f]{40}")


class GitHubHeadStorageError(RuntimeError):
    """Content-free durable-head persistence failure."""


@dataclass(frozen=True, slots=True)
class GitHubProviderIdentity:
    tenant_id: UUID
    installation_id: UUID
    transport_binding_id: UUID
    repository_id: int
    branch_name: str

    @property
    def repository_external_id(self) -> str:
        return str(self.repository_id)

    def validate(self) -> None:
        require_uuid7(self.tenant_id, field_name="tenant_id")
        require_uuid7(self.installation_id, field_name="installation_id")
        require_uuid7(self.transport_binding_id, field_name="transport_binding_id")
        if isinstance(self.repository_id, bool) or self.repository_id <= 0:
            raise ValueError("repository_id must be a positive integer")
        if (
            not self.branch_name
            or len(self.branch_name) > 255
            or any(character in self.branch_name for character in "\r\n\x00")
        ):
            raise ValueError("branch_name is invalid")


@dataclass(frozen=True, slots=True)
class GitHubProviderHeadState:
    identity: GitHubProviderIdentity
    bootstrap_commit_id: str
    bootstrap_tree_id: str
    last_verified_commit_id: str
    last_verified_tree_id: str
    etag: str | None
    verified_at: datetime


class GitHubProviderHeadRepository:
    """Create and advance one tenant-scoped provider checkpoint."""

    async def load_or_create(
        self,
        session: AsyncSession,
        identity: GitHubProviderIdentity,
        /,
    ) -> GitHubProviderHeadState:
        identity.validate()
        await session.execute(
            insert(IngressProviderHead)
            .values(
                tenant_id=identity.tenant_id,
                provider="github",
                repository_external_id=identity.repository_external_id,
                branch_name=identity.branch_name,
                installation_id=identity.installation_id,
                transport_binding_id=identity.transport_binding_id,
                bootstrap_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                bootstrap_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                last_verified_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                last_verified_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                etag=None,
            )
            .on_conflict_do_nothing(
                index_elements=(
                    IngressProviderHead.tenant_id,
                    IngressProviderHead.provider,
                    IngressProviderHead.repository_external_id,
                    IngressProviderHead.branch_name,
                )
            )
        )
        row = await self._load_locked(session, identity)
        return self._state(row, identity)

    async def advance(
        self,
        session: AsyncSession,
        identity: GitHubProviderIdentity,
        *,
        expected_commit_id: str,
        expected_tree_id: str,
        commit_id: str,
        tree_id: str,
        etag: str | None,
    ) -> GitHubProviderHeadState:
        identity.validate()
        for value in (expected_commit_id, expected_tree_id, commit_id, tree_id):
            if _OBJECT_ID.fullmatch(value) is None:
                raise ValueError("GitHub object ID is invalid")
        if etag is not None and (
            not etag or len(etag) > 1024 or any(character in etag for character in "\r\n\x00")
        ):
            raise ValueError("GitHub ETag is invalid")
        row = await self._load_locked(session, identity)
        database_now = await session.scalar(select(func.current_timestamp()))
        if not isinstance(database_now, datetime):
            raise GitHubHeadStorageError("database_clock_unavailable")
        if (row.last_verified_commit_id == commit_id) != (row.last_verified_tree_id == tree_id):
            raise GitHubHeadStorageError("verified_head_pair_mismatch")
        if row.last_verified_commit_id == commit_id:
            row.etag = etag
            row.verified_at = database_now
            await session.flush()
            return self._state(row, identity)
        if (
            row.last_verified_commit_id != expected_commit_id
            or row.last_verified_tree_id != expected_tree_id
        ):
            raise GitHubHeadStorageError("verified_head_race")
        row.last_verified_commit_id = commit_id
        row.last_verified_tree_id = tree_id
        row.etag = etag
        row.verified_at = database_now
        await session.flush()
        return self._state(row, identity)

    @staticmethod
    async def _load_locked(
        session: AsyncSession,
        identity: GitHubProviderIdentity,
    ) -> IngressProviderHead:
        row = await session.scalar(
            select(IngressProviderHead)
            .where(
                IngressProviderHead.tenant_id == identity.tenant_id,
                IngressProviderHead.provider == "github",
                IngressProviderHead.repository_external_id == identity.repository_external_id,
                IngressProviderHead.branch_name == identity.branch_name,
            )
            .with_for_update()
        )
        if row is None:
            raise GitHubHeadStorageError("verified_head_unavailable")
        if (
            row.installation_id != identity.installation_id
            or row.transport_binding_id != identity.transport_binding_id
            or row.bootstrap_commit_id != GITHUB_INGRESS_BOOTSTRAP_COMMIT
            or row.bootstrap_tree_id != GITHUB_INGRESS_BOOTSTRAP_TREE
        ):
            raise GitHubHeadStorageError("verified_head_identity_mismatch")
        return row

    @staticmethod
    def _state(
        row: IngressProviderHead,
        identity: GitHubProviderIdentity,
    ) -> GitHubProviderHeadState:
        return GitHubProviderHeadState(
            identity=identity,
            bootstrap_commit_id=row.bootstrap_commit_id,
            bootstrap_tree_id=row.bootstrap_tree_id,
            last_verified_commit_id=row.last_verified_commit_id,
            last_verified_tree_id=row.last_verified_tree_id,
            etag=row.etag,
            verified_at=row.verified_at,
        )


__all__ = [
    "GITHUB_INGRESS_BOOTSTRAP_COMMIT",
    "GITHUB_INGRESS_BOOTSTRAP_TREE",
    "GitHubHeadStorageError",
    "GitHubProviderHeadRepository",
    "GitHubProviderHeadState",
    "GitHubProviderIdentity",
]
