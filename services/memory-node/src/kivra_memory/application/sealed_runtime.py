"""Explicit runtime composition for the optional sealed-content boundary."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.queries import (
    QueryEmbedder,
    QueryEngine,
    RepositoryFactory,
    SelectionHistoryRepositoryFactory,
    SessionFactory,
)
from kivra_memory.application.sealed_content import (
    HmacSha256SealedDigestBinder,
    SealedDigestBinder,
)
from kivra_memory.application.selection import (
    NominationCommandLike,
    NominationResolver,
    PromotionPrincipalProvider,
    ResolvedNominationContext,
    SelectionEngine,
)
from kivra_memory.config import Settings
from kivra_memory.security.credential_files import read_protected_file
from kivra_memory.security.keys import KeyProvider
from kivra_memory.security.local_key_provider import LocalDirectoryKeyProvider
from kivra_memory.storage.selection_history import SelectionHistoryRepository


@dataclass(frozen=True, slots=True)
class SealedRuntime:
    """One validated provider instance shared by write, read, and purge composition."""

    key_provider: KeyProvider | None
    digest_binder: SealedDigestBinder | None

    def __post_init__(self) -> None:
        if (self.key_provider is None) != (self.digest_binder is None):
            raise RuntimeError("invalid_sealed_content_configuration")

    @classmethod
    def from_settings(cls, settings: Settings) -> SealedRuntime:
        if not settings.sealed_content_enabled:
            return cls(key_provider=None, digest_binder=None)
        root = settings.sealed_key_provider_root
        ledger_root = settings.sealed_destruction_ledger_root
        credential = settings.sealed_digest_binding_credential
        if root is None or ledger_root is None or credential is None:
            raise RuntimeError("invalid_sealed_content_configuration")
        try:
            provider = LocalDirectoryKeyProvider(
                root,
                destruction_ledger_root=ledger_root,
                required_owner_uid=0 if settings.environment == "production" else None,
            )
            digest_binder = HmacSha256SealedDigestBinder(
                _read_digest_binding_secret(
                    credential,
                    required_owner_uid=(
                        os.geteuid() if settings.environment == "production" else None
                    ),
                )
            )
        except Exception:
            raise RuntimeError("invalid_sealed_content_configuration") from None
        return cls(key_provider=provider, digest_binder=digest_binder)

    @property
    def enabled(self) -> bool:
        return self.key_provider is not None and self.digest_binder is not None

    def selection_engine(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        resolver: NominationResolver
        | Callable[
            [CommandPrincipal, NominationCommandLike],
            Awaitable[ResolvedNominationContext],
        ],
        promotion_principal_provider: PromotionPrincipalProvider
        | Callable[[CommandPrincipal, NominationCommandLike, UUID], Awaitable[CommandPrincipal]]
        | None = None,
    ) -> SelectionEngine:
        return SelectionEngine(
            session_factory,
            resolver,
            promotion_principal_provider,
            key_provider=self.key_provider,
            sealed_digest_binder=self.digest_binder,
        )

    def query_engine(
        self,
        session_factory: SessionFactory,
        repository_factory: RepositoryFactory,
        *,
        query_embedder: QueryEmbedder | None = None,
        selection_history_repository_factory: SelectionHistoryRepositoryFactory = (
            SelectionHistoryRepository
        ),
    ) -> QueryEngine:
        return QueryEngine(
            session_factory,
            repository_factory,
            query_embedder=query_embedder,
            selection_history_repository_factory=selection_history_repository_factory,
            key_provider=self.key_provider,
        )


def _read_digest_binding_secret(path: Path, *, required_owner_uid: int | None) -> bytes:
    return read_protected_file(
        path,
        minimum_bytes=32,
        maximum_bytes=128,
        required_owner_uid=required_owner_uid,
    )


__all__ = ["SealedRuntime"]
