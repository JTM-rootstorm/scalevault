"""Explicit runtime composition for the optional sealed-content boundary."""

from __future__ import annotations

import os
import stat
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
        credential = settings.sealed_digest_binding_credential
        if root is None or credential is None:
            raise RuntimeError("invalid_sealed_content_configuration")
        try:
            provider = LocalDirectoryKeyProvider(
                root,
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
    credential = Path(path)
    if (
        not credential.is_absolute()
        or ".." in credential.parts
        or credential.resolve(strict=True) != credential
    ):
        raise ValueError
    descriptor = os.open(credential, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or (required_owner_uid is not None and metadata.st_uid != required_owner_uid)
            or not 32 <= metadata.st_size <= 128
        ):
            raise ValueError
        secret = handle.read(129)
    if len(secret) != metadata.st_size or not 32 <= len(secret) <= 128:
        raise ValueError
    return secret


__all__ = ["SealedRuntime"]
