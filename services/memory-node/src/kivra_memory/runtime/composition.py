"""DB-backed production engine composition for direct private MCP requests."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import PostgresDsn
from starlette.types import ASGIApp

from kivra_memory.application.authentication import BearerAuthenticator
from kivra_memory.application.mutations import CommandPrincipal, MutationEngine
from kivra_memory.application.queries import QueryEngine
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.application.selection import (
    NominationCommandLike,
    SelectionEngine,
    SelectionResult,
)
from kivra_memory.application.status import (
    IngressStatusQuery,
    StatusEngine,
    StatusResponse,
    TransportStatusQuery,
)
from kivra_memory.auth import BearerTokenHasher
from kivra_memory.config import Settings
from kivra_memory.domain.commands import DirectMutationCommand, MutationResponse
from kivra_memory.retrieval.contracts import (
    DirectReadQuery,
    QueryPrincipal,
    ReadQueryV2,
    ReadResponse,
    ReadResponseV2,
)
from kivra_memory.runtime.authentication import (
    DirectBearerAuthenticationMiddleware,
    RequestBearerAuthenticator,
)
from kivra_memory.runtime.nomination import DirectNominationResolver
from kivra_memory.storage.credentials import CredentialRepository
from kivra_memory.storage.database import Database
from kivra_memory.storage.retrieval import RetrievalRepository

type RuntimeReadQuery = DirectReadQuery | ReadQueryV2 | IngressStatusQuery | TransportStatusQuery
type RuntimeReadResponse = ReadResponse | ReadResponseV2 | StatusResponse


@dataclass(frozen=True, slots=True)
class MemoryNodeRuntime:
    """One process-owned composition with request-scoped authority inputs."""

    database: Database
    authenticator: RequestBearerAuthenticator
    mutations: MutationEngine
    nominations: SelectionEngine
    queries: QueryEngine
    status: StatusEngine

    @classmethod
    def compose(
        cls,
        database_url: PostgresDsn,
        *,
        authenticator: RequestBearerAuthenticator,
        sealed_runtime: SealedRuntime,
    ) -> MemoryNodeRuntime:
        database = Database(str(database_url))
        return cls._from_database(
            database,
            authenticator=authenticator,
            sealed_runtime=sealed_runtime,
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        sealed_runtime: SealedRuntime,
    ) -> MemoryNodeRuntime:
        database_url = settings.database_url
        credential = settings.client_token_pepper_credential
        key_id = settings.client_token_pepper_key_id
        if database_url is None or credential is None or key_id is None:
            raise RuntimeError("invalid_runtime_configuration")
        try:
            pepper = _read_client_token_pepper(
                credential,
                required_owner_uid=os.geteuid() if settings.environment == "production" else None,
            )
            database = Database(str(database_url))
            authenticator = BearerAuthenticator(
                CredentialRepository(database.session_factory),
                hashers={key_id: BearerTokenHasher(pepper)},
            )
        except Exception:
            raise RuntimeError("invalid_runtime_configuration") from None
        return cls._from_database(
            database,
            authenticator=authenticator,
            sealed_runtime=sealed_runtime,
        )

    @classmethod
    def _from_database(
        cls,
        database: Database,
        *,
        authenticator: RequestBearerAuthenticator,
        sealed_runtime: SealedRuntime,
    ) -> MemoryNodeRuntime:
        sessions = database.session_factory
        return cls(
            database=database,
            authenticator=authenticator,
            mutations=MutationEngine(sessions),
            nominations=sealed_runtime.selection_engine(
                sessions,
                DirectNominationResolver(),
            ),
            queries=sealed_runtime.query_engine(
                database.tenant_session,
                RetrievalRepository,
            ),
            status=StatusEngine(sessions),
        )

    async def execute_mutation(
        self,
        principal: CommandPrincipal,
        command: DirectMutationCommand,
    ) -> MutationResponse:
        return await self.mutations.execute(principal, command)

    async def execute_nomination(
        self,
        principal: CommandPrincipal,
        command: NominationCommandLike,
    ) -> SelectionResult:
        return await self.nominations.execute(principal, command)

    async def execute_read(
        self,
        principal: QueryPrincipal,
        query: RuntimeReadQuery,
    ) -> RuntimeReadResponse:
        if isinstance(query, IngressStatusQuery):
            return await self.status.ingress_status(principal, query)
        if isinstance(query, TransportStatusQuery):
            return await self.status.transport_status(principal, query)
        return await self.queries.execute(principal, query)

    def authenticate_mcp(self, application: ASGIApp) -> ASGIApp:
        return DirectBearerAuthenticationMiddleware(application, self.authenticator)

    async def dispose(self) -> None:
        await self.database.dispose()


def _read_client_token_pepper(path: Path, *, required_owner_uid: int | None) -> bytes:
    credential = Path(path)
    if (
        not credential.is_absolute()
        or ".." in credential.parts
        or credential.resolve(strict=True) != credential
    ):
        raise ValueError
    descriptor = os.open(credential, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or (required_owner_uid is not None and metadata.st_uid != required_owner_uid)
            or not 32 <= metadata.st_size <= 128
        ):
            raise ValueError
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            secret = handle.read(129)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(secret) != metadata.st_size or not 32 <= len(secret) <= 128:
        raise ValueError
    return secret


__all__ = ["MemoryNodeRuntime", "RuntimeReadQuery", "RuntimeReadResponse"]
