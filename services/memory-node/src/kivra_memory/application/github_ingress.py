"""Application orchestration for policy-gated live GitHub proposals."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
    SelectionEngine,
    SelectionExecutionError,
    SelectionResult,
)
from kivra_memory.domain.enums import IngressState
from kivra_memory.ingress.runtime import (
    LiveProposalAdapterError,
    adapt_live_proposal,
    transaction_binding_sha256,
)
from kivra_memory.ingress.validator import (
    IngressFormat,
    IngressValidationError,
    validate_ingress,
)
from kivra_memory.storage.github_ingress import (
    GitHubIngressDiscovery,
    GitHubIngressRepository,
    GitHubIngressStorageError,
    IngressRegistration,
)
from kivra_memory.storage.github_revocation import (
    GitHubInstallationEpoch,
    require_active_github_installation,
)
from kivra_memory.storage.transactions import run_serializable_transaction

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_RETRYABLE_SELECTION_CODES = frozenset(
    {"authority_unavailable", "dependency_unavailable", "serialization_exhausted"}
)


class GitHubIngressProcessResult(BaseModel):
    """Content-free worker outcome safe for metrics and control flow."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ingress_id: UUID
    state: IngressState
    disposition: Literal["terminal", "retry", "unchanged"]
    code: str | None = None


class GitHubIngressTransactionParticipant:
    """Terminalize an ingress row in the canonical selection transaction."""

    def __init__(
        self,
        *,
        repository: GitHubIngressRepository,
        discovery: GitHubIngressDiscovery,
        installation_epoch: GitHubInstallationEpoch | None,
        binding_sha256: str,
        clock: Callable[[], datetime],
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", binding_sha256) is None:
            raise ValueError("binding_sha256 is invalid")
        self._repository = repository
        self._discovery = discovery
        self._installation_epoch = installation_epoch
        self._binding_sha256 = binding_sha256
        self._clock = clock

    @property
    def transaction_binding_sha256(self) -> str:
        return self._binding_sha256

    async def authorize(self, session: AsyncSession) -> None:
        """Fence canonical work against revocation before it stages writes."""

        await require_active_github_installation(
            session,
            tenant_id=self._discovery.tenant_id,
            installation_id=self._discovery.installation_id,
            expected_epoch=self._installation_epoch,
        )

    async def stage(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        resolved: ResolvedNominationContext,
        result: SelectionResult,
    ) -> None:
        if resolved.source_kind != "github_proposal":
            raise GitHubIngressStorageError("source_kind_mismatch")
        await self._repository.terminalize(
            session,
            discovery=self._discovery,
            principal=principal,
            command=command,
            result=result,
            processed_at=self._clock(),
            installation_epoch=self._installation_epoch,
        )


class GitHubIngressOrchestrator:
    """Register, validate, nominate, and terminalize one immutable GitHub blob."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        selection_engine: SelectionEngine,
        *,
        repository: GitHubIngressRepository | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._selection_engine = selection_engine
        self._repository = repository or GitHubIngressRepository()
        self._clock = clock

    async def _register(
        self,
        discovery: GitHubIngressDiscovery,
        installation_epoch: GitHubInstallationEpoch | None,
    ) -> IngressRegistration:
        async def operation(session: AsyncSession) -> IngressRegistration:
            return await self._repository.register(
                session, discovery, installation_epoch=installation_epoch
            )

        return await run_serializable_transaction(
            self._session_factory, discovery.tenant_id, operation
        )

    async def _validate(
        self,
        discovery: GitHubIngressDiscovery,
        *,
        idempotency_key: str,
        payload_sha256: bytes,
        installation_epoch: GitHubInstallationEpoch | None,
    ) -> IngressRegistration:
        async def operation(session: AsyncSession) -> IngressRegistration:
            return await self._repository.validate(
                session,
                discovery=discovery,
                idempotency_key=idempotency_key,
                payload_sha256=payload_sha256,
                validated_at=self._clock(),
                installation_epoch=installation_epoch,
            )

        return await run_serializable_transaction(
            self._session_factory, discovery.tenant_id, operation
        )

    async def _quarantine(
        self,
        discovery: GitHubIngressDiscovery,
        *,
        error_code: str,
        installation_epoch: GitHubInstallationEpoch | None,
    ) -> GitHubIngressProcessResult:
        if _SAFE_CODE.fullmatch(error_code) is None:
            error_code = "ingress_invalid"

        async def operation(session: AsyncSession) -> IngressRegistration:
            return await self._repository.quarantine(
                session,
                discovery=discovery,
                error_code=error_code,
                processed_at=self._clock(),
                installation_epoch=installation_epoch,
            )

        registration = await run_serializable_transaction(
            self._session_factory, discovery.tenant_id, operation
        )
        return GitHubIngressProcessResult(
            ingress_id=registration.ingress_id,
            state=registration.state,
            disposition="terminal" if registration.terminal else "unchanged",
            code=error_code,
        )

    async def process(
        self,
        discovery: GitHubIngressDiscovery,
        raw_bytes: bytes,
        /,
        *,
        installation_epoch: GitHubInstallationEpoch | None = None,
    ) -> GitHubIngressProcessResult:
        """Process exact bytes without reflecting payload values in failures."""

        registration = await self._register(discovery, installation_epoch)
        if not registration.same_object:
            return GitHubIngressProcessResult(
                ingress_id=registration.ingress_id,
                state=registration.state,
                disposition="terminal" if registration.canonical_changed else "unchanged",
                code="append_only_violation",
            )
        if registration.terminal:
            return GitHubIngressProcessResult(
                ingress_id=registration.ingress_id,
                state=registration.state,
                disposition="unchanged",
            )

        try:
            validated = validate_ingress(
                raw_bytes,
                discovery.immutable_path,
                source_git_blob_sha=discovery.blob_id,
            )
            if validated.format is not IngressFormat.PROPOSAL_V2:
                raise LiveProposalAdapterError("proposal_version_not_live")
            if UUID(validated.source_id) != discovery.ingress_id:
                raise LiveProposalAdapterError("proposal_identity_mismatch")
            payload_sha256 = hashlib.sha256(raw_bytes).digest()
            binding_sha256 = transaction_binding_sha256(
                ingress_id=discovery.ingress_id,
                installation_id=discovery.installation_id,
                repository_external_id=discovery.repository_external_id,
                immutable_path=discovery.immutable_path,
                commit_id=discovery.commit_id,
                blob_id=discovery.blob_id,
                payload_sha256=payload_sha256,
            )
            command = adapt_live_proposal(
                validated,
                expected_installation_id=discovery.installation_id,
                transaction_binding_sha256=binding_sha256,
            )
        except IngressValidationError as error:
            return await self._quarantine(
                discovery,
                error_code=error.code.value,
                installation_epoch=installation_epoch,
            )
        except (LiveProposalAdapterError, ValueError) as error:
            code = error.code if isinstance(error, LiveProposalAdapterError) else "proposal_invalid"
            return await self._quarantine(
                discovery,
                error_code=code,
                installation_epoch=installation_epoch,
            )

        validation = await self._validate(
            discovery,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            installation_epoch=installation_epoch,
        )
        if validation.terminal:
            return GitHubIngressProcessResult(
                ingress_id=validation.ingress_id,
                state=validation.state,
                disposition="unchanged",
            )

        principal = CommandPrincipal(
            tenant_id=discovery.tenant_id,
            actor_id=discovery.actor_id,
            client_id=discovery.client_id,
            transport_binding_id=discovery.transport_binding_id,
            scopes=frozenset({"memory:propose"}),
            ingress_id=discovery.ingress_id,
        )
        participant = GitHubIngressTransactionParticipant(
            repository=self._repository,
            discovery=discovery,
            installation_epoch=installation_epoch,
            binding_sha256=binding_sha256,
            clock=self._clock,
        )
        try:
            await self._selection_engine.execute(
                principal,
                command,
                transaction_participant=participant,
            )
        except SelectionExecutionError as error:
            if error.code in _RETRYABLE_SELECTION_CODES:
                return GitHubIngressProcessResult(
                    ingress_id=discovery.ingress_id,
                    state=IngressState.VALIDATED,
                    disposition="retry",
                    code=error.code,
                )
            return await self._quarantine(
                discovery,
                error_code=f"selection_{error.code}",
                installation_epoch=installation_epoch,
            )

        # The participant committed the terminal row with the selection result.
        refreshed = await self._register(discovery, installation_epoch)
        return GitHubIngressProcessResult(
            ingress_id=refreshed.ingress_id,
            state=refreshed.state,
            disposition="terminal" if refreshed.terminal else "retry",
            code=None if refreshed.terminal else "terminalization_unavailable",
        )


__all__ = [
    "GitHubIngressOrchestrator",
    "GitHubIngressProcessResult",
    "GitHubIngressTransactionParticipant",
]
