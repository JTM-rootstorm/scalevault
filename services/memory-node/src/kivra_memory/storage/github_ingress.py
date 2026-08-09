"""Race-safe persistence for immutable GitHub ingress objects."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import NominationCommandLike, SelectionResult
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import IngressState, MemoryStatus
from kivra_memory.domain.fingerprints import exact_memory_fingerprint
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.storage.models import (
    IngressItem,
    IngressProviderViolation,
    Memory,
    MemoryEvent,
)

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PROVENANCE_HASH_DOMAIN = b"scalevault:ingress-provider-provenance:v1\x00"
_TERMINAL_STATES = frozenset(
    {
        IngressState.ACCEPTED.value,
        IngressState.DUPLICATE.value,
        IngressState.CONFLICT.value,
        IngressState.REJECTED.value,
        IngressState.QUARANTINED.value,
    }
)


class GitHubIngressStorageError(RuntimeError):
    """Safe persistence failure that never renders external proposal content."""

    def __init__(self, code: str) -> None:
        if _SAFE_CODE.fullmatch(code) is None:
            raise ValueError("storage error code is invalid")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GitHubIngressDiscovery:
    """Immutable provider provenance known before proposal bytes are parsed."""

    ingress_id: UUID
    tenant_id: UUID
    transport_binding_id: UUID
    installation_id: UUID
    actor_id: UUID
    client_id: UUID
    repository_external_id: str
    branch_name: str
    immutable_path: str
    commit_id: str
    blob_id: str
    discovered_at: datetime

    @property
    def external_object_id(self) -> str:
        return self.immutable_path

    def validate(self) -> None:
        for name in (
            "ingress_id",
            "tenant_id",
            "transport_binding_id",
            "installation_id",
            "actor_id",
            "client_id",
        ):
            require_uuid7(cast(UUID, getattr(self, name)), field_name=name)
        bounded = {
            "repository_external_id": (self.repository_external_id, 255),
            "branch_name": (self.branch_name, 255),
            "immutable_path": (self.immutable_path, 2048),
            "commit_id": (self.commit_id, 255),
            "blob_id": (self.blob_id, 255),
        }
        if any(not value or len(value) > maximum for value, maximum in bounded.values()):
            raise ValueError("discovery provenance is invalid")
        if self.discovered_at.tzinfo is None or self.discovered_at.utcoffset() is None:
            raise ValueError("discovered_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class IngressRegistration:
    ingress_id: UUID
    state: IngressState
    created: bool
    same_object: bool
    canonical_changed: bool

    @property
    def terminal(self) -> bool:
        return self.state.value in _TERMINAL_STATES


class GitHubIngressRepositoryProtocol(Protocol):
    async def register(
        self, session: AsyncSession, discovery: GitHubIngressDiscovery, /
    ) -> IngressRegistration: ...

    async def validate(
        self,
        session: AsyncSession,
        *,
        discovery: GitHubIngressDiscovery,
        idempotency_key: str,
        payload_sha256: bytes,
        validated_at: datetime,
    ) -> IngressRegistration: ...

    async def quarantine(
        self,
        session: AsyncSession,
        *,
        discovery: GitHubIngressDiscovery,
        error_code: str,
        processed_at: datetime,
    ) -> IngressRegistration: ...


def _matches(row: IngressItem, discovery: GitHubIngressDiscovery) -> bool:
    return bool(
        row.ingress_id == discovery.ingress_id
        and row.tenant_id == discovery.tenant_id
        and row.transport_binding_id == discovery.transport_binding_id
        and row.installation_id == discovery.installation_id
        and row.actor_id == discovery.actor_id
        and row.client_id == discovery.client_id
        and row.provider == "github"
        and row.repository_external_id == discovery.repository_external_id
        and row.branch_name == discovery.branch_name
        and row.immutable_path == discovery.immutable_path
        and row.external_object_id == discovery.external_object_id
        and row.commit_id == discovery.commit_id
        and row.blob_id == discovery.blob_id
    )


def _provider_provenance_sha256(value: IngressItem | GitHubIngressDiscovery) -> bytes:
    provider = value.provider if isinstance(value, IngressItem) else "github"
    material = {
        "ingress_id": value.ingress_id,
        "tenant_id": value.tenant_id,
        "transport_binding_id": value.transport_binding_id,
        "installation_id": value.installation_id,
        "actor_id": value.actor_id,
        "client_id": value.client_id,
        "provider": provider,
        "repository_external_id": value.repository_external_id,
        "branch_name": value.branch_name,
        "immutable_path": value.immutable_path,
        "external_object_id": value.external_object_id,
        "commit_id": value.commit_id,
        "blob_id": value.blob_id,
    }
    return hashlib.sha256(_PROVENANCE_HASH_DOMAIN + canonical_json_bytes(material)).digest()


class GitHubIngressRepository:
    """Stage ingress state transitions inside caller-owned transactions."""

    async def _load_locked(
        self, session: AsyncSession, discovery: GitHubIngressDiscovery
    ) -> IngressItem:
        row = await session.scalar(
            select(IngressItem)
            .where(
                IngressItem.provider == "github",
                IngressItem.repository_external_id == discovery.repository_external_id,
                IngressItem.external_object_id == discovery.external_object_id,
            )
            .with_for_update()
        )
        if row is None:
            raise GitHubIngressStorageError("registration_unavailable")
        return row

    @staticmethod
    async def _record_provider_violation(
        session: AsyncSession,
        *,
        row: IngressItem,
        discovery: GitHubIngressDiscovery,
    ) -> None:
        expected_sha256 = _provider_provenance_sha256(row)
        observed_sha256 = _provider_provenance_sha256(discovery)
        if expected_sha256 == observed_sha256:
            raise GitHubIngressStorageError("provenance_audit_invalid")
        await session.execute(
            insert(IngressProviderViolation)
            .values(
                tenant_id=row.tenant_id,
                ingress_id=row.ingress_id,
                violation_code="append_only_violation",
                expected_provenance_sha256=expected_sha256,
                observed_provenance_sha256=observed_sha256,
            )
            .on_conflict_do_nothing(
                index_elements=(
                    IngressProviderViolation.tenant_id,
                    IngressProviderViolation.ingress_id,
                    IngressProviderViolation.violation_code,
                    IngressProviderViolation.expected_provenance_sha256,
                    IngressProviderViolation.observed_provenance_sha256,
                )
            )
        )

    async def register(
        self, session: AsyncSession, discovery: GitHubIngressDiscovery, /
    ) -> IngressRegistration:
        discovery.validate()
        statement = (
            insert(IngressItem)
            .values(
                ingress_id=discovery.ingress_id,
                tenant_id=discovery.tenant_id,
                transport_binding_id=discovery.transport_binding_id,
                installation_id=discovery.installation_id,
                actor_id=discovery.actor_id,
                client_id=discovery.client_id,
                provider="github",
                repository_external_id=discovery.repository_external_id,
                branch_name=discovery.branch_name,
                immutable_path=discovery.immutable_path,
                external_object_id=discovery.external_object_id,
                commit_id=discovery.commit_id,
                blob_id=discovery.blob_id,
                declared_idempotency_key=None,
                payload_sha256=None,
                discovered_at=discovery.discovered_at,
            )
            .on_conflict_do_nothing(
                index_elements=(
                    IngressItem.provider,
                    IngressItem.repository_external_id,
                    IngressItem.external_object_id,
                )
            )
            .returning(IngressItem.ingress_id)
        )
        created_id = await session.scalar(statement)
        row = await self._load_locked(session, discovery)
        same_object = _matches(row, discovery)
        canonical_changed = created_id is not None
        if not same_object:
            await self._record_provider_violation(session, row=row, discovery=discovery)
        if not same_object and row.state not in _TERMINAL_STATES:
            row.state = IngressState.QUARANTINED.value
            row.error_code = "append_only_violation"
            row.processed_at = datetime.now(UTC)
            await session.flush()
            canonical_changed = True
        return IngressRegistration(
            ingress_id=row.ingress_id,
            state=IngressState(row.state),
            created=created_id is not None,
            same_object=same_object,
            canonical_changed=canonical_changed,
        )

    async def validate(
        self,
        session: AsyncSession,
        *,
        discovery: GitHubIngressDiscovery,
        idempotency_key: str,
        payload_sha256: bytes,
        validated_at: datetime,
    ) -> IngressRegistration:
        if not idempotency_key or len(idempotency_key) > 255 or len(payload_sha256) != 32:
            raise GitHubIngressStorageError("semantic_identity_invalid")
        row = await self._load_locked(session, discovery)
        if not _matches(row, discovery):
            raise GitHubIngressStorageError("append_only_violation")
        if row.state in _TERMINAL_STATES:
            return IngressRegistration(
                ingress_id=row.ingress_id,
                state=IngressState(row.state),
                created=False,
                same_object=True,
                canonical_changed=False,
            )
        canonical_changed = False
        if row.state == IngressState.VALIDATED.value:
            if (
                row.declared_idempotency_key != idempotency_key
                or row.payload_sha256 != payload_sha256
            ):
                raise GitHubIngressStorageError("semantic_identity_mismatch")
        elif row.state == IngressState.DISCOVERED.value:
            row.declared_idempotency_key = idempotency_key
            row.payload_sha256 = payload_sha256
            row.state = IngressState.VALIDATED.value
            row.validated_at = validated_at
            await session.flush()
            canonical_changed = True
        else:
            raise GitHubIngressStorageError("state_invalid")
        return IngressRegistration(
            ingress_id=row.ingress_id,
            state=IngressState(row.state),
            created=False,
            same_object=True,
            canonical_changed=canonical_changed,
        )

    async def quarantine(
        self,
        session: AsyncSession,
        *,
        discovery: GitHubIngressDiscovery,
        error_code: str,
        processed_at: datetime,
    ) -> IngressRegistration:
        if _SAFE_CODE.fullmatch(error_code) is None:
            raise ValueError("quarantine error code is invalid")
        row = await self._load_locked(session, discovery)
        if row.state in _TERMINAL_STATES:
            return IngressRegistration(
                ingress_id=row.ingress_id,
                state=IngressState(row.state),
                created=False,
                same_object=_matches(row, discovery),
                canonical_changed=False,
            )
        row.state = IngressState.QUARANTINED.value
        row.error_code = error_code
        row.safe_diagnostic = None
        row.processed_at = processed_at
        await session.flush()
        return IngressRegistration(
            ingress_id=row.ingress_id,
            state=IngressState(row.state),
            created=False,
            same_object=_matches(row, discovery),
            canonical_changed=True,
        )

    async def terminalize(
        self,
        session: AsyncSession,
        *,
        discovery: GitHubIngressDiscovery,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        result: SelectionResult,
        processed_at: datetime,
    ) -> None:
        row = await self._load_locked(session, discovery)
        if row.state in _TERMINAL_STATES:
            return
        if (
            not _matches(row, discovery)
            or row.state != IngressState.VALIDATED.value
            or row.ingress_id != principal.ingress_id
            or row.tenant_id != principal.tenant_id
            or row.actor_id != principal.actor_id
            or row.client_id != principal.client_id
            or row.transport_binding_id != principal.transport_binding_id
            or row.declared_idempotency_key != command.idempotency_key
        ):
            raise GitHubIngressStorageError("validated_binding_mismatch")

        row.processed_at = processed_at
        if result.outcome in {"candidate", "active", "promoted"}:
            if result.event_id is None or result.memory_id is None:
                raise GitHubIngressStorageError("selection_result_invalid")
            row.state = IngressState.ACCEPTED.value
            row.result_event_id = result.event_id
            row.result_memory_id = result.memory_id
            row.error_code = None
        elif result.outcome == "omit" and set(result.reason_codes) & {
            "already_covered",
            "already_candidate",
        }:
            linked = await self._find_duplicate_link(session, principal=principal, command=command)
            if linked is None:
                raise GitHubIngressStorageError("duplicate_link_unavailable")
            row.state = IngressState.DUPLICATE.value
            row.result_event_id, row.result_memory_id = linked
            row.error_code = None
        else:
            row.state = IngressState.REJECTED.value
            row.result_event_id = None
            row.result_memory_id = None
            row.error_code = (
                "selection_rejected" if result.outcome == "reject" else "selection_omitted"
            )
        row.safe_diagnostic = None
        await session.flush()

    @staticmethod
    async def _find_duplicate_link(
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
    ) -> tuple[UUID, UUID] | None:
        proposal = command.proposal
        fingerprint = bytes.fromhex(
            exact_memory_fingerprint(
                statement=proposal.statement,
                category=proposal.category,
                ontological_status=proposal.ontological_status,
                scope=proposal.scope,
                interpretation_limits=proposal.interpretation_limits,
            ).sha256_hex
        )
        memory = await session.scalar(
            select(Memory).where(
                Memory.tenant_id == principal.tenant_id,
                Memory.branch_id == command.branch_id,
                Memory.subject_id == proposal.subject_id,
                Memory.normalized_fingerprint == fingerprint,
                Memory.status.in_((MemoryStatus.CANDIDATE.value, MemoryStatus.ACTIVE.value)),
            )
        )
        if memory is None:
            return None
        event_id = await session.scalar(
            select(MemoryEvent.event_id)
            .where(
                MemoryEvent.tenant_id == principal.tenant_id,
                MemoryEvent.lineage_id == memory.lineage_id,
                MemoryEvent.memory_id == memory.memory_id,
                MemoryEvent.operation.in_(("observed", "remembered")),
            )
            .order_by(MemoryEvent.sequence)
            .limit(1)
        )
        return (event_id, memory.memory_id) if event_id is not None else None


__all__ = [
    "GitHubIngressDiscovery",
    "GitHubIngressRepository",
    "GitHubIngressRepositoryProtocol",
    "GitHubIngressStorageError",
    "IngressRegistration",
]
