"""Authorized, transport-neutral status reads with safe projections."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Select, and_, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.enums import TransportKind
from kivra_memory.ingress.status import (
    IngressErrorCode,
    IngressState,
    IngressStatusQuery,
    IngressStatusResult,
)
from kivra_memory.retrieval.contracts import ReadError, ReadErrorBody
from kivra_memory.storage.models import (
    Actor,
    Client,
    IngressItem,
    TransportBinding,
    TransportInstallation,
)
from kivra_memory.transport.status import TransportStatusQuery, TransportStatusResult

STATUS_CONTRACT_VERSION = "mcp-read-v1"
_RECENT_WINDOW = timedelta(minutes=5)


StatusError = ReadError
StatusErrorBody = ReadErrorBody


type StatusResponse = IngressStatusResult | TransportStatusResult | StatusError


def _error(code: Literal["forbidden", "not_found", "internal_error"]) -> StatusError:
    return StatusError(
        error=StatusErrorBody(code=code, message=StatusErrorBody.SAFE_MESSAGES[code])
    )


class _TransportRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    transport_kind: TransportKind
    installation_id: UUID | None
    health_state: Literal["unknown", "healthy", "degraded", "offline"] | None
    last_seen_at: datetime | None


def _current_transport_statement(
    principal: CommandPrincipal, now: datetime
) -> Select[tuple[str, UUID | None, str, datetime | None]]:
    return (
        select(
            TransportBinding.transport_kind,
            TransportBinding.installation_id,
            TransportInstallation.health_state,
            TransportInstallation.last_seen_at,
        )
        .join(
            Actor,
            and_(
                Actor.tenant_id == TransportBinding.tenant_id,
                Actor.actor_id == TransportBinding.actor_id,
            ),
        )
        .join(
            Client,
            and_(
                Client.tenant_id == TransportBinding.tenant_id,
                Client.client_id == TransportBinding.client_id,
                Client.transport_kind == TransportBinding.transport_kind,
            ),
        )
        .outerjoin(
            TransportInstallation,
            and_(
                TransportInstallation.tenant_id == TransportBinding.tenant_id,
                TransportInstallation.installation_id == TransportBinding.installation_id,
            ),
        )
        .where(
            TransportBinding.tenant_id == principal.tenant_id,
            TransportBinding.transport_binding_id == principal.transport_binding_id,
            TransportBinding.actor_id == principal.actor_id,
            TransportBinding.client_id == principal.client_id,
            Actor.revoked_at.is_(None),
            Client.revoked_at.is_(None),
            or_(TransportBinding.valid_until.is_(None), TransportBinding.valid_until > now),
            or_(
                TransportBinding.installation_id.is_(None),
                and_(
                    TransportInstallation.installation_id.is_not(None),
                    TransportInstallation.revoked_at.is_(None),
                ),
            ),
        )
    )


class StatusEngine:
    """Execute bounded status reads for an authenticated principal."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock or (lambda: datetime.now(UTC))

    @asynccontextmanager
    async def _tenant_session(self, tenant_id: UUID) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session, session.begin():
            await session.execute(
                text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            yield session

    async def _current_transport(
        self, session: AsyncSession, principal: CommandPrincipal, now: datetime
    ) -> _TransportRow | None:
        row = (await session.execute(_current_transport_statement(principal, now))).one_or_none()
        if row is None:
            return None
        return _TransportRow(
            transport_kind=TransportKind(row.transport_kind),
            installation_id=row.installation_id,
            health_state=row.health_state,
            last_seen_at=row.last_seen_at,
        )

    async def ingress_status(
        self, principal: CommandPrincipal, query: IngressStatusQuery
    ) -> StatusResponse:
        proposal_access = "memory:propose" in principal.scopes
        status_access = "memory.status.ingress" in principal.scopes
        if not proposal_access and not status_access:
            return _error("forbidden")
        if proposal_access and not status_access and principal.ingress_id != query.ingress_id:
            return _error("not_found")

        now = self._clock()
        try:
            async with self._tenant_session(principal.tenant_id) as session:
                if await self._current_transport(session, principal, now) is None:
                    return _error("not_found")
                predicates = [
                    IngressItem.tenant_id == principal.tenant_id,
                    IngressItem.ingress_id == query.ingress_id,
                    IngressItem.actor_id == principal.actor_id,
                ]
                if not status_access:
                    predicates.extend(
                        [
                            IngressItem.transport_binding_id == principal.transport_binding_id,
                            IngressItem.client_id == principal.client_id,
                        ]
                    )
                row = (
                    await session.execute(
                        select(
                            IngressItem.ingress_id,
                            IngressItem.state,
                            IngressItem.result_event_id,
                            IngressItem.result_memory_id,
                            IngressItem.error_code,
                            IngressItem.discovered_at,
                            IngressItem.validated_at,
                            IngressItem.processed_at,
                        ).where(*predicates)
                    )
                ).one_or_none()
                if row is None:
                    return _error("not_found")
                public_error = (
                    cast(IngressErrorCode, row.state)
                    if row.error_code is not None
                    and row.state in {"conflict", "rejected", "quarantined"}
                    else None
                )
                return IngressStatusResult(
                    ingress_id=row.ingress_id,
                    state=cast(IngressState, row.state),
                    result_event_id=row.result_event_id,
                    result_memory_id=row.result_memory_id,
                    error_code=public_error,
                    discovered_at=row.discovered_at,
                    validated_at=row.validated_at,
                    processed_at=row.processed_at,
                )
        except Exception:
            return _error("internal_error")

    async def transport_status(
        self,
        principal: CommandPrincipal,
        query: TransportStatusQuery | None = None,
    ) -> StatusResponse:
        del query
        if "memory.status.transport" not in principal.scopes:
            return _error("forbidden")
        now = self._clock()
        try:
            async with self._tenant_session(principal.tenant_id) as session:
                transport = await self._current_transport(session, principal, now)
                if transport is None:
                    return _error("not_found")
                if transport.last_seen_at is None:
                    freshness: Literal["never", "recent", "stale"] = "never"
                elif transport.last_seen_at >= now - _RECENT_WINDOW:
                    freshness = "recent"
                else:
                    freshness = "stale"
                installed = transport.installation_id is not None
                return TransportStatusResult(
                    transport_kind=transport.transport_kind,
                    installation_state="active" if installed else "not_applicable",
                    health_state=transport.health_state if installed else None,
                    freshness=freshness if installed else "never",
                )
        except Exception:
            return _error("internal_error")


__all__ = [
    "STATUS_CONTRACT_VERSION",
    "IngressStatusQuery",
    "IngressStatusResult",
    "StatusEngine",
    "StatusError",
    "StatusErrorBody",
    "StatusResponse",
    "TransportStatusQuery",
    "TransportStatusResult",
]
