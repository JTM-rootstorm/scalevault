"""Transaction guard for the GitHub installation revocation boundary."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.storage.models import TransportInstallation


class GitHubInstallationRevoked(RuntimeError):
    """Content-free signal that no further ingress processing is authorized."""


async def require_active_github_installation(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    installation_id: UUID,
) -> None:
    """Hold a share lock that makes durable revocation a full processing fence."""

    result = await session.execute(
        select(TransportInstallation.installation_id, TransportInstallation.revoked_at)
        .where(
            TransportInstallation.tenant_id == tenant_id,
            TransportInstallation.installation_id == installation_id,
        )
        .with_for_update(read=True)
    )
    row = result.one_or_none()
    if row is None or row.revoked_at is not None:
        raise GitHubInstallationRevoked("github_installation_revoked")


__all__ = ["GitHubInstallationRevoked", "require_active_github_installation"]
