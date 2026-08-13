"""Transaction guards for the GitHub installation revocation boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.storage.models import TransportInstallation


class GitHubInstallationRevoked(RuntimeError):
    """Content-free signal that no further ingress processing is authorized."""


@dataclass(frozen=True, slots=True)
class GitHubInstallationEpoch:
    """Identity of the active installation observed before provider I/O."""

    tenant_id: UUID
    installation_id: UUID
    enrolled_at: datetime


async def capture_active_github_installation_epoch(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    installation_id: UUID,
) -> GitHubInstallationEpoch:
    """Capture active installation identity without retaining a database lock."""

    row = (
        await session.execute(
            select(
                TransportInstallation.installation_id,
                TransportInstallation.enrolled_at,
                TransportInstallation.revoked_at,
            ).where(
                TransportInstallation.tenant_id == tenant_id,
                TransportInstallation.installation_id == installation_id,
            )
        )
    ).one_or_none()
    if row is None or row.revoked_at is not None:
        raise GitHubInstallationRevoked("github_installation_revoked")
    return GitHubInstallationEpoch(
        tenant_id=tenant_id,
        installation_id=row.installation_id,
        enrolled_at=row.enrolled_at,
    )


async def check_active_github_installation_epoch(
    session: AsyncSession,
    *,
    epoch: GitHubInstallationEpoch,
) -> None:
    """Recheck an epoch without carrying a lock beyond this short transaction."""

    row = (
        await session.execute(
            select(
                TransportInstallation.installation_id,
                TransportInstallation.enrolled_at,
                TransportInstallation.revoked_at,
            ).where(
                TransportInstallation.tenant_id == epoch.tenant_id,
                TransportInstallation.installation_id == epoch.installation_id,
            )
        )
    ).one_or_none()
    if (
        row is None
        or row.revoked_at is not None
        or row.installation_id != epoch.installation_id
        or row.enrolled_at != epoch.enrolled_at
    ):
        raise GitHubInstallationRevoked("github_installation_revoked")


async def require_active_github_installation(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    installation_id: UUID,
    expected_epoch: GitHubInstallationEpoch | None = None,
) -> None:
    """Take an exclusive row lock and fence every durable ingress mutation."""

    if expected_epoch is not None and (
        expected_epoch.tenant_id != tenant_id or expected_epoch.installation_id != installation_id
    ):
        raise GitHubInstallationRevoked("github_installation_revoked")

    result = await session.execute(
        select(
            TransportInstallation.installation_id,
            TransportInstallation.enrolled_at,
            TransportInstallation.revoked_at,
        )
        .where(
            TransportInstallation.tenant_id == tenant_id,
            TransportInstallation.installation_id == installation_id,
        )
        .with_for_update()
    )
    row = result.one_or_none()
    if (
        row is None
        or row.revoked_at is not None
        or (
            expected_epoch is not None
            and (
                row.installation_id != expected_epoch.installation_id
                or row.enrolled_at != expected_epoch.enrolled_at
            )
        )
    ):
        raise GitHubInstallationRevoked("github_installation_revoked")


__all__ = [
    "GitHubInstallationEpoch",
    "GitHubInstallationRevoked",
    "capture_active_github_installation_epoch",
    "check_active_github_installation_epoch",
    "require_active_github_installation",
]
