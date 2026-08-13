"""Tenant-scoped, metadata-only operator reports through reviewed SQL functions."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy import TextClause, text
from sqlalchemy.ext.asyncio import AsyncSession

REPORT_VERSION = "scalevault-operator-report-v1"
MAX_REPORT_ROWS = 500
FORBIDDEN_REPORT_COLUMNS = frozenset(
    {
        "aad",
        "certificate_sha256",
        "content_key_id",
        "evidence",
        "key_reference",
        "metadata",
        "payload",
        "reason",
        "repository_reference",
        "safe_summary",
        "sealed_ciphertext",
        "sealed_nonce",
        "secret_hash",
        "statement",
    }
)


class TenantDatabase(Protocol):
    def tenant_session(self, tenant_id: UUID) -> AbstractAsyncContextManager[AsyncSession]: ...


@dataclass(frozen=True, slots=True)
class ReportQuery:
    name: str
    statement: TextClause
    tenant_qualifiers: tuple[str, ...]


REPORT_QUERIES = (
    ReportQuery(
        "selection_by_actor_client",
        text(
            """
            SELECT period_start, actor_id, client_id, outcome, count
              FROM public.scalevault_operator_report_selection(
                   :tenant_id, :since, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "writes_by_client_profile",
        text(
            """
            SELECT client_id, profile, operation, count
              FROM public.scalevault_operator_report_writes(
                   :tenant_id, :since, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "unresolved_conflicts",
        text(
            """
            SELECT conflict_id, lineage_id, branch_id, subject_id, status, opened_at
              FROM public.scalevault_operator_report_conflicts(:tenant_id, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "sensitive_and_lifecycle_memory_metadata",
        text(
            """
            SELECT memory_id, lineage_id, branch_id, subject_id, subject_kind,
                   category, scope, visibility, status, sensitivity,
                   content_protection, revision, updated_at
              FROM public.scalevault_operator_report_memories(:tenant_id, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "branch_metadata",
        text(
            """
            SELECT lineage_id, branch_id, parent_branch_id, fork_event_sequence,
                   visibility_ceiling, created_at, sealed_at
              FROM public.scalevault_operator_report_branches(:tenant_id, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "credentials_nearing_expiry",
        text(
            """
            SELECT credential_id, client_id, profile, kind, expires_at, revoked_at
              FROM public.scalevault_operator_report_credentials(
                   :tenant_id, :expiry_cutoff, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "queue_status",
        text(
            """
            SELECT job_type, state, count, oldest_available_at
              FROM public.scalevault_operator_report_queues(:tenant_id, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "archive_status",
        text(
            """
            SELECT archive_target_id, target_state, checkpoint_state,
                   last_event_sequence, last_pushed_at, failed_count
              FROM public.scalevault_operator_report_archive(:tenant_id, :limit)
            """
        ),
        (":tenant_id",),
    ),
    ReportQuery(
        "consistency_checks",
        text(
            """
            SELECT check_name, state
              FROM public.scalevault_operator_report_consistency(:tenant_id)
            """
        ),
        (":tenant_id",),
    ),
)


def _safe_scalar(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    raise TypeError("unsafe_report_value")


@dataclass(frozen=True, slots=True)
class OperatorReport:
    tenant_id: UUID
    generated_at: datetime
    window_days: int
    sections: Mapping[str, tuple[Mapping[str, object], ...]]

    def as_dict(self) -> dict[str, object]:
        return {
            "report_version": REPORT_VERSION,
            "tenant_id": str(self.tenant_id),
            "generated_at": _safe_scalar(self.generated_at),
            "window_days": self.window_days,
            "sections": {name: list(rows) for name, rows in self.sections.items()},
            "external_status": {
                "backup": "status_artifact_required",
                "recovery": "status_artifact_required",
            },
        }


class OperatorReportRepository:
    def __init__(self, database: TenantDatabase) -> None:
        self._database = database

    async def collect(
        self,
        tenant_id: UUID,
        *,
        window_days: int = 30,
        now: datetime | None = None,
    ) -> OperatorReport:
        if window_days < 1 or window_days > 90:
            raise ValueError("invalid_report_window")
        generated_at = (now or datetime.now(UTC)).astimezone(UTC)
        parameters = {
            "tenant_id": tenant_id,
            "since": generated_at - timedelta(days=window_days),
            "expiry_cutoff": generated_at + timedelta(days=30),
            "limit": MAX_REPORT_ROWS,
        }
        sections: dict[str, tuple[Mapping[str, object], ...]] = {}
        async with self._database.tenant_session(tenant_id) as session:
            await session.execute(text("SET LOCAL ROLE kivra_memory_operator_report"))
            for query in REPORT_QUERIES:
                result = await session.execute(query.statement, parameters)
                rows = []
                for row in result.mappings().all():
                    rows.append({str(key): _safe_scalar(value) for key, value in row.items()})
                sections[query.name] = tuple(rows)
        return OperatorReport(tenant_id, generated_at, window_days, sections)


__all__ = [
    "FORBIDDEN_REPORT_COLUMNS",
    "MAX_REPORT_ROWS",
    "REPORT_QUERIES",
    "REPORT_VERSION",
    "OperatorReport",
    "OperatorReportRepository",
    "ReportQuery",
    "TenantDatabase",
]
