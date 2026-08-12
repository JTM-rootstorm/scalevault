"""Tenant-scoped, metadata-only operator report queries.

The report intentionally uses a normal tenant transaction and explicit column
lists.  It never selects statements, evidence, sealed envelopes, outbox
payloads, credential verifiers, key references, provider coordinates, or free
form failure text.
"""

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


REPORT_QUERIES = (
    ReportQuery(
        "selection_by_actor_client",
        text(
            """
            SELECT date_trunc('day', decided_at) AS period_start,
                   actor_id, client_id, outcome, count(*) AS count
              FROM selection_decisions
             WHERE decided_at >= :since
             GROUP BY period_start, actor_id, client_id, outcome
             ORDER BY period_start DESC, actor_id, client_id, outcome
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "writes_by_client_profile",
        text(
            """
            SELECT e.client_id, c.transport_kind AS profile, e.operation, count(*) AS count
              FROM memory_events AS e
              JOIN clients AS c ON c.tenant_id = e.tenant_id AND c.client_id = e.client_id
             WHERE e.created_at >= :since
             GROUP BY e.client_id, c.transport_kind, e.operation
             ORDER BY count DESC, e.client_id, e.operation
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "unresolved_conflicts",
        text(
            """
            SELECT conflict_id, lineage_id, branch_id, subject_id, status, opened_at
              FROM memory_conflicts
             WHERE status = 'open'
             ORDER BY opened_at DESC, conflict_id
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "sensitive_and_lifecycle_memory_metadata",
        text(
            """
            SELECT memory_id, lineage_id, branch_id, subject_id, subject_kind,
                   category, scope, visibility, status, sensitivity,
                   content_protection, revision, updated_at
              FROM memories
             WHERE sensitivity >= 3
                OR visibility = 'public_seed'
                OR status IN ('candidate', 'retired', 'tombstoned')
             ORDER BY updated_at DESC, memory_id
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "branch_metadata",
        text(
            """
            SELECT lineage_id, branch_id, parent_branch_id, fork_event_sequence,
                   visibility_ceiling, created_at, sealed_at
              FROM branches
             ORDER BY created_at DESC, branch_id
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "credentials_nearing_expiry",
        text(
            """
            SELECT cc.credential_id, cc.client_id, c.transport_kind AS profile,
                   cc.kind, cc.expires_at, cc.revoked_at
              FROM client_credentials AS cc
              JOIN clients AS c ON c.tenant_id = cc.tenant_id AND c.client_id = cc.client_id
             WHERE cc.revoked_at IS NOT NULL
                OR (cc.expires_at IS NOT NULL AND cc.expires_at <= :expiry_cutoff)
             ORDER BY cc.expires_at NULLS LAST, cc.credential_id
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "queue_status",
        text(
            """
            SELECT job_type, state, count(*) AS count,
                   min(available_at) AS oldest_available_at
              FROM outbox_jobs
             WHERE state IN ('pending', 'leased', 'dead')
             GROUP BY job_type, state
             ORDER BY job_type, state
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "archive_status",
        text(
            """
            SELECT t.archive_target_id, t.state AS target_state,
                   c.state AS checkpoint_state,
                   max(c.last_event_sequence) AS last_event_sequence,
                   max(c.pushed_at) AS last_pushed_at,
                   count(*) FILTER (WHERE c.state = 'failed') AS failed_count
              FROM archive_targets AS t
              LEFT JOIN archive_export_checkpoints AS c
                ON c.tenant_id = t.tenant_id
               AND c.archive_target_id = t.archive_target_id
             GROUP BY t.archive_target_id, t.state, c.state
             ORDER BY t.archive_target_id, c.state
             LIMIT :limit
            """
        ),
    ),
    ReportQuery(
        "consistency_checks",
        text(
            """
            SELECT 'memory_event_sequence' AS check_name,
                   CASE WHEN COALESCE(max(e.sequence), 0) =
                                  COALESCE(max(ec.next_sequence - 1), 0)
                        THEN 'ok' ELSE 'inconsistent' END AS state
              FROM memory_events AS e
              FULL JOIN memory_event_counter AS ec ON ec.counter_id = 1
            UNION ALL
            SELECT 'selection_sequence' AS check_name,
                   CASE WHEN COALESCE(max(s.selection_sequence), 0) =
                                  COALESCE(max(sc.next_sequence - 1), 0)
                        THEN 'ok' ELSE 'inconsistent' END AS state
              FROM selection_decisions AS s
              FULL JOIN selection_decision_counter AS sc ON sc.counter_id = 1
            ORDER BY check_name
            """
        ),
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
            "since": generated_at - timedelta(days=window_days),
            "expiry_cutoff": generated_at + timedelta(days=30),
            "limit": MAX_REPORT_ROWS,
        }
        sections: dict[str, tuple[Mapping[str, object], ...]] = {}
        async with self._database.tenant_session(tenant_id) as session:
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
