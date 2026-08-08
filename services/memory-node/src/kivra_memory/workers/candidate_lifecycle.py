"""Outbox handler for policy-gated candidate expiry."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from kivra_memory.application.candidate_lifecycle import (
    CandidateLifecycleEngine,
    CandidateLifecycleExecutionError,
    CandidateLifecycleResult,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.commands import CandidateExpiryCommand
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob


class CandidateLifecycleJobError(RuntimeError):
    """Safe, allowlisted candidate worker failure."""

    def __init__(
        self,
        code: Literal[
            "invalid_job", "dependency_unavailable", "stale_revision", "forbidden", "not_found"
        ],
    ):
        super().__init__(code)
        self.code = code


def _expiry_command(job: ClaimedOutboxJob) -> CandidateExpiryCommand:
    if (
        job.job_type != "expire_candidate"
        or job.aggregate_type != "memory"
        or job.aggregate_id is None
        or set(job.payload) != {"event_id", "memory_id", "memory_version", "selection_decision_id"}
    ):
        raise CandidateLifecycleJobError("invalid_job")
    try:
        memory_id = UUID(str(job.payload["memory_id"]))
        selection_decision_id = UUID(str(job.payload["selection_decision_id"]))
        expected_revision = job.payload["memory_version"]
    except (TypeError, ValueError):
        raise CandidateLifecycleJobError("invalid_job") from None
    if (
        memory_id != job.aggregate_id
        or not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
    ):
        raise CandidateLifecycleJobError("invalid_job")
    try:
        return CandidateExpiryCommand(
            memory_id=memory_id,
            expected_revision=expected_revision,
            selection_decision_id=selection_decision_id,
            policy_rule_code="candidate_expired",
        )
    except (TypeError, ValueError):
        raise CandidateLifecycleJobError("invalid_job") from None


async def handle_candidate_lifecycle_job(
    *,
    job: ClaimedOutboxJob,
    principal: CommandPrincipal,
    engine: CandidateLifecycleEngine,
    now: datetime | None = None,
) -> CandidateLifecycleResult:
    """Validate a leased expiry job and delegate to the transaction engine."""

    if principal.tenant_id != job.tenant_id:
        raise CandidateLifecycleJobError("forbidden")
    command = _expiry_command(job)
    try:
        return await engine.expire(principal, command, now=now)
    except CandidateLifecycleExecutionError as error:
        if error.code == "forbidden":
            raise CandidateLifecycleJobError("forbidden") from error
        if error.code == "not_found":
            raise CandidateLifecycleJobError("not_found") from error
        raise CandidateLifecycleJobError("dependency_unavailable") from error
