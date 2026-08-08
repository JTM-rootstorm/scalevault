from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from kivra_memory.application.candidate_lifecycle import (
    CandidateLifecycleExecutionError,
    CandidateLifecycleResult,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob
from kivra_memory.workers.candidate_lifecycle import (
    CandidateLifecycleJobError,
    handle_candidate_lifecycle_job,
)


async def test_expiry_worker_passes_injected_time_and_accepts_stale_noop() -> None:
    tenant_id = new_uuid7()
    memory_id = new_uuid7()
    decision_id = new_uuid7()
    principal = CommandPrincipal(
        tenant_id=tenant_id,
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=frozenset({"memory.lifecycle.expire"}),
    )
    job = ClaimedOutboxJob(
        job_id=1,
        job_uuid=new_uuid7(),
        tenant_id=tenant_id,
        job_type="expire_candidate",
        aggregate_type="memory",
        aggregate_id=memory_id,
        payload={
            "event_id": str(new_uuid7()),
            "memory_id": str(memory_id),
            "memory_version": 4,
            "selection_decision_id": str(decision_id),
        },
        attempt_count=1,
        max_attempts=8,
        lease_token="candidate-worker:unit",
    )
    engine = AsyncMock()
    engine.expire.return_value = CandidateLifecycleResult(
        operation="expire",
        action="no_op",
        decision_id=decision_id,
        source_decision_id=decision_id,
        memory_id=memory_id,
        revision=5,
        policy_sha256="a" * 64,
        reason_code="stale_revision",
    )
    now = datetime(2026, 8, 8, 12, tzinfo=UTC)

    result = await handle_candidate_lifecycle_job(
        job=job, principal=principal, engine=engine, now=now
    )

    assert result.action == "no_op"
    engine.expire.assert_awaited_once()
    assert engine.expire.await_args.kwargs["now"] == now


@pytest.mark.parametrize(
    ("engine_code", "worker_code"),
    [
        ("forbidden", "forbidden"),
        ("not_found", "not_found"),
        ("serialization_exhausted", "dependency_unavailable"),
        ("validation_failed", "dependency_unavailable"),
    ],
)
async def test_expiry_worker_preserves_terminal_errors_and_sanitizes_retryable_failures(
    engine_code: str, worker_code: str
) -> None:
    tenant_id = new_uuid7()
    memory_id = new_uuid7()
    decision_id = new_uuid7()
    principal = CommandPrincipal(
        tenant_id=tenant_id,
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=frozenset({"memory.lifecycle.expire"}),
    )
    job = ClaimedOutboxJob(
        job_id=1,
        job_uuid=new_uuid7(),
        tenant_id=tenant_id,
        job_type="expire_candidate",
        aggregate_type="memory",
        aggregate_id=memory_id,
        payload={
            "event_id": str(new_uuid7()),
            "memory_id": str(memory_id),
            "memory_version": 1,
            "selection_decision_id": str(decision_id),
        },
        attempt_count=1,
        max_attempts=8,
        lease_token="candidate-worker:error-unit",
    )
    engine = AsyncMock()
    engine.expire.side_effect = CandidateLifecycleExecutionError(engine_code)

    with pytest.raises(CandidateLifecycleJobError) as caught:
        await handle_candidate_lifecycle_job(job=job, principal=principal, engine=engine)

    assert caught.value.code == worker_code
