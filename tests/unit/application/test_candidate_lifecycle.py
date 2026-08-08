from __future__ import annotations

from datetime import UTC, datetime

from kivra_memory.application.candidate_lifecycle import _LifecycleIdentifiers


def test_lifecycle_retry_allocations_are_stable_per_command() -> None:
    now = datetime(2026, 8, 8, 12, tzinfo=UTC)
    allocations = _LifecycleIdentifiers(evaluated_at=now)

    assert allocations.evaluated_at == now
    assert allocations.decision_id == allocations.decision_id
    assert allocations.event_id == allocations.event_id
    assert allocations.correlation_id == allocations.correlation_id
    assert len(allocations.job_ids) == 2
    assert len(set(allocations.job_ids)) == 2
