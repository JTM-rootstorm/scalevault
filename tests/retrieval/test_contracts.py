from __future__ import annotations

from datetime import timedelta

import pytest
from kivra_memory.domain.enums import EventOperation
from kivra_memory.retrieval.contracts import (
    ContextPackQuery,
    MemoryGetQuery,
    MemorySelectionDecisionsQuery,
    MemoryTimelineQuery,
    QueryPrincipal,
    SelectionDecisionView,
    SelectionEventRecord,
    TimeWindow,
)
from pydantic import ValidationError

from tests.retrieval.conftest import NOW, uid


def common() -> dict[str, object]:
    return {
        "contract_version": "mcp-read-v1",
        "persona_id": uid(1),
        "branch_id": uid(3),
    }


def test_query_principal_is_strict_server_derived_and_immutable() -> None:
    principal = QueryPrincipal(
        tenant_id=uid(1),
        actor_id=uid(2),
        client_id=uid(3),
        transport_binding_id=uid(4),
        scopes=frozenset({"memory.read.search"}),
        allowed_memory_scopes=frozenset(),
        allowed_visibilities=frozenset(),
        max_sensitivity=0,
    )

    with pytest.raises(ValidationError, match="frozen"):
        principal.max_sensitivity = 4
    with pytest.raises(ValidationError, match="Extra inputs"):
        QueryPrincipal.model_validate({**principal.model_dump(), "provider": "github"})


def test_context_pack_exposes_requested_memory_scopes_at_top_level() -> None:
    query = ContextPackQuery.model_validate(
        {
            **common(),
            "query": "synthetic",
            "requested_memory_scopes": frozenset(),
            "token_budget": 4096,
        }
    )

    assert "requested_memory_scopes" in query.model_fields_set


def test_memory_get_exposes_only_implemented_conflict_expansion() -> None:
    query = MemoryGetQuery.model_validate(
        {
            **common(),
            "memory_id": uid(8),
            "include_conflicts": True,
        }
    )

    assert query.include_conflicts is True
    with pytest.raises(ValidationError, match="Extra inputs"):
        MemoryGetQuery.model_validate({**common(), "memory_id": uid(8), "include_evidence": True})


def test_timeline_requires_one_explicit_bounded_time_window() -> None:
    with pytest.raises(ValidationError, match="Field required"):
        MemoryTimelineQuery.model_validate(common())
    with pytest.raises(ValidationError, match="Extra inputs"):
        MemoryTimelineQuery.model_validate(
            {
                **common(),
                "window": TimeWindow(starts_at=NOW, ends_at=NOW + timedelta(hours=1)),
                "anchor_event_id": uid(9),
            }
        )
    query = MemoryTimelineQuery.model_validate(
        {
            **common(),
            "window": TimeWindow(starts_at=NOW, ends_at=NOW + timedelta(hours=1)),
        }
    )
    assert query.window.starts_at == NOW


def test_selection_history_record_exposes_events_not_identity_or_payload() -> None:
    record = SelectionEventRecord(
        event_id=uid(8),
        sequence=1,
        operation=EventOperation.REMEMBERED,
        memory_id=uid(9),
        created_at=NOW,
    )

    assert set(SelectionEventRecord.model_fields) == {
        "event_id",
        "sequence",
        "operation",
        "memory_id",
        "created_at",
    }
    assert record.operation is EventOperation.REMEMBERED


def test_selection_decisions_v2_is_additive_and_strict() -> None:
    query = MemorySelectionDecisionsQuery.model_validate(
        {
            "contract_version": "mcp-read-v2",
            "persona_id": uid(1),
            "branch_id": uid(3),
            "limit": 25,
        }
    )

    assert query.contract_version == "mcp-read-v2"
    with pytest.raises(ValidationError, match="Extra inputs"):
        MemorySelectionDecisionsQuery.model_validate(
            {
                **query.model_dump(),
                "tenant_id": uid(9),
            }
        )

    assert set(SelectionDecisionView.model_fields) == {
        "selection_sequence",
        "decision_id",
        "profile_version",
        "profile_sha256",
        "matched_rule_ids",
        "outcome",
        "reason_codes",
        "memory_id",
        "event_id",
        "decided_at",
    }
