from __future__ import annotations

from datetime import timedelta

import pytest
from kivra_memory.retrieval.contracts import (
    ContextPackQuery,
    MemoryGetQuery,
    MemoryTimelineQuery,
    QueryPrincipal,
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


def test_memory_get_has_bounded_related_flags() -> None:
    query = MemoryGetQuery.model_validate(
        {
            **common(),
            "memory_id": uid(8),
            "include_revisions": True,
            "include_links": True,
            "include_conflicts": True,
            "related_limit": 10,
        }
    )

    assert query.include_revisions and query.related_limit == 10


def test_timeline_requires_exactly_one_window_or_anchor() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        MemoryTimelineQuery.model_validate(common())
    with pytest.raises(ValidationError, match="exactly one"):
        MemoryTimelineQuery.model_validate(
            {
                **common(),
                "window": TimeWindow(starts_at=NOW, ends_at=NOW + timedelta(hours=1)),
                "anchor_event_id": uid(9),
            }
        )
    assert MemoryTimelineQuery.model_validate(
        {**common(), "anchor_memory_id": uid(8)}
    ).anchor_memory_id == uid(8)


def test_selection_history_record_exposes_events_not_identity_or_payload() -> None:
    record = SelectionEventRecord(
        event_id=uid(8),
        sequence=1,
        operation="remembered",
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
    assert record.operation == "remembered"
