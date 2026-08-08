from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from kivra_memory.domain.enums import EventOperation, LinkType, MemoryStatus
from kivra_memory.domain.events import (
    BranchCreatedPayload,
    BranchState,
    CandidateLifecyclePayload,
    EvidenceState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryStateV2,
    MemoryTransitionPayload,
    TombstonedPayload,
)
from kivra_memory.domain.folding import ProjectionState, rebuild
from kivra_memory.storage.live_projection import (
    load_projection_state_for_update,
    stage_live_projection,
    validate_live_event,
)
from kivra_memory.storage.models import Memory, MemoryEvidence, MemoryLink
from kivra_memory.storage.projector import ProjectionPersistenceError, memory_state_to_row
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.dml import Update
from sqlalchemy.sql.selectable import Select
from test_projector import (  # type: ignore[import-not-found]
    BRANCH_ID,
    LINEAGE_ID,
    NOW,
    TENANT_ID,
    _history_with_all_children,
    branch_event,
    changed_memory,
    evidence_state,
    make_event,
    memory_state,
    uid,
)


class _Result:
    def __init__(self, rows: Sequence[object]) -> None:
        self.rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> Sequence[object]:
        return self.rows

    def scalar_one_or_none(self) -> object | None:
        if not self.rows:
            return None
        assert len(self.rows) == 1
        return self.rows[0]


class PostgreSQLError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("content-bearing database detail")
        self.sqlstate = sqlstate


def database_error(sqlstate: str) -> DBAPIError:
    return DBAPIError("private statement", {}, PostgreSQLError(sqlstate), False)


class _Session:
    def __init__(self, rows: dict[type[object], Sequence[object]] | None = None) -> None:
        self.rows = {} if rows is None else rows
        self.statements: list[object] = []
        self.added: list[object] = []
        self.flushes = 0

    def in_transaction(self) -> bool:
        return True

    async def execute(self, statement: object) -> _Result:
        self.statements.append(statement)
        if isinstance(statement, Select):
            entity = statement.column_descriptions[0].get("entity")
            return _Result(self.rows.get(cast(type[object], entity), ()))
        return _Result(())

    def add(self, row: object) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flushes += 1


def _branch_state() -> BranchState:
    payload = branch_event().typed_payload()
    assert isinstance(payload, BranchCreatedPayload)
    return payload.branch


def _base_state(*memories: MemoryState) -> ProjectionState:
    return ProjectionState(
        sequence=1,
        memories={memory.memory_id: memory for memory in memories},
        branches={BRANCH_ID: _branch_state()},
    )


def _direct_cases() -> list[tuple[str, ProjectionState, MemoryEvent, int, int]]:
    created = memory_state()
    observed = changed_memory(created, status=MemoryStatus.CANDIDATE)
    revised = changed_memory(
        created,
        revision=2,
        statement="The synthetic project uses a revised stable test floor.",
        updated_at=NOW + timedelta(seconds=1),
        normalized_fingerprint="bc" * 32,
    )
    retired = changed_memory(
        created,
        revision=2,
        status=MemoryStatus.RETIRED,
        updated_at=NOW + timedelta(seconds=1),
    )
    tombstoned = changed_memory(
        created,
        revision=2,
        status=MemoryStatus.TOMBSTONED,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        normalized_fingerprint=None,
        updated_at=NOW + timedelta(seconds=1),
    )
    second = changed_memory(
        memory_state(memory_id=uid(12)),
        normalized_fingerprint="cd" * 32,
    )
    link = LinkState(
        link_id=uid(60),
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        branch_id=BRANCH_ID,
        source_memory_id=created.memory_id,
        target_memory_id=second.memory_id,
        link_type=LinkType.ASSOCIATED_WITH,
        status="active",
        created_at=NOW + timedelta(seconds=1),
        metadata={},
    )
    event_time = NOW + timedelta(seconds=1)
    simple = [
        (
            "observed",
            _base_state(),
            make_event(
                sequence=2,
                operation=EventOperation.OBSERVED,
                payload=MemoryCreatedPayload(memory=observed),
                memory_id=observed.memory_id,
            ),
            1,
            0,
        ),
        (
            "remembered",
            _base_state(),
            make_event(
                sequence=2,
                operation=EventOperation.REMEMBERED,
                payload=MemoryCreatedPayload(memory=created),
                memory_id=created.memory_id,
            ),
            1,
            0,
        ),
        (
            "revised",
            _base_state(created),
            make_event(
                sequence=2,
                operation=EventOperation.REVISED,
                payload=MemoryTransitionPayload(previous_revision=1, memory=revised),
                memory_id=created.memory_id,
                expected_revision=1,
                created_at=event_time,
            ),
            0,
            1,
        ),
        (
            "linked",
            _base_state(created, second),
            make_event(
                sequence=2,
                operation=EventOperation.LINKED,
                payload=LinkedPayload(link=link),
                memory_id=None,
                created_at=event_time,
            ),
            1,
            0,
        ),
        (
            "retired",
            _base_state(created),
            make_event(
                sequence=2,
                operation=EventOperation.RETIRED,
                payload=MemoryTransitionPayload(previous_revision=1, memory=retired),
                memory_id=created.memory_id,
                expected_revision=1,
                created_at=event_time,
            ),
            0,
            1,
        ),
        (
            "tombstoned",
            _base_state(created),
            make_event(
                sequence=2,
                operation=EventOperation.TOMBSTONED,
                payload=TombstonedPayload(
                    previous_revision=1,
                    memory=tombstoned,
                    forget_mode="logical",
                ),
                memory_id=created.memory_id,
                expected_revision=1,
                created_at=event_time,
            ),
            0,
            1,
        ),
    ]
    history = _history_with_all_children()
    simple.extend(
        [
            ("conflict_opened", rebuild(history[:5]), history[5], 3, 2),
            ("conflict_resolved", rebuild(history[:7]), history[7], 0, 5),
        ]
    )
    return simple


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "before", "event", "expected_adds", "expected_updates"),
    _direct_cases(),
    ids=lambda value: value if isinstance(value, str) else None,
)
async def test_validate_and_stage_all_direct_mutation_after_images(
    name: str,
    before: ProjectionState,
    event: MemoryEvent,
    expected_adds: int,
    expected_updates: int,
) -> None:
    del name
    after = validate_live_event(before, event)
    session = _Session()

    await stage_live_projection(
        cast(object, session),  # type: ignore[arg-type]
        before=before,
        after=after,
        event=event,
    )

    assert len(session.added) == expected_adds
    update_count = sum(isinstance(statement, Update) for statement in session.statements)
    assert update_count == expected_updates
    assert session.flushes == 1


@pytest.mark.asyncio
async def test_load_projection_locks_link_endpoints_in_deterministic_order() -> None:
    first = memory_state(memory_id=uid(12))
    second = changed_memory(memory_state(memory_id=uid(10)), normalized_fingerprint="ef" * 32)
    link = LinkState(
        link_id=uid(60),
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        branch_id=BRANCH_ID,
        source_memory_id=first.memory_id,
        target_memory_id=second.memory_id,
        link_type=LinkType.REFINES,
        status="active",
        created_at=NOW,
        metadata={},
    )
    event = make_event(
        sequence=2,
        operation=EventOperation.LINKED,
        payload=LinkedPayload(link=link),
        memory_id=None,
    )
    rows = [
        memory_state_to_row(first, last_event_id=uid(80)),
        memory_state_to_row(second, last_event_id=uid(81)),
    ]
    session = _Session({Memory: rows, MemoryLink: ()})

    state = await load_projection_state_for_update(
        cast(object, session),  # type: ignore[arg-type]
        event=event,
        branch=_branch_state(),
    )

    assert set(state.memories) == {first.memory_id, second.memory_id}
    sql = [str(statement) for statement in session.statements]
    assert "ORDER BY memories.memory_id" in sql[0]
    assert "FOR UPDATE" in sql[0]
    assert "FOR UPDATE" in sql[1]


@pytest.mark.asyncio
async def test_candidate_promotion_locks_and_stages_policy_evidence() -> None:
    base = memory_state()
    candidate = MemoryStateV2.model_validate(
        {
            **base.model_dump(mode="python"),
            "status": MemoryStatus.CANDIDATE,
            "candidate_expires_at": NOW + timedelta(days=30),
        }
    )
    promoted = MemoryStateV2.model_validate(
        {
            **base.model_dump(mode="python"),
            "revision": 2,
            "updated_at": NOW + timedelta(seconds=1),
            "candidate_expires_at": None,
        }
    )
    item = evidence_state(uid(50), candidate.memory_id).model_copy(
        update={"created_at": NOW + timedelta(seconds=1)}
    )
    event = make_event(
        sequence=2,
        operation=EventOperation.CANDIDATE_PROMOTED,
        payload=CandidateLifecyclePayload(
            previous_revision=1,
            memory=promoted,
            selection_decision_id=uid(70),
            policy_rule_code="trusted_confirmation",
            evidence=(item,),
        ),
        memory_id=candidate.memory_id,
        expected_revision=1,
        created_at=NOW + timedelta(seconds=1),
        schema_version=2,
        payload_version=2,
    )
    session = _Session(
        {
            Memory: (memory_state_to_row(candidate, last_event_id=uid(80)),),
            MemoryEvidence: (),
        }
    )

    before = await load_projection_state_for_update(
        cast(object, session),  # type: ignore[arg-type]
        event=event,
        branch=_branch_state(),
    )
    after = validate_live_event(before, event)
    await stage_live_projection(
        cast(object, session),  # type: ignore[arg-type]
        before=before,
        after=after,
        event=event,
    )

    staged = [row for row in session.added if isinstance(row, MemoryEvidence)]
    assert len(staged) == 1
    assert staged[0].evidence_id == item.evidence_id
    assert staged[0].source_event_id == event.event_id
    evidence_select = next(
        statement
        for statement in session.statements
        if isinstance(statement, Select) and "memory_evidence" in str(statement)
    )
    assert "FOR UPDATE" in str(evidence_select)


@pytest.mark.asyncio
async def test_load_projection_sanitizes_invalid_persisted_content() -> None:
    row = memory_state_to_row(memory_state(), last_event_id=uid(80))
    row.statement = "private stored statement"
    row.reason_to_remember = None
    revised = changed_memory(
        memory_state(),
        revision=2,
        updated_at=NOW + timedelta(seconds=1),
    )
    event = make_event(
        sequence=2,
        operation=EventOperation.REVISED,
        payload=MemoryTransitionPayload(previous_revision=1, memory=revised),
        memory_id=revised.memory_id,
        expected_revision=1,
        created_at=NOW + timedelta(seconds=1),
    )
    session = _Session({Memory: (row,)})

    with pytest.raises(Exception) as caught:
        await load_projection_state_for_update(
            cast(object, session),  # type: ignore[arg-type]
            event=event,
            branch=_branch_state(),
        )

    assert str(caught.value) == "invalid_live_projection"
    assert "private stored statement" not in repr(caught.value)


@pytest.mark.asyncio
async def test_tombstone_loads_active_evidence_so_canonical_fold_rejects_it() -> None:
    current = memory_state()
    tombstoned = changed_memory(
        current,
        revision=2,
        status=MemoryStatus.TOMBSTONED,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        normalized_fingerprint=None,
        updated_at=NOW + timedelta(seconds=1),
    )
    event = make_event(
        sequence=2,
        operation=EventOperation.TOMBSTONED,
        payload=TombstonedPayload(
            previous_revision=1,
            memory=tombstoned,
            forget_mode="logical",
        ),
        memory_id=current.memory_id,
        expected_revision=1,
        created_at=NOW + timedelta(seconds=1),
    )
    item: EvidenceState = evidence_state(uid(50), current.memory_id)
    evidence_row = MemoryEvidence(
        evidence_id=item.evidence_id,
        tenant_id=item.tenant_id,
        lineage_id=item.lineage_id,
        branch_id=item.branch_id,
        memory_id=item.memory_id,
        source_event_id=uid(82),
        source_type=item.source_type,
        source_reference=dict(item.source_reference),
        excerpt=item.excerpt,
        occurred_at=item.occurred_at,
        content_sha256=bytes.fromhex(item.content_sha256 or ""),
        trust_classification=item.trust_classification,
        status=item.status,
        created_at=item.created_at,
        metadata_=dict(item.metadata),
    )
    session = _Session(
        {
            Memory: (memory_state_to_row(current, last_event_id=uid(80)),),
            MemoryEvidence: (evidence_row,),
        }
    )

    before = await load_projection_state_for_update(
        cast(object, session),  # type: ignore[arg-type]
        event=event,
        branch=_branch_state(),
    )

    assert set(before.evidence) == {item.evidence_id}
    with pytest.raises(Exception, match="unsanitized_tombstone"):
        validate_live_event(before, event)
    evidence_sql = str(session.statements[1])
    assert "ORDER BY memory_evidence.evidence_id" in evidence_sql
    assert "FOR UPDATE" in evidence_sql


async def test_projection_load_serialization_failure_propagates_for_retry() -> None:
    expected = database_error("40001")
    raw = Mock(spec=AsyncSession)
    raw.in_transaction = Mock(return_value=True)
    raw.execute = AsyncMock(side_effect=expected)

    with pytest.raises(DBAPIError) as caught:
        await load_projection_state_for_update(
            cast(AsyncSession, raw),
            event=_direct_cases()[1][2],
            branch=_branch_state(),
        )

    assert caught.value is expected


async def test_projection_write_serialization_failure_propagates_for_retry() -> None:
    before, event = _direct_cases()[1][1:3]
    after = validate_live_event(before, event)
    expected = database_error("40001")
    raw = Mock(spec=AsyncSession)
    raw.in_transaction = Mock(return_value=True)
    raw.add = Mock()
    raw.flush = AsyncMock(side_effect=expected)

    with pytest.raises(DBAPIError) as caught:
        await stage_live_projection(
            cast(AsyncSession, raw),
            before=before,
            after=after,
            event=event,
        )

    assert caught.value is expected


@pytest.mark.parametrize("sqlstate", ["40P01", "23505", "08006"])
async def test_projection_load_non_serialization_failure_is_sanitized(sqlstate: str) -> None:
    raw = Mock(spec=AsyncSession)
    raw.in_transaction = Mock(return_value=True)
    raw.execute = AsyncMock(side_effect=database_error(sqlstate))

    with pytest.raises(ProjectionPersistenceError) as caught:
        await load_projection_state_for_update(
            cast(AsyncSession, raw),
            event=_direct_cases()[1][2],
            branch=_branch_state(),
        )

    assert str(caught.value) == "live_projection_load_failed"
    assert "private statement" not in repr(caught.value)
    assert caught.value.__suppress_context__ is True


async def test_projection_write_non_serialization_failure_is_sanitized() -> None:
    before, event = _direct_cases()[1][1:3]
    after = validate_live_event(before, event)
    raw = Mock(spec=AsyncSession)
    raw.in_transaction = Mock(return_value=True)
    raw.add = Mock()
    raw.flush = AsyncMock(side_effect=database_error("23505"))

    with pytest.raises(ProjectionPersistenceError) as caught:
        await stage_live_projection(
            cast(AsyncSession, raw),
            before=before,
            after=after,
            event=event,
        )

    assert str(caught.value) == "live_projection_write_failed"
    assert "private statement" not in repr(caught.value)
    assert caught.value.__suppress_context__ is True
