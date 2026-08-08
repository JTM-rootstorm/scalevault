from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.application import mutations as mutations_module
from kivra_memory.domain.commands import (
    ForgetCommand,
    LinkCommand,
    MemoryChanges,
    MemoryInput,
    MutationResult,
    ObserveCommand,
    OpenConflictCommand,
    RememberCommand,
    ResolveConflictCommand,
    RetireCommand,
    ReviseCommand,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import (
    AffectedMemory,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    TombstonedPayload,
)
from kivra_memory.domain.identifiers import new_uuid7
from pydantic import ValidationError

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def principal(*, ingress_id: UUID | None = None) -> CommandPrincipal:
    return CommandPrincipal(
        tenant_id=uid(1),
        actor_id=uid(2),
        client_id=uid(3),
        transport_binding_id=uid(4),
        scopes=frozenset({"memory.write.revise", "memory.write.legacy_v1"}),
        ingress_id=ingress_id,
    )


def command() -> ReviseCommand:
    return ReviseCommand(
        contract_version="mcp-mutation-v1",
        idempotency_key="unit-revise",
        logical_session_id=None,
        persona_id=uid(5),
        branch_id=uid(6),
        reason="Exercise the application command seam.",
        memory_id=uid(7),
        expected_revision=3,
        changes=MemoryChanges(statement="The revised safe synthetic statement."),
    )


def proposal_command(
    command_type: type[ObserveCommand] | type[RememberCommand],
) -> ObserveCommand | RememberCommand:
    return command_type(
        contract_version="mcp-mutation-v1",
        idempotency_key=f"unit-{command_type.OPERATION}",
        logical_session_id=None,
        persona_id=uid(5),
        branch_id=uid(6),
        reason="Exercise narrowly authorized proposal ingress.",
        memory=MemoryInput(
            subject_id=uid(9),
            subject_kind=SubjectKind.PROJECT,
            category=MemoryCategory.PROJECT_DECISION,
            ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
            scope=MemoryScope.PROJECT,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement="The proposal authorization fixture is synthetic.",
            reason_to_remember="The fixture verifies proposal ingress authorization.",
            interpretation_limits=("Synthetic fixture only.",),
            confidence=Decimal("0.9"),
            salience=Decimal("0.8"),
            durability=Decimal("0.7"),
            sensitivity=0,
            authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
            metadata={"fixture": True},
        ),
    )


def memory() -> MemoryState:
    return MemoryState(
        memory_id=uid(7),
        tenant_id=uid(1),
        lineage_id=uid(8),
        branch_id=uid(6),
        subject_id=uid(9),
        subject_kind=SubjectKind.PROJECT,
        revision=3,
        category=MemoryCategory.PROJECT_DECISION,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="The original safe synthetic statement.",
        reason_to_remember="The fixture exercises immutable after-images.",
        interpretation_limits=("Synthetic fixture only.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=NOW,
        publication_approved_at=None,
        publication_approved_by_actor_id=None,
        content_protection="plaintext",
        content_key_id=None,
        created_at=NOW,
        updated_at=NOW,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


def result() -> MutationResult:
    return MutationResult(
        contract_version="mcp-mutation-v1",
        operation="revise",
        receipt_id=uid(20),
        event_id=uid(21),
        memory_id=uid(7),
        revision=4,
    )


def test_command_principal_is_strict_immutable_and_provider_neutral() -> None:
    context = principal(ingress_id=uid(10))

    assert context.ingress_id == uid(10)
    assert set(CommandPrincipal.model_fields) == {
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "scopes",
        "ingress_id",
    }
    with pytest.raises(ValidationError, match="frozen"):
        context.client_id = uid(11)
    with pytest.raises(ValidationError, match="Extra inputs"):
        CommandPrincipal.model_validate({**context.model_dump(), "provider": "github"}, strict=True)


def test_revise_after_image_preserves_server_owned_and_lifecycle_fields() -> None:
    current = memory()

    revised = mutations_module._revised_memory(current, command(), NOW)

    assert revised.revision == 4
    assert revised.statement == "The revised safe synthetic statement."
    assert revised.status is MemoryStatus.ACTIVE
    assert revised.memory_id == current.memory_id
    assert revised.subject_id == current.subject_id
    assert revised.content_protection == current.content_protection
    assert revised.publication_approved_at is None
    assert revised.normalized_fingerprint != current.normalized_fingerprint


@pytest.mark.parametrize("ingress_id", [None, uid(30)])
async def test_transport_provenance_does_not_create_a_provider_specific_execute_path(
    monkeypatch: pytest.MonkeyPatch, ingress_id: UUID | None
) -> None:
    seen: list[CommandPrincipal] = []

    async def fake_attempt(self: MutationEngine, session: Any, **kwargs: Any) -> MutationResult:
        del self, session
        seen.append(kwargs["principal"])
        return result()

    async def fake_transaction(factory: Any, tenant_id: UUID, operation: Any) -> MutationResult:
        del factory
        assert tenant_id == uid(1)
        return cast(MutationResult, await operation(MagicMock()))

    monkeypatch.setattr(MutationEngine, "_attempt", fake_attempt)
    monkeypatch.setattr(mutations_module, "run_serializable_transaction", fake_transaction)
    engine = MutationEngine(MagicMock())

    response = await engine.execute(principal(ingress_id=ingress_id), command())

    assert response == result()
    assert seen == [principal(ingress_id=ingress_id)]


@pytest.mark.parametrize("command_type", [ObserveCommand, RememberCommand])
def test_proposal_scope_does_not_bypass_nomination_policy(
    command_type: type[ObserveCommand] | type[RememberCommand],
) -> None:
    context = principal(ingress_id=uid(30)).model_copy(
        update={"scopes": frozenset({"memory:propose"})}
    )

    assert not mutations_module._principal_authorized(context, proposal_command(command_type))


def test_proposal_scope_does_not_authorize_a_direct_principal() -> None:
    context = principal().model_copy(update={"scopes": frozenset({"memory:propose"})})

    assert not mutations_module._principal_authorized(context, proposal_command(ObserveCommand))


def test_proposal_scope_does_not_authorize_other_ingress_mutations() -> None:
    context = principal(ingress_id=uid(30)).model_copy(
        update={"scopes": frozenset({"memory:propose"})}
    )

    assert not mutations_module._principal_authorized(context, command())


def test_exact_dotted_scope_authorization_is_unchanged() -> None:
    assert mutations_module._principal_authorized(principal(), command())


async def test_duplicate_active_link_returns_stable_non_retryable_invalid_input() -> None:
    session = MagicMock()
    session.scalar = AsyncMock(return_value=uid(40))
    link = LinkCommand(
        contract_version="mcp-mutation-v1",
        idempotency_key="unit-link",
        logical_session_id=None,
        persona_id=uid(5),
        branch_id=uid(6),
        reason="Exercise duplicate active link handling.",
        source_memory_id=uid(7),
        source_expected_revision=3,
        target_memory_id=uid(8),
        target_expected_revision=2,
        link_type=LinkType.SUPPORTS,
    )

    with pytest.raises(mutations_module._SafeFailure) as failure:
        await mutations_module._reject_duplicate_active_link(
            session,
            principal=principal(),
            lineage_id=uid(10),
            command=link,
        )

    assert failure.value.response.error.code == "invalid_input"
    assert not failure.value.response.error.retryable


@pytest.mark.parametrize("operation", ["retire", "forget"])
def test_disputed_memory_terminal_mutations_require_conflict_resolution(
    operation: str,
) -> None:
    del operation  # Both command paths use the same guard before event construction.
    disputed = memory().model_copy(update={"status": MemoryStatus.DISPUTED})

    with pytest.raises(mutations_module._SafeFailure) as failure:
        mutations_module._reject_disputed_terminal_mutation(disputed)

    assert failure.value.response.error.code == "conflict_state_changed"
    assert not failure.value.response.error.retryable


async def test_retry_callback_reuses_attempt_identity_and_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identities: list[tuple[object, ...]] = []

    async def fake_attempt(self: MutationEngine, session: Any, **kwargs: Any) -> MutationResult:
        del self, session
        identities.append(
            (
                kwargs["event_id"],
                kwargs["receipt_id"],
                kwargs["aggregate_id"],
                kwargs["correlation_id"],
                kwargs["created_at"],
                kwargs["job_ids"],
            )
        )
        return result()

    async def fake_transaction(factory: Any, tenant_id: UUID, operation: Any) -> MutationResult:
        del factory, tenant_id
        await operation(MagicMock())
        return cast(MutationResult, await operation(MagicMock()))

    monkeypatch.setattr(MutationEngine, "_attempt", fake_attempt)
    monkeypatch.setattr(mutations_module, "run_serializable_transaction", fake_transaction)

    response = await MutationEngine(MagicMock()).execute(principal(), command())

    assert response == result()
    assert len(identities) == 2
    assert identities[0] == identities[1]
    job_ids = cast(tuple[UUID, ...], identities[0][-1])
    assert len(job_ids) == 34
    assert len(set(job_ids)) == 34


def _job_event() -> MemoryEvent:
    event = MagicMock(spec=MemoryEvent)
    event.event_id = uid(80)
    event.sequence = 17
    return cast(MemoryEvent, event)


def _mock_command(command_type: type[Any], **values: object) -> Any:
    command = MagicMock(spec=command_type)
    for name, value in values.items():
        setattr(command, name, value)
    return command


def _job_types(
    command_value: Any,
    payload: Any,
    *,
    mutation_result: MutationResult | None = None,
) -> list[str]:
    scheduled = mutations_module._scheduled_jobs(
        command=command_value,
        event=_job_event(),
        payload=payload,
        result=mutation_result or result(),
    )
    return [job_type for job_type, _, _, _ in scheduled]


def test_create_and_revision_duplicate_scheduling_is_content_sensitive() -> None:
    created = memory().model_copy(update={"revision": 1})
    create_payload = MemoryCreatedPayload(memory=created)
    assert _job_types(_mock_command(RememberCommand), create_payload) == [
        "embed_memory",
        "check_duplicates",
        "export_git_batch",
    ]

    revised = memory().model_copy(update={"revision": 4})
    revision_payload = MemoryTransitionPayload(previous_revision=3, memory=revised)
    content_revision = _mock_command(
        ReviseCommand,
        changes=MemoryChanges(statement="A changed semantic statement."),
    )
    metadata_revision = _mock_command(
        ReviseCommand,
        changes=MemoryChanges(metadata={"reviewed": True}),
    )
    assert _job_types(content_revision, revision_payload) == [
        "embed_memory",
        "check_duplicates",
        "export_git_batch",
    ]
    assert _job_types(metadata_revision, revision_payload) == [
        "embed_memory",
        "export_git_batch",
    ]


@pytest.mark.parametrize("terminal_type", [RetireCommand, ForgetCommand])
def test_terminal_revisions_always_schedule_embedding_cleanup(
    terminal_type: type[RetireCommand] | type[ForgetCommand],
) -> None:
    terminal = memory().model_copy(update={"revision": 4, "status": MemoryStatus.TOMBSTONED})
    payload = TombstonedPayload(
        previous_revision=3,
        memory=terminal.model_copy(
            update={
                "statement": None,
                "reason_to_remember": None,
                "interpretation_limits": (),
                "normalized_fingerprint": None,
                "metadata": {},
            }
        ),
        forget_mode="hard",
    )
    command_value = _mock_command(terminal_type, mode="hard")
    scheduled = mutations_module._scheduled_jobs(
        command=command_value,
        event=_job_event(),
        payload=payload,
        result=result().model_copy(update={"memory_id": uid(7), "revision": 4}),
    )
    job_types = [job_type for job_type, _, _, _ in scheduled]

    assert job_types[0] == "embed_memory"
    assert job_types.count("export_git_batch") == 1
    assert job_types.count("purge_payload") == (1 if terminal_type is ForgetCommand else 0)
    assert scheduled[0][3] == {
        "memory_id": uid(7),
        "memory_version": 4,
        "event_id": uid(80),
    }


def _conflict_payload(*, resolved: bool) -> ConflictOpenedPayload | ConflictResolvedPayload:
    first = memory().model_copy(
        update={"memory_id": uid(71), "revision": 4, "status": MemoryStatus.DISPUTED}
    )
    second = memory().model_copy(
        update={"memory_id": uid(70), "revision": 6, "status": MemoryStatus.DISPUTED}
    )
    conflict_id = uid(72)
    conflict = ConflictState(
        conflict_id=conflict_id,
        tenant_id=uid(1),
        lineage_id=uid(8),
        branch_id=uid(6),
        subject_id=uid(9),
        status="resolved" if resolved else "open",
        reason="Synthetic conflict scheduling fixture.",
        resolution_kind="explicit_user_resolution" if resolved else None,
        resolution_rationale="Synthetic resolution." if resolved else None,
        opened_at=NOW,
        resolved_at=NOW if resolved else None,
        metadata={},
    )
    members = tuple(
        ConflictMemberState(
            conflict_id=conflict_id,
            memory_id=item.memory_id,
            disposition="retained" if resolved else "disputed",
            joined_at=NOW,
        )
        for item in (first, second)
    )
    affected = (
        AffectedMemory(previous_revision=3, memory=first),
        AffectedMemory(previous_revision=5, memory=second),
    )
    payload_type = ConflictResolvedPayload if resolved else ConflictOpenedPayload
    return payload_type(conflict=conflict, members=members, affected_memories=affected)


@pytest.mark.parametrize(
    ("command_type", "resolved"),
    [(OpenConflictCommand, False), (ResolveConflictCommand, True)],
)
def test_conflict_state_changes_schedule_every_after_image_in_stable_order(
    command_type: type[OpenConflictCommand] | type[ResolveConflictCommand], resolved: bool
) -> None:
    scheduled = mutations_module._scheduled_jobs(
        command=_mock_command(command_type),
        event=_job_event(),
        payload=_conflict_payload(resolved=resolved),
        result=result(),
    )

    assert [job_type for job_type, _, _, _ in scheduled] == [
        "embed_memory",
        "embed_memory",
        "export_git_batch",
    ]
    assert [job[2] for job in scheduled[:2]] == [uid(70), uid(71)]
    assert [job[3]["memory_version"] for job in scheduled[:2]] == [6, 4]


def test_safe_error_mapping_contains_no_exception_or_command_content() -> None:
    response = mutations_module._error("dependency_unavailable", retryable=True)

    rendered = response.model_dump_json()
    assert response.error.message == "A required dependency is unavailable."
    assert "synthetic statement" not in rendered
    assert "exception" not in rendered
