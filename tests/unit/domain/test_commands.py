from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from kivra_memory.domain.commands import (
    CandidateExpiryCommand,
    CandidatePromotionCommand,
    CommandHashBinding,
    ConflictErrorDetails,
    ConflictResolution,
    ForgetCommand,
    LinkCommand,
    MemoryChanges,
    MemoryInput,
    MemoryRevisionExpectation,
    MutationCommand,
    MutationError,
    MutationErrorBody,
    MutationResult,
    ObserveCommand,
    OpenConflictCommand,
    RememberCommand,
    ResolveConflictCommand,
    RetireCommand,
    ReviseCommand,
    StaleRevisionDetails,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from pydantic import ValidationError


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def envelope() -> dict[str, object]:
    return {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": "test-session:019c-command",
        "logical_session_id": uid(1),
        "persona_id": uid(2),
        "branch_id": uid(3),
        "reason": "Exercise a synthetic domain mutation.",
    }


def command[CommandT: MutationCommand](model: type[CommandT], **fields: object) -> CommandT:
    document = envelope()
    document.update(fields)
    return model.model_validate(document)


def memory_input() -> MemoryInput:
    return MemoryInput(
        subject_id=uid(4),
        subject_kind=SubjectKind.PROJECT,
        category=MemoryCategory.PROJECT_DECISION,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement="The synthetic project uses typed mutation commands.",
        reason_to_remember="This decision defines the command test contract.",
        interpretation_limits=("Synthetic fixture only.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        valid_from=None,
        valid_to=None,
        observed_at=datetime(2026, 8, 8, 12, tzinfo=UTC),
        origin_session_id=uid(1),
        metadata={"fixture": True},
    )


def all_commands() -> tuple[MutationCommand, ...]:
    return (
        command(ObserveCommand, memory=memory_input()),
        command(RememberCommand, memory=memory_input()),
        command(
            ReviseCommand,
            memory_id=uid(10),
            expected_revision=1,
            changes=MemoryChanges(statement="A revised synthetic statement."),
        ),
        command(
            LinkCommand,
            source_memory_id=uid(10),
            source_expected_revision=1,
            target_memory_id=uid(11),
            target_expected_revision=2,
            link_type=LinkType.SUPPORTS,
        ),
        command(
            OpenConflictCommand,
            subject_id=uid(4),
            members=(
                MemoryRevisionExpectation(memory_id=uid(10), expected_revision=1),
                MemoryRevisionExpectation(memory_id=uid(11), expected_revision=2),
            ),
            conflict_reason="The synthetic claims cannot both hold.",
        ),
        command(
            ResolveConflictCommand,
            conflict_id=uid(12),
            members=(
                ConflictResolution(
                    memory_id=uid(10),
                    expected_revision=2,
                    disposition="retained",
                    resulting_status="active",
                ),
                ConflictResolution(
                    memory_id=uid(11),
                    expected_revision=3,
                    disposition="retired",
                    resulting_status="retired",
                ),
            ),
            resolution_kind="explicit_user_resolution",
            resolution_rationale="The synthetic authority selected the retained claim.",
            user_confirmed=True,
        ),
        command(RetireCommand, memory_id=uid(10), expected_revision=2),
        command(
            ForgetCommand,
            memory_id=uid(10),
            expected_revision=2,
            mode="logical",
            confirmation="confirm_logical_forget",
        ),
    )


def test_all_eight_direct_mutation_contracts_are_immutable_and_canonical() -> None:
    commands = all_commands()

    assert len(commands) == 8
    assert {mutation.OPERATION for mutation in commands} == {
        "observe",
        "remember",
        "revise",
        "link",
        "open_conflict",
        "resolve_conflict",
        "retire",
        "forget",
    }
    for mutation in commands:
        assert len(mutation.canonical_hash()) == 64
        with pytest.raises(ValidationError, match="frozen"):
            mutation.reason = "changed"


@pytest.mark.parametrize(
    "forbidden_field",
    ["tenant_id", "actor_id", "client_id", "transport_binding_id", "installation_id"],
)
def test_authenticated_identity_and_transport_provenance_are_not_command_input(
    forbidden_field: str,
) -> None:
    document = {**envelope(), "memory": memory_input(), forbidden_field: uid(20)}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RememberCommand.model_validate(document)


def test_strict_contract_rejects_coercion_unknown_fields_and_non_uuid7() -> None:
    with pytest.raises(ValidationError):
        command(RetireCommand, memory_id=uid(10), expected_revision="1")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        command(RetireCommand, memory_id=uid(10), expected_revision=1, surprise=True)
    with pytest.raises(ValidationError, match="UUIDv7"):
        command(RetireCommand, memory_id=uuid4(), expected_revision=1)


def test_command_hash_excludes_replay_session_and_authenticated_context() -> None:
    first = command(RememberCommand, memory=memory_input())
    changed_envelope = envelope()
    changed_envelope.update(idempotency_key="retry:another-key", logical_session_id=uid(99))
    changed_envelope["memory"] = memory_input()
    retry = RememberCommand.model_validate(changed_envelope)

    assert first.canonical_material() == retry.canonical_material()
    assert first.canonical_hash() == retry.canonical_hash()
    material_text = repr(first.canonical_material())
    assert "idempotency" not in material_text
    assert "logical_session" not in material_text
    assert "tenant_id" not in material_text


def test_command_hash_changes_with_semantics_and_can_bind_trusted_context() -> None:
    first = command(RetireCommand, memory_id=uid(10), expected_revision=1)
    second = command(RetireCommand, memory_id=uid(10), expected_revision=2)
    binding = CommandHashBinding(
        tenant_id=uid(30), lineage_id=uid(31), actor_id=uid(32), client_id=uid(33)
    )

    assert first.canonical_hash() != second.canonical_hash()
    assert first.bound_canonical_hash(binding) != first.canonical_hash()
    assert "transport" not in repr(first.bound_canonical_material(binding))


@pytest.mark.parametrize("server_owned", ["status", "content_protection"])
def test_memory_input_rejects_server_owned_lifecycle_and_protection(server_owned: str) -> None:
    document = memory_input().model_dump(mode="python")
    document[server_owned] = "active" if server_owned == "status" else "plaintext"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MemoryInput.model_validate(document)


def test_revise_changes_are_non_empty_and_preserve_explicit_null() -> None:
    with pytest.raises(ValidationError, match="at least one"):
        MemoryChanges()
    changes = MemoryChanges(valid_to=None)

    assert changes.canonical_value() == {"valid_to": None}


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("subject_id", uid(90)),
        ("subject_kind", SubjectKind.GLOBAL),
        ("scope", MemoryScope.GLOBAL),
        ("origin_session_id", uid(91)),
    ],
)
def test_revise_changes_reject_aggregate_identity_fields(field_name: str, value: object) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MemoryChanges.model_validate({field_name: value})


def test_memory_input_rejects_scope_mismatch_duplicate_limits_and_unbounded_maps() -> None:
    document = memory_input().model_dump(mode="python")
    document["subject_kind"] = SubjectKind.GLOBAL
    with pytest.raises(ValidationError, match="scope does not match"):
        MemoryInput.model_validate(document)

    document = memory_input().model_dump(mode="python")
    document["interpretation_limits"] = ("same", "same")
    with pytest.raises(ValidationError, match="unique"):
        MemoryInput.model_validate(document)

    document = memory_input().model_dump(mode="python")
    document["metadata"] = {"key": "x" * 4097}
    with pytest.raises(ValidationError, match="exceeds 4096"):
        MemoryInput.model_validate(document)


def test_link_and_conflict_members_must_be_distinct() -> None:
    with pytest.raises(ValidationError, match="self-referential"):
        command(
            LinkCommand,
            source_memory_id=uid(10),
            source_expected_revision=1,
            target_memory_id=uid(10),
            target_expected_revision=1,
            link_type=LinkType.SUPPORTS,
        )
    member = MemoryRevisionExpectation(memory_id=uid(10), expected_revision=1)
    with pytest.raises(ValidationError, match="unique"):
        command(
            OpenConflictCommand,
            subject_id=uid(4),
            members=(member, member),
            conflict_reason="Synthetic conflict.",
        )


def test_forget_requires_mode_bound_confirmation_literal() -> None:
    with pytest.raises(ValidationError, match="must match"):
        command(
            ForgetCommand,
            memory_id=uid(10),
            expected_revision=1,
            mode="hard",
            confirmation="confirm_logical_forget",
        )


@pytest.mark.parametrize("model", [CandidatePromotionCommand, CandidateExpiryCommand])
def test_internal_candidate_lifecycle_commands_are_content_free_and_strict(
    model: type[CandidatePromotionCommand] | type[CandidateExpiryCommand],
) -> None:
    command = model(
        memory_id=uid(10),
        expected_revision=2,
        selection_decision_id=uid(11),
        policy_rule_code="candidate_repeated_observation",
    )

    assert command.memory_id == uid(10)
    assert command.expected_revision == 2
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model.model_validate(
            {
                "memory_id": uid(10),
                "expected_revision": 2,
                "selection_decision_id": uid(11),
                "policy_rule_code": "candidate_repeated_observation",
                "statement": "must not cross the internal lifecycle boundary",
            }
        )


def test_mutation_result_is_typed_bounded_and_payload_free() -> None:
    result = MutationResult(
        contract_version="mcp-mutation-v1",
        operation="remember",
        receipt_id=uid(39),
        event_id=uid(40),
        memory_id=uid(10),
        revision=1,
        warnings=("candidate_created",),
    )

    assert result.ok is True
    assert "statement" not in result.model_dump()
    with pytest.raises(ValidationError, match="supplied together"):
        MutationResult(
            contract_version="mcp-mutation-v1",
            operation="remember",
            receipt_id=uid(39),
            event_id=uid(40),
            memory_id=uid(10),
        )
    with pytest.raises(ValidationError, match="pattern"):
        MutationResult(
            contract_version="mcp-mutation-v1",
            operation="remember",
            receipt_id=uid(39),
            event_id=uid(40),
            warnings=("secret: value",),
        )


def test_mutation_error_only_accepts_safe_typed_details() -> None:
    stale = MutationError(
        contract_version="mcp-mutation-v1",
        error=MutationErrorBody(
            code="stale_revision",
            message="The target changed after the supplied revision.",
            retryable=True,
            details=StaleRevisionDetails(
                memory_id=uid(10), expected_revision=1, current_revision=2
            ),
        ),
    )
    conflict = MutationError(
        contract_version="mcp-mutation-v1",
        error=MutationErrorBody(
            code="conflict_state_changed",
            message="The conflict state changed before this mutation completed.",
            details=ConflictErrorDetails(conflict_id=uid(12), memory_ids=(uid(10), uid(11))),
        ),
    )

    assert isinstance(stale.error.details, StaleRevisionDetails)
    assert stale.error.details.suggested_action == "read_then_retry_or_open_conflict"
    assert isinstance(conflict.error.details, ConflictErrorDetails)
    assert conflict.error.details.suggested_action == "inspect_conflict"
    for forbidden in ("statement", "evidence", "authorization", "sql"):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            document: dict[str, object] = {
                "contract_version": "mcp-mutation-v1",
                "error": MutationErrorBody(
                    code="invalid_input", message="The mutation input is invalid."
                ),
                forbidden: "sensitive value",
            }
            MutationError.model_validate(document)


def test_mutation_error_rejects_unstructured_or_secret_bearing_detail_maps() -> None:
    with pytest.raises(ValidationError):
        MutationError.model_validate(
            {
                "contract_version": "mcp-mutation-v1",
                "error": {
                    "code": "stale_revision",
                    "message": "The target changed after the supplied revision.",
                    "details": {"statement": "private memory", "sql": "SELECT secret"},
                },
            },
        )


def test_internal_error_uses_generic_safe_message_without_details() -> None:
    error = MutationError(
        contract_version="mcp-mutation-v1",
        error=MutationErrorBody(
            code="internal_error",
            message="The mutation could not be completed.",
        ),
    )

    assert error.error.details is None
    assert error.error.code == "internal_error"
