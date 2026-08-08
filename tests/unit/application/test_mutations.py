from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.application import mutations as mutations_module
from kivra_memory.domain.commands import MemoryChanges, MutationResult, ReviseCommand
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import MemoryState
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
        scopes=frozenset({"memory.write.revise"}),
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
    assert revised.publication_approved_at == current.publication_approved_at
    assert revised.normalized_fingerprint != current.normalized_fingerprint


@pytest.mark.parametrize("ingress_id", [None, uid(30)])
async def test_direct_and_synthetic_ingress_use_the_same_execute_path(
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


def test_safe_error_mapping_contains_no_exception_or_command_content() -> None:
    response = mutations_module._error("dependency_unavailable", retryable=True)

    rendered = response.model_dump_json()
    assert response.error.message == "A required dependency is unavailable."
    assert "synthetic statement" not in rendered
    assert "exception" not in rendered
