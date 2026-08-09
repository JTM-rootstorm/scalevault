from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.application.github_ingress import (
    GitHubIngressOrchestrator,
    GitHubIngressProcessResult,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import SelectionResult
from kivra_memory.domain.enums import IngressState, MemoryScope, SubjectKind
from kivra_memory.ingress.github_client import GitHubProposalObject
from kivra_memory.ingress.runtime import adapt_live_proposal, transaction_binding_sha256
from kivra_memory.ingress.validator import IngressValidationError, validate_ingress
from kivra_memory.storage.github_ingress import (
    GitHubIngressDiscovery,
    GitHubIngressRepository,
    IngressRegistration,
)
from kivra_memory.storage.models import IngressItem
from kivra_memory.workers.github_ingress import (
    GitHubIngressIdentity,
    GitHubIngressWorker,
    GitHubIngressWorkItem,
    work_item_from_proposal,
)
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE = (
    _ROOT
    / "tests"
    / "contract"
    / "fixtures"
    / "json_schemas"
    / "chatgpt-memory-proposal-v2.schema.json"
)


def _payload() -> dict[str, object]:
    value = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _raw(payload: dict[str, object] | None = None) -> bytes:
    return json.dumps(payload or _payload(), separators=(",", ":")).encode()


def _path(payload: dict[str, object] | None = None) -> str:
    value = payload or _payload()
    return f"ingress/v2/{value['installation_id']}/2026/08/{value['proposal_id']}.json"


def _discovery(ordinal: int = 1) -> GitHubIngressDiscovery:
    payload = _payload()
    proposal_id = str(payload["proposal_id"])
    if ordinal != 1:
        proposal_id = f"019c0000-0000-7000-8000-{ordinal:012d}"
    installation_id = UUID(str(payload["installation_id"]))
    path = f"ingress/v2/{installation_id}/2026/08/{proposal_id}.json"
    return GitHubIngressDiscovery(
        ingress_id=UUID(proposal_id),
        tenant_id=UUID("019c0000-0000-7000-8000-000000000031"),
        transport_binding_id=UUID("019c0000-0000-7000-8000-000000000032"),
        installation_id=installation_id,
        actor_id=UUID("019c0000-0000-7000-8000-000000000033"),
        client_id=UUID("019c0000-0000-7000-8000-000000000034"),
        repository_external_id="12345678",
        branch_name="main",
        immutable_path=path,
        commit_id="1" * 40,
        blob_id="2" * 40,
        discovered_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
    )


def test_v2_adapter_builds_only_the_existing_nomination_contract() -> None:
    payload = _payload()
    validated = validate_ingress(_raw(payload), _path(payload), source_git_blob_sha="2" * 40)
    discovery = _discovery()
    digest = transaction_binding_sha256(
        ingress_id=discovery.ingress_id,
        installation_id=discovery.installation_id,
        repository_external_id=discovery.repository_external_id,
        immutable_path=discovery.immutable_path,
        commit_id=discovery.commit_id,
        blob_id=discovery.blob_id,
        payload_sha256=b"x" * 32,
    )

    command = adapt_live_proposal(
        validated,
        expected_installation_id=discovery.installation_id,
        transaction_binding_sha256=digest,
    )

    assert command.transaction_binding_sha256 == digest
    assert command.proposal.scope is MemoryScope.PROJECT
    assert command.proposal.subject_kind is SubjectKind.PROJECT
    assert command.proposal.sensitivity == 0
    assert command.proposal.metadata == {}
    assert command.logical_session_id is None
    assert command.sealed_content is None
    assert "evidence_summary" not in command.model_dump(mode="json")["proposal"]
    with pytest.raises(ValidationError, match="GitHub sealed content is unsupported"):
        type(command).model_validate(
            {
                **command.model_dump(mode="python"),
                "sealed_content": {"safe_summary": "Must remain forbidden."},
            },
            strict=False,
        )


def test_poller_object_is_bound_to_pinned_local_identity_without_invented_fields() -> None:
    discovery = _discovery()
    raw = _raw()
    proposal = GitHubProposalObject(
        repository_id=12345678,
        commit_id=discovery.commit_id,
        path=discovery.immutable_path,
        blob_id=discovery.blob_id,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=raw,
    )
    identity = GitHubIngressIdentity(
        tenant_id=discovery.tenant_id,
        transport_binding_id=discovery.transport_binding_id,
        installation_id=discovery.installation_id,
        actor_id=discovery.actor_id,
        client_id=discovery.client_id,
        repository_id=12345678,
        branch_name="main",
    )

    item = work_item_from_proposal(
        proposal,
        identity=identity,
        discovered_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
    )

    assert item.discovery == discovery
    assert item.raw_bytes is raw


async def test_duplicate_link_is_resolved_before_terminal_row_becomes_dirty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = _discovery()
    raw = _raw()
    validated = validate_ingress(raw, discovery.immutable_path, source_git_blob_sha="2" * 40)
    binding = transaction_binding_sha256(
        ingress_id=discovery.ingress_id,
        installation_id=discovery.installation_id,
        repository_external_id=discovery.repository_external_id,
        immutable_path=discovery.immutable_path,
        commit_id=discovery.commit_id,
        blob_id=discovery.blob_id,
        payload_sha256=hashlib.sha256(raw).digest(),
    )
    command = adapt_live_proposal(
        validated,
        expected_installation_id=discovery.installation_id,
        transaction_binding_sha256=binding,
    )
    principal = CommandPrincipal(
        tenant_id=discovery.tenant_id,
        actor_id=discovery.actor_id,
        client_id=discovery.client_id,
        transport_binding_id=discovery.transport_binding_id,
        scopes=frozenset({"memory:propose"}),
        ingress_id=discovery.ingress_id,
    )
    row = IngressItem(
        ingress_id=discovery.ingress_id,
        tenant_id=discovery.tenant_id,
        transport_binding_id=discovery.transport_binding_id,
        installation_id=discovery.installation_id,
        actor_id=discovery.actor_id,
        client_id=discovery.client_id,
        provider="github",
        repository_external_id=discovery.repository_external_id,
        branch_name=discovery.branch_name,
        immutable_path=discovery.immutable_path,
        external_object_id=discovery.external_object_id,
        commit_id=discovery.commit_id,
        blob_id=discovery.blob_id,
        declared_idempotency_key=command.idempotency_key,
        payload_sha256=hashlib.sha256(raw).digest(),
        state=IngressState.VALIDATED.value,
        result_event_id=None,
        result_memory_id=None,
        error_code=None,
        safe_diagnostic=None,
        discovered_at=discovery.discovered_at,
        validated_at=discovery.discovered_at,
        processed_at=None,
    )
    event_id = UUID("019c0000-0000-7000-8000-000000000041")
    memory_id = UUID("019c0000-0000-7000-8000-000000000042")
    repository = GitHubIngressRepository()
    lookup_state: list[tuple[str, datetime | None]] = []

    async def load_locked(
        _session: AsyncSession, _discovery: GitHubIngressDiscovery
    ) -> IngressItem:
        return row

    async def find_duplicate_link(
        _session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: object,
    ) -> tuple[UUID, UUID]:
        del principal, command
        lookup_state.append((row.state, row.processed_at))
        return event_id, memory_id

    class FlushProbe:
        flushed = False

        async def flush(self) -> None:
            self.flushed = True

    session = FlushProbe()
    monkeypatch.setattr(repository, "_load_locked", load_locked)
    monkeypatch.setattr(repository, "_find_duplicate_link", find_duplicate_link)

    await repository.terminalize(
        cast(AsyncSession, session),
        discovery=discovery,
        principal=principal,
        command=command,
        result=SelectionResult(
            receipt_id=UUID("019c0000-0000-7000-8000-000000000043"),
            decision_id=UUID("019c0000-0000-7000-8000-000000000044"),
            outcome="omit",
            policy_sha256="0" * 64,
            reason_codes=("already_candidate",),
            matched_rule_ids=(),
            event_id=None,
            memory_id=None,
            revision=None,
        ),
        processed_at=discovery.discovered_at,
    )

    assert lookup_state == [(IngressState.VALIDATED.value, None)]
    assert row.state == IngressState.DUPLICATE.value
    assert row.result_event_id == event_id
    assert row.result_memory_id == memory_id
    assert row.processed_at == discovery.discovered_at
    assert session.flushed is True


async def test_terminal_provenance_violation_reports_unchanged_canonical_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = _discovery()
    orchestrator = GitHubIngressOrchestrator(cast(Any, None), cast(Any, None))

    async def register(_: GitHubIngressDiscovery) -> IngressRegistration:
        return IngressRegistration(
            ingress_id=discovery.ingress_id,
            state=IngressState.ACCEPTED,
            created=False,
            same_object=False,
            canonical_changed=False,
        )

    monkeypatch.setattr(orchestrator, "_register", register)

    result = await orchestrator.process(discovery, b"content-must-not-be-read")

    assert result == GitHubIngressProcessResult(
        ingress_id=discovery.ingress_id,
        state=IngressState.ACCEPTED,
        disposition="unchanged",
        code="append_only_violation",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"operation": "remember"}),
        lambda value: value.update({"sensitivity": 1}),
        lambda value: value.update({"scope": "global", "subject_kind": "global"}),
        lambda value: value.update({"scope": "scene_local", "subject_kind": "scene"}),
        lambda value: value.update({"sealed_payload": "forbidden"}),
        lambda value: value.update({"hidden_reasoning": "forbidden"}),
        lambda value: value.update({"metadata": {"producer": "untrusted"}}),
    ],
)
def test_v2_schema_fails_closed_on_sensitive_or_extensible_inputs(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    payload = deepcopy(_payload())
    mutation(payload)

    with pytest.raises(IngressValidationError):
        validate_ingress(_raw(payload), _path(payload))


class _ConcurrentProcessor:
    def __init__(self) -> None:
        self.active = 0
        self.maximum = 0

    async def process(
        self, discovery: GitHubIngressDiscovery, raw_bytes: bytes, /
    ) -> GitHubIngressProcessResult:
        assert raw_bytes == b"{}"
        self.active += 1
        self.maximum = max(self.maximum, self.active)
        await asyncio.sleep(0)
        self.active -= 1
        return GitHubIngressProcessResult(
            ingress_id=discovery.ingress_id,
            state=IngressState.QUARANTINED,
            disposition="terminal",
            code="schema_invalid",
        )


async def test_worker_processes_fifty_distinct_objects_with_bounded_concurrency() -> None:
    processor = _ConcurrentProcessor()
    worker = GitHubIngressWorker(processor, concurrency=7)
    items = tuple(
        GitHubIngressWorkItem(discovery=_discovery(index), raw_bytes=b"{}")
        for index in range(100, 150)
    )

    results = await worker.process_batch(items)

    assert len(results) == 50
    assert len({result.ingress_id for result in results}) == 50
    assert 1 < processor.maximum <= 7


class _RetryingProcessor:
    def __init__(self) -> None:
        self.attempts: dict[UUID, int] = {}

    async def process(
        self, discovery: GitHubIngressDiscovery, raw_bytes: bytes, /
    ) -> GitHubIngressProcessResult:
        assert raw_bytes == b"{}"
        attempt = self.attempts.get(discovery.ingress_id, 0) + 1
        self.attempts[discovery.ingress_id] = attempt
        return GitHubIngressProcessResult(
            ingress_id=discovery.ingress_id,
            state=(IngressState.ACCEPTED if attempt == 3 else IngressState.VALIDATED),
            disposition="terminal" if attempt == 3 else "retry",
            code=None if attempt == 3 else "serialization_exhausted",
        )


async def test_worker_retries_only_explicit_retry_dispositions() -> None:
    processor = _RetryingProcessor()
    worker = GitHubIngressWorker(
        processor,
        concurrency=2,
        max_process_attempts=3,
        retry_delay_seconds=0,
    )
    items = tuple(
        GitHubIngressWorkItem(discovery=_discovery(index), raw_bytes=b"{}") for index in (201, 202)
    )

    results = await worker.process_batch(items)

    assert {result.state for result in results} == {IngressState.ACCEPTED}
    assert set(processor.attempts.values()) == {3}


async def test_worker_rejects_duplicate_provider_objects_before_processing() -> None:
    processor = _ConcurrentProcessor()
    worker = GitHubIngressWorker(processor)
    item = GitHubIngressWorkItem(discovery=_discovery(), raw_bytes=b"{}")

    with pytest.raises(ValueError, match="duplicate provider objects"):
        await worker.process_batch((item, item))
    assert processor.maximum == 0
