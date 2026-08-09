"""Pure deterministic fold for accepted memory events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from kivra_memory.domain.canonical_json import (
    canonical_json_bytes,
    normalize_json_value,
    sha256_digest,
)
from kivra_memory.domain.enums import EventOperation, MemoryStatus, MemoryVisibility
from kivra_memory.domain.events import (
    AffectedMemory,
    BranchCreatedPayload,
    BranchState,
    CandidateLifecyclePayload,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    EventContractError,
    EvidenceAttachedPayload,
    EvidenceRedactedPayload,
    EvidenceState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryStateV3,
    MemoryTransitionPayload,
    PayloadPurgeCompletedPayload,
    SupersededPayload,
    TombstonedPayload,
    UnlinkedPayload,
    validate_event_envelope_shape,
)
from kivra_memory.domain.identifiers import require_uuid7


class FoldError(ValueError):
    """A safe diagnostic for an invalid accepted-event sequence."""

    def __init__(self, code: str, sequence: int, detail: str) -> None:
        super().__init__(f"event {sequence}: {code}: {detail}")
        self.code = code
        self.sequence = sequence
        self.detail = detail


ScopeKey = tuple[UUID, UUID, UUID]


@dataclass(frozen=True, slots=True)
class ProjectionState:
    """Semantic projection state; mappings are immutable snapshots."""

    sequence: int = 0
    memories: Mapping[UUID, MemoryState] = field(default_factory=dict)
    evidence: Mapping[UUID, EvidenceState] = field(default_factory=dict)
    links: Mapping[UUID, LinkState] = field(default_factory=dict)
    conflicts: Mapping[UUID, ConflictState] = field(default_factory=dict)
    conflict_members: Mapping[tuple[UUID, UUID], ConflictMemberState] = field(default_factory=dict)
    branches: Mapping[UUID, BranchState] = field(default_factory=dict)
    event_scopes: Mapping[UUID, ScopeKey] = field(default_factory=dict, repr=False)
    sequence_scopes: Mapping[int, ScopeKey] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("projection sequence cannot be negative")
        for name in (
            "memories",
            "evidence",
            "links",
            "conflicts",
            "conflict_members",
            "branches",
            "event_scopes",
            "sequence_scopes",
        ):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass(frozen=True, slots=True)
class TenantReplayState:
    """Projection plus the immutable tenant boundary for filtered global replay."""

    tenant_id: UUID
    projection: ProjectionState = field(default_factory=ProjectionState)

    def __post_init__(self) -> None:
        require_uuid7(self.tenant_id, field_name="tenant_id")
        has_foreign_row = (
            any(row.tenant_id != self.tenant_id for row in self.projection.memories.values())
            or any(row.tenant_id != self.tenant_id for row in self.projection.evidence.values())
            or any(row.tenant_id != self.tenant_id for row in self.projection.links.values())
            or any(row.tenant_id != self.tenant_id for row in self.projection.conflicts.values())
            or any(row.tenant_id != self.tenant_id for row in self.projection.branches.values())
        )
        if has_foreign_row:
            raise ValueError("tenant replay projection contains another tenant")
        if any(scope[0] != self.tenant_id for scope in self.projection.event_scopes.values()):
            raise ValueError("tenant replay event history contains another tenant")
        if any(scope[0] != self.tenant_id for scope in self.projection.sequence_scopes.values()):
            raise ValueError("tenant replay sequence history contains another tenant")


def _fail(event: MemoryEvent, code: str, detail: str) -> FoldError:
    return FoldError(code, event.sequence, detail)


def _scope(event: MemoryEvent) -> ScopeKey:
    return event.tenant_id, event.lineage_id, event.branch_id


_BRANCH_VISIBILITIES: dict[MemoryVisibility, frozenset[MemoryVisibility]] = {
    MemoryVisibility.PRIVATE_ROOT: frozenset({MemoryVisibility.PRIVATE_ROOT}),
    MemoryVisibility.RESTRICTED: frozenset(
        {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}
    ),
    MemoryVisibility.SHAREABLE: frozenset(
        {
            MemoryVisibility.PRIVATE_ROOT,
            MemoryVisibility.RESTRICTED,
            MemoryVisibility.SHAREABLE,
        }
    ),
    MemoryVisibility.PUBLIC_SEED: frozenset(MemoryVisibility),
}


def _memory_after_images(payload: object) -> tuple[MemoryState, ...]:
    if isinstance(payload, MemoryCreatedPayload | MemoryTransitionPayload):
        return (payload.memory,)
    if isinstance(payload, ConflictOpenedPayload | ConflictResolvedPayload):
        return tuple(change.memory for change in payload.affected_memories)
    return ()


def _validate_branch_visibility(event: MemoryEvent, branch: BranchState, payload: object) -> None:
    allowed = _BRANCH_VISIBILITIES[branch.visibility_ceiling]
    for memory in _memory_after_images(payload):
        if memory.visibility not in allowed:
            raise _fail(event, "branch_visibility_forbidden", "memory exceeds branch visibility")


def _check_scoped_after_image(event: MemoryEvent, item: object) -> None:
    actual = (
        getattr(item, "tenant_id", None),
        getattr(item, "lineage_id", None),
        getattr(item, "branch_id", None),
    )
    if actual != _scope(event):
        raise _fail(event, "scope_mismatch", "after-image ownership differs from event")


def _check_target(event: MemoryEvent, memory: MemoryState) -> None:
    _check_scoped_after_image(event, memory)
    if event.memory_id != memory.memory_id:
        raise _fail(event, "memory_mismatch", "envelope and payload memory IDs differ")
    if (
        isinstance(memory, MemoryStateV3)
        and memory.content_protection == "envelope_encrypted"
        and event.operation in {EventOperation.OBSERVED, EventOperation.REMEMBERED}
    ):
        if event.schema_version != 3 or event.payload_version != 3:
            raise _fail(event, "invalid_sealed_contract", "sealed memory requires event v3")
        aad = canonical_json_bytes(
            {
                "aad_contract": "scalevault.sealed-content-aad.v1",
                "algorithm": "AES-256-GCM",
                "branch_id": event.branch_id,
                "content_key_id": memory.content_key_id,
                "event_id": event.event_id,
                "lineage_id": event.lineage_id,
                "memory_id": memory.memory_id,
                "payload_version": event.payload_version,
                "revision": memory.revision,
                "schema_version": event.schema_version,
                "tenant_id": event.tenant_id,
            }
        )
        if sha256_digest(aad).hex() != memory.sealed_content.aad_sha256:
            raise _fail(event, "invalid_sealed_binding", "sealed memory AAD binding differs")


def _check_revision(
    event: MemoryEvent,
    current: MemoryState,
    previous_revision: int,
    after: MemoryState,
    *,
    check_envelope: bool = True,
) -> None:
    if check_envelope and event.expected_revision != previous_revision:
        raise _fail(event, "expected_revision_mismatch", "envelope and payload differ")
    if current.revision != previous_revision:
        raise _fail(event, "stale_event_revision", "projection revision differs from event")
    if after.revision != previous_revision + 1:
        raise _fail(event, "invalid_revision", "after-image revision must increment exactly once")
    if after.memory_id != current.memory_id:
        raise _fail(event, "identity_changed", "memory ID cannot change")
    for name in ("tenant_id", "lineage_id", "branch_id", "subject_id", "created_at"):
        if getattr(after, name) != getattr(current, name):
            raise _fail(event, "identity_changed", f"memory {name} cannot change")
    if isinstance(current, MemoryStateV3) or isinstance(after, MemoryStateV3):
        if not isinstance(current, MemoryStateV3) or not isinstance(after, MemoryStateV3):
            raise _fail(
                event,
                "sealed_identity_changed",
                "sealed memory contract cannot change",
            )
        if event.operation not in {
            EventOperation.TOMBSTONED,
            EventOperation.PAYLOAD_PURGE_COMPLETED,
        }:
            raise _fail(
                event,
                "unsupported_sealed_transition",
                "sealed memory transition is unsupported",
            )
        if (
            after.content_key_id != current.content_key_id
            or after.sealed_content != current.sealed_content
        ):
            raise _fail(
                event,
                "sealed_identity_changed",
                "sealed envelope and content-key identity are immutable",
            )
    if after.updated_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "after-image update time must equal event time")


_REVISED_TRANSITIONS: dict[MemoryStatus, frozenset[MemoryStatus]] = {
    MemoryStatus.CANDIDATE: frozenset(
        {MemoryStatus.CANDIDATE, MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}
    ),
    MemoryStatus.ACTIVE: frozenset({MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}),
    MemoryStatus.DISPUTED: frozenset({MemoryStatus.DISPUTED, MemoryStatus.ACTIVE}),
}


def _check_revised_lifecycle(event: MemoryEvent, current: MemoryState, after: MemoryState) -> None:
    allowed = _REVISED_TRANSITIONS.get(current.status, frozenset())
    if after.status not in allowed:
        raise _fail(event, "invalid_lifecycle", "revised event has an invalid status transition")


def _check_candidate_lifecycle(
    event: MemoryEvent,
    current: MemoryState,
    payload: CandidateLifecyclePayload,
    *,
    required_status: MemoryStatus,
) -> None:
    if current.status is not MemoryStatus.CANDIDATE:
        raise _fail(event, "invalid_lifecycle", "candidate lifecycle requires a candidate memory")
    if payload.memory.status is not required_status:
        raise _fail(
            event,
            "invalid_lifecycle",
            f"candidate lifecycle requires {required_status.value}",
        )
    if payload.memory.candidate_expires_at is not None:
        raise _fail(
            event,
            "invalid_lifecycle",
            "candidate lifecycle must clear the expiry deadline",
        )


def _attach_candidate_lifecycle_evidence(
    event: MemoryEvent,
    payload: CandidateLifecyclePayload,
    memories: dict[UUID, MemoryState],
    evidence: dict[UUID, EvidenceState],
) -> None:
    if event.operation is EventOperation.CANDIDATE_EXPIRED and payload.evidence:
        raise _fail(event, "invalid_lifecycle", "candidate expiry cannot attach evidence")
    for item in payload.evidence:
        _attach_evidence(event, EvidenceAttachedPayload(evidence=item), memories, evidence)


def _replace_memory(
    event: MemoryEvent,
    memories: dict[UUID, MemoryState],
    payload: MemoryTransitionPayload,
    *,
    required_status: MemoryStatus | None = None,
    preserve_status: bool = False,
) -> None:
    after = payload.memory
    _check_target(event, after)
    current = memories.get(after.memory_id)
    if current is None:
        raise _fail(event, "missing_memory", "target memory does not exist")
    _check_revision(event, current, payload.previous_revision, after)
    if required_status is not None and after.status != required_status:
        raise _fail(event, "invalid_lifecycle", f"operation requires {required_status.value}")
    if preserve_status and after.status != current.status:
        raise _fail(event, "invalid_lifecycle", "operation must preserve memory status")
    memories[after.memory_id] = after


def _create_memory(
    event: MemoryEvent,
    payload: MemoryCreatedPayload,
    memories: dict[UUID, MemoryState],
    evidence: dict[UUID, EvidenceState],
) -> None:
    memory = payload.memory
    _check_target(event, memory)
    if event.expected_revision is not None:
        raise _fail(event, "unexpected_revision", "create events cannot expect a revision")
    if memory.memory_id in memories:
        raise _fail(event, "duplicate_memory", "memory ID already exists")
    if memory.revision != 1:
        raise _fail(event, "invalid_revision", "new memory revision must be one")
    if memory.created_at != event.created_at or memory.updated_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "new memory timestamps must equal event time")
    if event.operation == EventOperation.OBSERVED and memory.status != MemoryStatus.CANDIDATE:
        raise _fail(event, "invalid_lifecycle", "observed memories must be candidates")
    if event.operation == EventOperation.REMEMBERED and memory.status not in {
        MemoryStatus.CANDIDATE,
        MemoryStatus.ACTIVE,
    }:
        raise _fail(event, "invalid_lifecycle", "remembered memory has invalid initial status")
    memories[memory.memory_id] = memory
    for item in payload.evidence:
        _check_scoped_after_image(event, item)
        if item.memory_id != memory.memory_id:
            raise _fail(event, "evidence_memory_mismatch", "evidence belongs to another memory")
        if item.evidence_id in evidence:
            raise _fail(event, "duplicate_evidence", "evidence ID already exists")
        if item.created_at != event.created_at:
            raise _fail(event, "timestamp_mismatch", "evidence creation time must equal event time")
        evidence[item.evidence_id] = item


def _attach_evidence(
    event: MemoryEvent,
    payload: EvidenceAttachedPayload,
    memories: dict[UUID, MemoryState],
    evidence: dict[UUID, EvidenceState],
) -> None:
    item = payload.evidence
    _check_scoped_after_image(event, item)
    if item.memory_id != event.memory_id:
        raise _fail(event, "evidence_memory_mismatch", "evidence belongs to another memory")
    target = memories.get(item.memory_id)
    if target is None:
        raise _fail(event, "missing_memory", "evidence target does not exist")
    if target.status not in {MemoryStatus.CANDIDATE, MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}:
        raise _fail(event, "invalid_lifecycle", "terminal memory cannot accept evidence")
    if item.status != "active":
        raise _fail(event, "invalid_evidence_state", "attached evidence must be active")
    if item.created_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "evidence creation time must equal event time")
    if item.evidence_id in evidence:
        raise _fail(event, "duplicate_evidence", "evidence ID already exists")
    evidence[item.evidence_id] = item


def _redact_evidence(
    event: MemoryEvent,
    payload: EvidenceRedactedPayload,
    evidence: dict[UUID, EvidenceState],
) -> None:
    current = evidence.get(payload.evidence_id)
    if current is None:
        raise _fail(event, "missing_evidence", "redacted evidence does not exist")
    if event.memory_id != payload.memory_id or current.memory_id != payload.memory_id:
        raise _fail(event, "evidence_memory_mismatch", "evidence belongs to another memory")
    if payload.redacted_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "redaction time must equal event time")
    del evidence[payload.evidence_id]


def _link(
    event: MemoryEvent,
    payload: LinkedPayload | SupersededPayload,
    memories: dict[UUID, MemoryState],
    links: dict[UUID, LinkState],
) -> None:
    item = payload.link
    _check_scoped_after_image(event, item)
    if item.link_id in links:
        raise _fail(event, "duplicate_link", "link ID already exists")
    if item.status != "active":
        raise _fail(event, "invalid_link_state", "new link must be active")
    if item.created_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "link creation time must equal event time")
    if item.source_memory_id not in memories or item.target_memory_id not in memories:
        raise _fail(event, "missing_link_endpoint", "link endpoint does not exist")
    links[item.link_id] = item


def _unlink(event: MemoryEvent, payload: UnlinkedPayload, links: dict[UUID, LinkState]) -> None:
    item = payload.link
    _check_scoped_after_image(event, item)
    current = links.get(item.link_id)
    if current is None:
        raise _fail(event, "missing_link", "unlinked relationship does not exist")
    if current.status != "active" or item.status != "unlinked":
        raise _fail(event, "invalid_link_state", "link must transition active to unlinked")
    if item.unlinked_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "unlink time must equal event time")
    for name in (
        "link_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "source_memory_id",
        "target_memory_id",
        "link_type",
        "created_at",
    ):
        if getattr(item, name) != getattr(current, name):
            raise _fail(event, "identity_changed", f"link {name} cannot change")
    links[item.link_id] = item


def _apply_affected_memories(
    event: MemoryEvent,
    affected: tuple[AffectedMemory, ...],
    memories: dict[UUID, MemoryState],
    *,
    opening: bool,
) -> set[UUID]:
    ids: set[UUID] = set()
    for change in affected:
        after = change.memory
        if after.memory_id in ids:
            raise _fail(event, "duplicate_conflict_member", "memory appears twice in transition")
        ids.add(after.memory_id)
        _check_scoped_after_image(event, after)
        current = memories.get(after.memory_id)
        if current is None:
            raise _fail(event, "missing_memory", "conflict member does not exist")
        _check_revision(
            event,
            current,
            change.previous_revision,
            after,
            check_envelope=False,
        )
        if opening:
            if current.status not in {MemoryStatus.CANDIDATE, MemoryStatus.ACTIVE}:
                raise _fail(event, "invalid_lifecycle", "only current claims can enter conflict")
            if after.status != MemoryStatus.DISPUTED:
                raise _fail(event, "invalid_lifecycle", "opened conflict members must be disputed")
        else:
            if current.status != MemoryStatus.DISPUTED:
                raise _fail(
                    event, "invalid_lifecycle", "resolved conflict members must be disputed"
                )
            if after.status not in {
                MemoryStatus.ACTIVE,
                MemoryStatus.SUPERSEDED,
                MemoryStatus.RETIRED,
            }:
                raise _fail(event, "invalid_lifecycle", "invalid resolved member status")
        memories[after.memory_id] = after
    return ids


def _open_conflict(
    event: MemoryEvent,
    payload: ConflictOpenedPayload,
    memories: dict[UUID, MemoryState],
    conflicts: dict[UUID, ConflictState],
    conflict_members: dict[tuple[UUID, UUID], ConflictMemberState],
) -> None:
    conflict = payload.conflict
    _check_scoped_after_image(event, conflict)
    if conflict.conflict_id in conflicts:
        raise _fail(event, "duplicate_conflict", "conflict ID already exists")
    if conflict.status != "open":
        raise _fail(event, "invalid_conflict_state", "new conflict must be open")
    if conflict.opened_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "conflict open time must equal event time")
    affected_ids = _apply_affected_memories(
        event, payload.affected_memories, memories, opening=True
    )
    member_ids = {member.memory_id for member in payload.members}
    if any(member.joined_at != event.created_at for member in payload.members):
        raise _fail(event, "timestamp_mismatch", "conflict join time must equal event time")
    if affected_ids != member_ids:
        raise _fail(event, "conflict_member_mismatch", "members and transitions differ")
    if any(memories[memory_id].subject_id != conflict.subject_id for memory_id in member_ids):
        raise _fail(event, "conflict_subject_mismatch", "members do not share conflict subject")
    conflicts[conflict.conflict_id] = conflict
    for member in payload.members:
        key = (member.conflict_id, member.memory_id)
        if key in conflict_members:
            raise _fail(event, "duplicate_conflict_member", "conflict membership already exists")
        conflict_members[key] = member


def _resolve_conflict(
    event: MemoryEvent,
    payload: ConflictResolvedPayload,
    memories: dict[UUID, MemoryState],
    conflicts: dict[UUID, ConflictState],
    conflict_members: dict[tuple[UUID, UUID], ConflictMemberState],
) -> None:
    conflict = payload.conflict
    _check_scoped_after_image(event, conflict)
    current = conflicts.get(conflict.conflict_id)
    if current is None:
        raise _fail(event, "missing_conflict", "resolved conflict does not exist")
    if current.status != "open" or conflict.status != "resolved":
        raise _fail(event, "invalid_conflict_state", "conflict must transition open to resolved")
    if conflict.resolved_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "conflict resolution time must equal event time")
    for name in (
        "conflict_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "subject_id",
        "reason",
        "opened_at",
    ):
        if getattr(conflict, name) != getattr(current, name):
            raise _fail(event, "identity_changed", f"conflict {name} cannot change")
    current_member_ids = {
        memory_id
        for (conflict_id, memory_id) in conflict_members
        if conflict_id == conflict.conflict_id
    }
    if current_member_ids != {member.memory_id for member in payload.members}:
        raise _fail(event, "conflict_member_mismatch", "resolution cannot change membership")
    for member in payload.members:
        old_member = conflict_members[(member.conflict_id, member.memory_id)]
        if member.joined_at != old_member.joined_at:
            raise _fail(event, "identity_changed", "conflict member join time cannot change")
    affected_ids = _apply_affected_memories(
        event, payload.affected_memories, memories, opening=False
    )
    if affected_ids != {member.memory_id for member in payload.members}:
        raise _fail(event, "conflict_member_mismatch", "members and transitions differ")
    conflicts[conflict.conflict_id] = conflict
    for key in tuple(conflict_members):
        if key[0] == conflict.conflict_id:
            del conflict_members[key]
    for member in payload.members:
        conflict_members[(member.conflict_id, member.memory_id)] = member


def _create_branch(
    event: MemoryEvent,
    payload: BranchCreatedPayload,
    branches: dict[UUID, BranchState],
    sequence_scopes: Mapping[int, ScopeKey],
) -> None:
    branch = payload.branch
    _check_scoped_after_image(event, branch)
    if branch.branch_id != event.branch_id:
        raise _fail(event, "branch_mismatch", "envelope and payload branch IDs differ")
    if branch.branch_id in branches:
        raise _fail(event, "duplicate_branch", "branch ID already exists")
    if branch.created_at != event.created_at:
        raise _fail(event, "timestamp_mismatch", "branch creation time must equal event time")
    if branch.parent_branch_id is not None:
        parent = branches.get(branch.parent_branch_id)
        if parent is None:
            raise _fail(event, "missing_parent_branch", "parent branch does not exist")
        if parent.tenant_id != branch.tenant_id or parent.lineage_id != branch.lineage_id:
            raise _fail(event, "branch_scope_mismatch", "parent crosses tenant or lineage")
        fork_scope = sequence_scopes.get(branch.fork_event_sequence or 0)
        expected_scope = (branch.tenant_id, branch.lineage_id, branch.parent_branch_id)
        if fork_scope != expected_scope:
            raise _fail(event, "invalid_fork_sequence", "fork event is not on the parent branch")
    branches[branch.branch_id] = branch


def _fold_event(
    state: ProjectionState, event: MemoryEvent, *, require_contiguous_sequence: bool
) -> ProjectionState:
    """Verify and apply one event using the selected global-sequence policy."""

    if require_contiguous_sequence and event.sequence != state.sequence + 1:
        raise _fail(event, "sequence_gap", f"expected sequence {state.sequence + 1}")
    if not require_contiguous_sequence and event.sequence <= state.sequence:
        raise _fail(event, "sequence_not_increasing", "tenant replay sequence must increase")
    try:
        validate_event_envelope_shape(event)
    except EventContractError as error:
        raise _fail(event, "invalid_envelope", str(error)) from error
    event.verify_hashes()
    if event.event_id in state.event_scopes:
        raise _fail(event, "duplicate_event", "event ID already exists")
    if event.operation != EventOperation.BRANCH_CREATED:
        branch = state.branches.get(event.branch_id)
        if branch is None:
            raise _fail(event, "missing_branch", "event branch does not exist")
        if (branch.tenant_id, branch.lineage_id) != (event.tenant_id, event.lineage_id):
            raise _fail(event, "branch_scope_mismatch", "event branch crosses tenant or lineage")
    if event.causation_event_id is not None:
        cause_scope = state.event_scopes.get(event.causation_event_id)
        if cause_scope is None:
            raise _fail(event, "missing_causation", "causation event is not earlier in the stream")
        if cause_scope[:2] != _scope(event)[:2]:
            raise _fail(event, "causation_scope_mismatch", "causation crosses tenant or lineage")

    memories = dict(state.memories)
    evidence = dict(state.evidence)
    links = dict(state.links)
    conflicts = dict(state.conflicts)
    conflict_members = dict(state.conflict_members)
    branches = dict(state.branches)
    payload = event.typed_payload()
    if event.operation != EventOperation.BRANCH_CREATED:
        _validate_branch_visibility(event, branches[event.branch_id], payload)

    match event.operation:
        case EventOperation.OBSERVED | EventOperation.REMEMBERED:
            assert isinstance(payload, MemoryCreatedPayload)
            _create_memory(event, payload, memories, evidence)
        case EventOperation.CANDIDATE_PROMOTED:
            assert isinstance(payload, CandidateLifecyclePayload)
            current = memories.get(payload.memory.memory_id)
            _replace_memory(event, memories, payload)
            assert current is not None
            _check_candidate_lifecycle(
                event,
                current,
                payload,
                required_status=MemoryStatus.ACTIVE,
            )
            _attach_candidate_lifecycle_evidence(event, payload, memories, evidence)
        case EventOperation.CANDIDATE_EXPIRED:
            assert isinstance(payload, CandidateLifecyclePayload)
            current = memories.get(payload.memory.memory_id)
            _replace_memory(event, memories, payload)
            assert current is not None
            _check_candidate_lifecycle(
                event,
                current,
                payload,
                required_status=MemoryStatus.RETIRED,
            )
            _attach_candidate_lifecycle_evidence(event, payload, memories, evidence)
        case EventOperation.REVISED:
            assert isinstance(payload, MemoryTransitionPayload)
            current = memories.get(payload.memory.memory_id)
            _replace_memory(event, memories, payload)
            assert current is not None
            _check_revised_lifecycle(event, current, payload.memory)
        case EventOperation.VISIBILITY_CHANGED:
            assert isinstance(payload, MemoryTransitionPayload)
            current = memories.get(payload.memory.memory_id)
            _replace_memory(event, memories, payload, preserve_status=True)
            assert current is not None
            if current.status == MemoryStatus.TOMBSTONED:
                raise _fail(event, "invalid_lifecycle", "tombstone is terminal")
            if payload.memory.visibility == current.visibility:
                raise _fail(event, "unchanged_visibility", "visibility did not change")
        case EventOperation.RETIRED:
            assert isinstance(payload, MemoryTransitionPayload)
            current = memories.get(payload.memory.memory_id)
            if current is not None and current.status not in {
                MemoryStatus.CANDIDATE,
                MemoryStatus.ACTIVE,
                MemoryStatus.DISPUTED,
            }:
                raise _fail(event, "invalid_lifecycle", "terminal memory cannot be retired")
            _replace_memory(event, memories, payload, required_status=MemoryStatus.RETIRED)
        case EventOperation.SUPERSEDED:
            assert isinstance(payload, SupersededPayload)
            current = memories.get(payload.memory.memory_id)
            if current is not None and current.status not in {
                MemoryStatus.CANDIDATE,
                MemoryStatus.ACTIVE,
                MemoryStatus.DISPUTED,
            }:
                raise _fail(event, "invalid_lifecycle", "terminal memory cannot be superseded")
            _replace_memory(event, memories, payload, required_status=MemoryStatus.SUPERSEDED)
            _link(event, payload, memories, links)
        case EventOperation.TOMBSTONED:
            assert isinstance(payload, TombstonedPayload)
            current = memories.get(payload.memory.memory_id)
            if current is not None and current.status == MemoryStatus.TOMBSTONED:
                raise _fail(event, "invalid_lifecycle", "tombstone is terminal")
            if payload.forget_mode == "hard" and (
                current is None
                or current.content_protection != "envelope_encrypted"
                or payload.memory.content_protection != "envelope_encrypted"
                or payload.memory.content_key_id != current.content_key_id
            ):
                raise _fail(
                    event,
                    "hard_forget_unprotected",
                    "hard forget requires stable envelope-encryption metadata",
                )
            _replace_memory(event, memories, payload, required_status=MemoryStatus.TOMBSTONED)
            for evidence_id, item in tuple(evidence.items()):
                if item.memory_id == payload.memory.memory_id:
                    raise _fail(
                        event,
                        "unsanitized_tombstone",
                        f"active evidence remains for {evidence_id}",
                    )
        case EventOperation.EVIDENCE_ATTACHED:
            assert isinstance(payload, EvidenceAttachedPayload)
            _attach_evidence(event, payload, memories, evidence)
        case EventOperation.EVIDENCE_REDACTED:
            assert isinstance(payload, EvidenceRedactedPayload)
            _redact_evidence(event, payload, evidence)
        case EventOperation.LINKED:
            assert isinstance(payload, LinkedPayload)
            _link(event, payload, memories, links)
        case EventOperation.UNLINKED:
            assert isinstance(payload, UnlinkedPayload)
            _unlink(event, payload, links)
        case EventOperation.CONFLICT_OPENED:
            assert isinstance(payload, ConflictOpenedPayload)
            _open_conflict(event, payload, memories, conflicts, conflict_members)
        case EventOperation.CONFLICT_RESOLVED:
            assert isinstance(payload, ConflictResolvedPayload)
            _resolve_conflict(event, payload, memories, conflicts, conflict_members)
        case EventOperation.BRANCH_CREATED:
            assert isinstance(payload, BranchCreatedPayload)
            _create_branch(event, payload, branches, state.sequence_scopes)
        case EventOperation.PAYLOAD_PURGE_COMPLETED:
            assert isinstance(payload, PayloadPurgeCompletedPayload)
            current = memories.get(payload.memory.memory_id)
            if current is None or current.status != MemoryStatus.TOMBSTONED:
                raise _fail(event, "invalid_lifecycle", "purge completion requires a tombstone")
            if current.content_protection != "envelope_encrypted":
                raise _fail(event, "invalid_purge", "purge requires protected content")
            if payload.memory.content_protection != "cryptographically_erased":
                raise _fail(event, "invalid_purge", "purge must record cryptographic erasure")
            if payload.memory.content_key_id != payload.content_key_id:
                raise _fail(event, "invalid_purge", "purge content-key identity differs")
            if payload.key_destroyed_at != event.created_at:
                raise _fail(
                    event, "timestamp_mismatch", "key destruction time must equal event time"
                )
            _replace_memory(event, memories, payload, required_status=MemoryStatus.TOMBSTONED)

    event_scopes = dict(state.event_scopes)
    event_scopes[event.event_id] = _scope(event)
    sequence_scopes = dict(state.sequence_scopes)
    sequence_scopes[event.sequence] = _scope(event)
    return ProjectionState(
        sequence=event.sequence,
        memories=memories,
        evidence=evidence,
        links=links,
        conflicts=conflicts,
        conflict_members=conflict_members,
        branches=branches,
        event_scopes=event_scopes,
        sequence_scopes=sequence_scopes,
    )


def fold_event(state: ProjectionState, event: MemoryEvent) -> ProjectionState:
    """Apply one event from the complete, contiguous global event stream."""

    return _fold_event(state, event, require_contiguous_sequence=True)


def fold_tenant_event(state: TenantReplayState, event: MemoryEvent) -> TenantReplayState:
    """Apply one tenant-filtered event with a strictly increasing global sequence."""

    if event.tenant_id != state.tenant_id:
        raise _fail(event, "tenant_scope_mismatch", "event is outside tenant replay scope")
    projection = _fold_event(
        state.projection,
        event,
        require_contiguous_sequence=False,
    )
    return TenantReplayState(tenant_id=state.tenant_id, projection=projection)


def rebuild(events: Iterable[MemoryEvent]) -> ProjectionState:
    """Fold an accepted event stream from an empty semantic projection."""

    state = ProjectionState()
    for event in events:
        state = fold_event(state, event)
    return state


def rebuild_tenant(tenant_id: UUID, events: Iterable[MemoryEvent]) -> TenantReplayState:
    """Rebuild one tenant from its ordered subset of the global event stream."""

    state = TenantReplayState(tenant_id=tenant_id)
    for event in events:
        state = fold_tenant_event(state, event)
    return state


def canonical_aggregate_bytes(state: ProjectionState, memory_id: UUID) -> bytes:
    """Serialize one canonical semantic aggregate for archive/equivalence checks."""

    memory = state.memories.get(memory_id)
    if memory is None:
        raise KeyError(memory_id)
    evidence = sorted(
        (item for item in state.evidence.values() if item.memory_id == memory_id),
        key=lambda item: str(item.evidence_id),
    )
    links = sorted(
        (
            item
            for item in state.links.values()
            if memory_id in (item.source_memory_id, item.target_memory_id)
        ),
        key=lambda item: (
            item.link_type.value,
            str(item.source_memory_id),
            str(item.target_memory_id),
            str(item.link_id),
        ),
    )
    conflicts = sorted(
        (
            item
            for item in state.conflicts.values()
            if (item.conflict_id, memory_id) in state.conflict_members
        ),
        key=lambda item: str(item.conflict_id),
    )
    conflict_ids = {item.conflict_id for item in conflicts}
    conflict_members = sorted(
        (
            item
            for (conflict_id, _), item in state.conflict_members.items()
            if conflict_id in conflict_ids
        ),
        key=lambda item: (str(item.conflict_id), str(item.memory_id)),
    )
    if len(evidence) > 4096 or len(links) > 4096 or len(conflicts) > 4096:
        raise ValueError("canonical aggregate child collection exceeds v1 bounds")
    if len(conflict_members) > 16384:
        raise ValueError("canonical aggregate conflict membership exceeds v1 bounds")
    memory_value = memory.canonical_value()
    if not isinstance(memory_value, dict):
        raise TypeError("memory canonical value must be an object")
    memory_value = {"schema_version": 1, **memory_value}
    aggregate = normalize_json_value(
        {
            "schema_version": 1,
            "memory": memory_value,
            "evidence": [item.canonical_value() for item in evidence],
            "links": [item.canonical_value() for item in links],
            "conflicts": [item.canonical_value() for item in conflicts],
            "conflict_members": [item.canonical_value() for item in conflict_members],
        }
    )
    return canonical_json_bytes(aggregate)
