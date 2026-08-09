"""Protected staging, application, and replay verification for Genesis import."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select

from kivra_memory.application.genesis_import import (
    GenesisCanonicalMappings,
    GenesisImportEngine,
    GenesisImporterAuthority,
    GenesisImportPlanContext,
    GenesisImportRunContext,
    GenesisSourceRecordContext,
    canonical_genesis_mappings_sha256,
    resolve_genesis_mapping_metadata,
)
from kivra_memory.application.genesis_plan import GenesisImportPlan
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.canonical_json import canonical_json_bytes, normalize_json_value
from kivra_memory.domain.enums import SubjectKind
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.ingress.processor import (
    GenesisNominationInput,
    LegacyProposalProvenance,
    RelationshipBindingStatus,
)
from kivra_memory.ingress.snapshot import IMPORT_MANIFEST_VERSION, SourceContract
from kivra_memory.ingress.validator import IngressFormat
from kivra_memory.policy import SELECTION_V1_PROFILE, SELECTION_V1_PROFILE_SHA256
from kivra_memory.storage.database import Database
from kivra_memory.storage.genesis_import import GenesisImportRepository, GenesisRunStatus
from kivra_memory.storage.models import (
    Actor,
    Branch,
    Client,
    CommandReceipt,
    GenesisImportExclusion,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportSource,
    GenesisImportSupersession,
    Lineage,
    LogicalSession,
    Memory,
    MemoryEvent,
    MemoryEvidence,
    OutboxJob,
    Persona,
    SelectionDecision,
    Subject,
    Tenant,
    TransportBinding,
)

_DIGEST = r"^[0-9a-f]{64}$"
_FROZEN_RAW_COMPATIBILITY_VALUES: dict[str, object] = {
    "/candidates/1/disposition": "federation_shared_candidate",
    "/candidates/1/scope": "federation",
    "/candidates/1/binding/visibility": "federation_shared_candidate",
    "/exclusions/0/scope": "federation",
    "/exclusions/1/scope": "federation",
}


class GenesisApplyError(RuntimeError):
    """A stable, payload-free protected import failure."""


class GenesisOperatorConfig(BaseModel):
    """Root-controlled identities and recovery evidence for one exact import."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["scalevault-genesis-operator-config-v1"]
    expected_plan_sha256: Annotated[str, Field(pattern=_DIGEST)]
    import_run_id: UUID
    pre_state_sha256: Annotated[str, Field(pattern=_DIGEST)]
    backup_reference: Annotated[str, Field(min_length=1, max_length=255)]
    mappings: GenesisCanonicalMappings
    importer_authority: GenesisImporterAuthority

    @field_validator("import_run_id")
    @classmethod
    def validate_run_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="import_run_id")

    @model_validator(mode="after")
    def validate_tenant_authority(self) -> GenesisOperatorConfig:
        if self.importer_authority.actor_id == self.mappings.genesis_actor_id:
            raise ValueError("importer actor must be distinct from Genesis")
        terminal_subjects = tuple(
            item
            for item in self.mappings.subjects
            if item.subject_kind is SubjectKind.GLOBAL
            and item.source_reference == "genesis-import:terminal"
        )
        if len(terminal_subjects) != 1:
            raise ValueError("exact terminal audit subject mapping is required")
        return self

    def principal(self) -> CommandPrincipal:
        return CommandPrincipal(
            tenant_id=self.importer_authority.tenant_id,
            actor_id=self.importer_authority.actor_id,
            client_id=self.importer_authority.client_id,
            transport_binding_id=self.importer_authority.transport_binding_id,
            scopes=frozenset({"memory.write.genesis_import"}),
        )


@dataclass(frozen=True, slots=True)
class PreparedGenesisImport:
    plan: GenesisImportPlan
    run: GenesisImportRun
    sources: tuple[GenesisImportSource, ...] = field(repr=False)
    records: tuple[GenesisImportRecord, ...] = field(repr=False)
    exclusions: tuple[GenesisImportExclusion, ...] = field(repr=False)
    supersessions: tuple[GenesisImportSupersession, ...] = field(repr=False)
    plan_context: GenesisImportPlanContext
    run_context: GenesisImportRunContext
    nominations: tuple[tuple[GenesisNominationInput, GenesisSourceRecordContext], ...] = field(
        repr=False
    )


@dataclass(frozen=True, slots=True)
class GenesisApplyStatus:
    source_count: int
    planned_record_count: int
    terminal_record_count: int
    completed: bool
    canonical_mapping_sha256: str


@dataclass(frozen=True, slots=True)
class _ReplayExpected:
    outcome: str
    receipt_id: UUID
    decision_id: UUID
    event_id: UUID | None
    memory_id: UUID | None
    revision: int | None


@dataclass(frozen=True, slots=True)
class _ReplaySnapshot:
    expected: dict[str, _ReplayExpected]
    row_counts: tuple[int, ...]


def _stable_uuid7(run_id: UUID, kind: str, identity: str) -> UUID:
    """Derive replay-stable UUID7 values while retaining the run's timestamp."""

    digest = hashlib.sha256(
        b"scalevault.genesis-import.uuid7.v1\x00"
        + run_id.bytes
        + kind.encode("ascii")
        + b"\x00"
        + identity.encode("utf-8")
    ).digest()
    timestamp = run_id.int >> 80
    random_a = int.from_bytes(digest[:2], "big") & 0x0FFF
    random_b = int.from_bytes(digest[2:10], "big") & ((1 << 62) - 1)
    return UUID(int=(timestamp << 80) | (7 << 76) | (random_a << 64) | (2 << 62) | random_b)


def _one_or_none(values: tuple[str, ...]) -> str | None:
    unique = tuple(dict.fromkeys(item for item in values if item))
    return unique[0] if len(unique) == 1 else None


def _require_proposal(
    proposal: LegacyProposalProvenance | None,
) -> LegacyProposalProvenance:
    if proposal is None:
        raise GenesisApplyError("invalid_source_provenance")
    return proposal


def prepare_genesis_import(
    plan: GenesisImportPlan, config: GenesisOperatorConfig
) -> PreparedGenesisImport:
    """Recheck the exact digest and losslessly build protected staging rows."""

    try:
        plan.manifest.require_digest(config.expected_plan_sha256)
    except ValueError:
        raise GenesisApplyError("genesis_plan_digest_mismatch") from None

    tenant_id = config.importer_authority.tenant_id
    run_id = config.import_run_id
    plan_digest = bytes.fromhex(config.expected_plan_sha256)
    report = plan.report.value
    parser_versions = report.get("parser_schema_versions")
    if not isinstance(parser_versions, dict):
        raise GenesisApplyError("invalid_genesis_plan")

    run = GenesisImportRun(
        import_run_id=run_id,
        tenant_id=tenant_id,
        source_repository=str(report["source_repository"]),
        snapshot_commit=str(report["source_snapshot_commit"]),
        plan_sha256=plan_digest,
        manifest_version=IMPORT_MANIFEST_VERSION,
        mapping_version=str(report["mapping_version"]),
        compatibility_version=str(report["compatibility_version"]),
        parser_schema_versions=parser_versions,
        policy_id=SELECTION_V1_PROFILE.policy_id,
        policy_version=SELECTION_V1_PROFILE.profile_version,
        policy_sha256=bytes.fromhex(SELECTION_V1_PROFILE_SHA256),
        canonical_mapping_sha256=canonical_genesis_mappings_sha256(config.mappings),
        source_count=len(plan.planned_sources),
        pre_state_sha256=bytes.fromhex(config.pre_state_sha256),
        backup_reference=config.backup_reference,
    )
    plan_context = GenesisImportPlanContext(
        contract_version="scalevault-genesis-import-plan-context-v1",
        plan_sha256=config.expected_plan_sha256,
        source_repository="JTM-rootstorm/scalevault-memory-ingress",
        source_snapshot_commit="7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9",
        mapping_version="genesis-import-mapping-v1",
        compatibility_version="genesis-first-import-compat-v1",
        policy_profile_sha256=("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"),
    )
    run_context = GenesisImportRunContext(
        contract_version="scalevault-genesis-import-run-context-v1",
        import_run_id=run_id,
        plan_sha256=config.expected_plan_sha256,
    )

    sources: list[GenesisImportSource] = []
    records: list[GenesisImportRecord] = []
    exclusions: list[GenesisImportExclusion] = []
    nomination_contexts: list[tuple[GenesisNominationInput, GenesisSourceRecordContext]] = []
    record_ids: dict[str, UUID] = {}
    exclusion_ids: dict[str, UUID] = {}
    source_ids: dict[str, UUID] = {}

    for planned in plan.planned_sources:
        item = planned.source_item
        validated = planned.validated
        processed = planned.processed
        source_id = _stable_uuid7(run_id, "source", item.source_path)
        source_ids[item.source_path] = source_id
        provenance = processed.provenance
        checkpoint = provenance.checkpoint
        proposal = provenance.proposal
        if (checkpoint is None) == (proposal is None):
            raise GenesisApplyError("invalid_source_provenance")
        candidates = provenance.candidates
        bindings = tuple(candidate.binding for candidate in candidates)
        compatibility = tuple(code.value for code in validated.compatibility_codes)
        parsed_canonical = canonical_json_bytes(validated.payload)
        source_kind = {
            IngressFormat.PROPOSAL_V1: "proposal_v1",
            IngressFormat.GENESIS_CHECKPOINT_V1: "checkpoint_v1",
            IngressFormat.GENESIS_CHECKPOINT_V2: "checkpoint_v2",
        }[validated.format]
        source_contract_version = {
            SourceContract.PROPOSAL_V1: "proposal-v1.schema.1",
            SourceContract.CHECKPOINT_V1: "checkpoint-v1.documented.1",
            SourceContract.CHECKPOINT_V2: "checkpoint-v2.schema.1",
        }[item.source_contract]
        sources.append(
            GenesisImportSource(
                source_id=source_id,
                tenant_id=tenant_id,
                import_run_id=run_id,
                source_kind=source_kind,
                source_contract_version=source_contract_version,
                source_identity=item.source_id,
                source_path=item.source_path,
                blob_object_id=item.source_git_blob_sha,
                raw_sha256=bytes.fromhex(item.source_raw_sha256),
                raw_bytes=item.raw_bytes,
                introducing_commit=None,
                parsed_document=validated.payload,
                parsed_canonical_json=parsed_canonical,
                parsed_canonical_sha256=hashlib.sha256(parsed_canonical).digest(),
                proposal_id=proposal.proposal_id if proposal else None,
                checkpoint_id=checkpoint.checkpoint_id if checkpoint else None,
                previous_checkpoint_id=checkpoint.previous_checkpoint if checkpoint else None,
                declared_idempotency_key=(
                    checkpoint.idempotency_key
                    if checkpoint is not None
                    else _require_proposal(proposal).idempotency_key
                ),
                origin_actor_ref=checkpoint.origin_actor if checkpoint else None,
                runtime_ref=checkpoint.origin_runtime if checkpoint else None,
                trigger_identity=checkpoint.triggered_by if checkpoint else None,
                source_conversation_ref=(
                    checkpoint.source_conversation.conversation_reference if checkpoint else None
                ),
                owner_ref=_one_or_none(tuple(binding.owner_actor_id or "" for binding in bindings)),
                perspective_ref=_one_or_none(
                    tuple(binding.perspective_actor_id or "" for binding in bindings)
                ),
                subject_ref=_one_or_none(
                    tuple(actor for binding in bindings for actor in binding.subject_actor_ids)
                ),
                participant_refs=list(
                    dict.fromkeys(
                        actor for binding in bindings for actor in binding.participant_actor_ids
                    )
                ),
                relationship_ref=_one_or_none(
                    tuple(rel for binding in bindings for rel in binding.relationship_ids)
                ),
                interaction_ref=_one_or_none(
                    tuple(binding.interaction_id or "" for binding in bindings)
                ),
                original_visibility=_one_or_none(
                    tuple(binding.original_visibility or "" for binding in bindings)
                ),
                binding_metadata={
                    "candidate_bindings": [binding.model_dump(mode="json") for binding in bindings]
                },
                provenance_metadata=provenance.model_dump(mode="json"),
                compatibility_correction_version=(
                    "genesis-first-import-compat-v1" if compatibility else None
                ),
                raw_compatibility_values=(
                    _FROZEN_RAW_COMPATIBILITY_VALUES.copy() if compatibility else None
                ),
            )
        )

        candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        for nomination in processed.nominations:
            candidate = candidates_by_id.get(nomination.source_record_id)
            record_id = _stable_uuid7(
                run_id, "record", f"{item.source_path}\x00{nomination.source_record_id}"
            )
            if nomination.source_record_id in record_ids:
                raise GenesisApplyError("duplicate_source_record_identity")
            record_ids[nomination.source_record_id] = record_id
            binding = candidate.binding if candidate else None
            owner_reference = binding.owner_actor_id if binding else None
            perspective_reference = binding.perspective_actor_id if binding else None
            if (owner_reference, perspective_reference) not in {
                (None, None),
                ("kivra:genesis", "kivra:genesis"),
            }:
                raise GenesisApplyError("unresolved_genesis_mapping")
            resolved_owner: Literal["kivra:genesis"] | None = (
                "kivra:genesis" if owner_reference is not None else None
            )
            resolved_perspective: Literal["kivra:genesis"] | None = (
                "kivra:genesis" if perspective_reference is not None else None
            )
            unresolved_binding = (
                nomination.review_controls.relationship_binding_status
                is RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
            )
            source_context = GenesisSourceRecordContext(
                contract_version="scalevault-genesis-source-record-context-v1",
                import_record_id=record_id,
                import_source_id=source_id,
                source_id=item.source_id,
                source_record_id=nomination.source_record_id,
                source_path=item.source_path,
                source_git_blob_sha=item.source_git_blob_sha,
                source_raw_sha256=item.source_raw_sha256,
                nomination_sha256=nomination.nomination_sha256,
                owner_actor_reference=resolved_owner,
                perspective_actor_reference=resolved_perspective,
                compatibility_codes=compatibility,
            )
            try:
                resolved_target = resolve_genesis_mapping_metadata(
                    nomination, config.mappings, source_context
                )
            except Exception:
                raise GenesisApplyError("unresolved_genesis_mapping") from None
            normalized_mapping_metadata = normalize_json_value(
                resolved_target.mapping_metadata.model_dump(mode="python")
            )
            if not isinstance(normalized_mapping_metadata, dict):
                raise GenesisApplyError("invalid_genesis_mapping")
            records.append(
                GenesisImportRecord(
                    import_record_id=record_id,
                    tenant_id=tenant_id,
                    import_run_id=run_id,
                    source_id=source_id,
                    lineage_id=config.mappings.lineage_id,
                    branch_id=config.mappings.branch_id,
                    record_kind="candidate" if candidate else "proposal",
                    source_item_identity=nomination.source_record_id,
                    source_item_document=(
                        candidate.model_dump(mode="json")
                        if candidate
                        else _require_proposal(proposal).model_dump(mode="json")
                    ),
                    nomination_sha256=bytes.fromhex(nomination.nomination_sha256),
                    nomination_idempotency_key=nomination.idempotency_key,
                    mapping_version="genesis-import-mapping-v1",
                    selection_basis="imported_legacy",
                    qualifier="imported_source_unreconciled",
                    requested_outcome_ceiling="candidate",
                    effective_visibility="private_root",
                    unresolved_legacy_binding=unresolved_binding,
                    original_candidate_type=candidate.candidate_type
                    if candidate
                    else _require_proposal(proposal).category,
                    original_disposition=(
                        candidate.disposition
                        if candidate
                        else _require_proposal(proposal).operation
                    ),
                    original_confidence=(
                        candidate.source_confidence
                        if candidate
                        else _require_proposal(proposal).source_confidence
                    ),
                    original_scope=(
                        candidate.source_scope if candidate else _require_proposal(proposal).scope
                    ),
                    original_ontology=(
                        candidate.source_ontology
                        if candidate
                        else _require_proposal(proposal).source_ontology
                    ),
                    original_visibility=(binding.original_visibility if binding else None),
                    review_recommendation=(
                        candidate.review.recommended_action if candidate else "review_and_scope"
                    ),
                    evidence_references=[
                        reference.model_dump(mode="json")
                        for reference in nomination.evidence_references
                    ],
                    interpretation_limits=list(nomination.semantics.interpretation_limits),
                    mapping_metadata=normalized_mapping_metadata,
                    provenance_metadata={
                        "source": provenance.source.model_dump(mode="json"),
                        "checkpoint": (checkpoint.model_dump(mode="json") if checkpoint else None),
                    },
                    processing_state="planned",
                    selection_decision_id=None,
                    event_id=None,
                    memory_id=None,
                    processed_at=None,
                )
            )
            nomination_contexts.append((nomination, source_context))

        for exclusion in provenance.exclusions:
            exclusion_id = _stable_uuid7(
                run_id, "exclusion", f"{item.source_path}\x00{exclusion.exclusion_id}"
            )
            if exclusion.exclusion_id in exclusion_ids:
                raise GenesisApplyError("duplicate_exclusion_identity")
            exclusion_ids[exclusion.exclusion_id] = exclusion_id
            exclusions.append(
                GenesisImportExclusion(
                    exclusion_id=exclusion_id,
                    tenant_id=tenant_id,
                    import_run_id=run_id,
                    source_id=source_id,
                    applies_to_record_id=None,
                    source_exclusion_identity=exclusion.exclusion_id,
                    claim=exclusion.claim,
                    reason=exclusion.reason,
                    raw_scope=exclusion.scope,
                    actor_ref=_one_or_none(exclusion.applies_to_actor_ids),
                    relationship_ref=_one_or_none(exclusion.applies_to_relationship_ids),
                    binding_metadata={
                        "actor_refs": list(exclusion.applies_to_actor_ids),
                        "relationship_refs": list(exclusion.applies_to_relationship_ids),
                    },
                    provenance_metadata=exclusion.model_dump(mode="json"),
                    blocks_automatic_promotion=True,
                )
            )

    supersessions: list[GenesisImportSupersession] = []
    for planned in plan.planned_sources:
        source_id = source_ids[planned.source_item.source_path]
        for candidate in planned.processed.provenance.candidates:
            for predecessor in candidate.supersedes:
                if predecessor not in record_ids:
                    raise GenesisApplyError("unresolved_supersession")
                supersessions.append(
                    GenesisImportSupersession(
                        supersession_id=_stable_uuid7(
                            run_id,
                            "supersession",
                            f"candidate\x00{candidate.candidate_id}\x00{predecessor}",
                        ),
                        tenant_id=tenant_id,
                        import_run_id=run_id,
                        source_id=source_id,
                        predecessor_record_id=record_ids[predecessor],
                        predecessor_exclusion_id=None,
                        successor_record_id=record_ids[candidate.candidate_id],
                        successor_exclusion_id=None,
                        provenance_metadata={"origin_kind": "candidate"},
                    )
                )
        for exclusion in planned.processed.provenance.exclusions:
            for predecessor in exclusion.supersedes:
                if predecessor not in exclusion_ids:
                    raise GenesisApplyError("unresolved_supersession")
                supersessions.append(
                    GenesisImportSupersession(
                        supersession_id=_stable_uuid7(
                            run_id,
                            "supersession",
                            f"exclusion\x00{exclusion.exclusion_id}\x00{predecessor}",
                        ),
                        tenant_id=tenant_id,
                        import_run_id=run_id,
                        source_id=source_id,
                        predecessor_record_id=None,
                        predecessor_exclusion_id=exclusion_ids[predecessor],
                        successor_record_id=None,
                        successor_exclusion_id=exclusion_ids[exclusion.exclusion_id],
                        provenance_metadata={"origin_kind": "exclusion"},
                    )
                )

    return PreparedGenesisImport(
        plan=plan,
        run=run,
        sources=tuple(sources),
        records=tuple(records),
        exclusions=tuple(exclusions),
        supersessions=tuple(supersessions),
        plan_context=plan_context,
        run_context=run_context,
        nominations=tuple(nomination_contexts),
    )


def _safe_status(status: GenesisRunStatus) -> GenesisApplyStatus:
    return GenesisApplyStatus(
        source_count=status.source_count,
        planned_record_count=status.planned_record_count,
        terminal_record_count=status.terminal_record_count,
        completed=status.completed,
        canonical_mapping_sha256=status.canonical_mapping_sha256.hex(),
    )


async def preflight_genesis_import(
    database: Database,
    prepared: PreparedGenesisImport,
    config: GenesisOperatorConfig,
) -> None:
    """Validate the complete existing identity graph before immutable staging."""

    tenant_id = config.importer_authority.tenant_id
    if prepared.run.tenant_id != tenant_id or bytes(
        prepared.run.canonical_mapping_sha256
    ) != canonical_genesis_mappings_sha256(config.mappings):
        raise GenesisApplyError("genesis_identity_preflight_failed")
    now = datetime.now(UTC)
    async with database.tenant_session(tenant_id) as session:
        tenant = await session.get(Tenant, tenant_id)
        importer = await session.get(Actor, config.importer_authority.actor_id)
        genesis = await session.get(Actor, config.mappings.genesis_actor_id)
        client = await session.get(Client, config.importer_authority.client_id)
        binding = await session.get(
            TransportBinding, config.importer_authority.transport_binding_id
        )
        persona = await session.get(Persona, config.mappings.persona_id)
        lineage = await session.get(Lineage, config.mappings.lineage_id)
        branch = await session.get(Branch, config.mappings.branch_id)
        if (
            tenant is None
            or tenant.state != "active"
            or importer is None
            or importer.tenant_id != tenant_id
            or importer.kind != "service"
            or importer.revoked_at is not None
            or genesis is None
            or genesis.tenant_id != tenant_id
            or genesis.kind != "persona"
            or genesis.revoked_at is not None
            or client is None
            or client.tenant_id != tenant_id
            or client.kind != "operator"
            or client.transport_kind != "internal_service"
            or client.revoked_at is not None
            or set(client.scopes) != {"memory.write.genesis_import"}
            or binding is None
            or binding.tenant_id != tenant_id
            or binding.actor_id != importer.actor_id
            or binding.client_id != client.client_id
            or binding.transport_kind != "internal_service"
            or binding.disclosure_boundary != "internal"
            or binding.installation_id is not None
            or (binding.valid_until is not None and binding.valid_until <= now)
            or binding.authorized_operations != {"operations": ["observed"]}
            or persona is None
            or persona.tenant_id != tenant_id
            or persona.actor_id != genesis.actor_id
            or persona.retired_at is not None
            or lineage is None
            or lineage.tenant_id != tenant_id
            or lineage.persona_id != persona.persona_id
            or lineage.sealed_at is not None
            or branch is None
            or branch.tenant_id != tenant_id
            or branch.lineage_id != lineage.lineage_id
            or branch.sealed_at is not None
        ):
            raise GenesisApplyError("genesis_identity_preflight_failed")

        sessions: dict[str, LogicalSession] = {}
        for session_mapping in config.mappings.sessions:
            session_row = await session.get(LogicalSession, session_mapping.logical_session_id)
            if (
                session_row is None
                or session_row.tenant_id != tenant_id
                or session_row.actor_id != genesis.actor_id
                or session_row.lineage_id != lineage.lineage_id
                or session_row.branch_id != branch.branch_id
            ):
                raise GenesisApplyError("genesis_identity_preflight_failed")
            sessions[session_mapping.source_reference] = session_row

        for subject_mapping in config.mappings.subjects:
            subject_row = await session.get(Subject, subject_mapping.subject_id)
            source_reference = subject_mapping.source_reference
            anchor_valid = {
                SubjectKind.GLOBAL: (
                    subject_row is not None
                    and subject_row.persona_id is None
                    and subject_row.relationship_actor_id is None
                    and subject_row.project_ref is None
                    and subject_row.episode_ref is None
                    and subject_row.origin_session_id is None
                ),
                SubjectKind.PERSONA: (
                    subject_row is not None and subject_row.persona_id == persona.persona_id
                ),
                SubjectKind.RELATIONSHIP: (
                    subject_row is not None
                    and subject_row.relationship_actor_id is not None
                    and source_reference is not None
                ),
                SubjectKind.PROJECT: (
                    subject_row is not None and subject_row.project_ref == source_reference
                ),
                SubjectKind.EPISODE: (
                    subject_row is not None and subject_row.episode_ref == source_reference
                ),
                SubjectKind.SCENE: (
                    subject_row is not None
                    and source_reference in sessions
                    and subject_row.origin_session_id == sessions[source_reference].session_id
                ),
                SubjectKind.CONCEPT: (
                    subject_row is not None
                    and subject_row.persona_id is None
                    and subject_row.relationship_actor_id is None
                    and subject_row.project_ref is None
                    and subject_row.episode_ref is None
                    and subject_row.origin_session_id is None
                ),
            }[subject_mapping.subject_kind]
            if (
                subject_row is None
                or subject_row.tenant_id != tenant_id
                or subject_row.lineage_id != lineage.lineage_id
                or subject_row.kind != subject_mapping.subject_kind.value
                or not anchor_valid
            ):
                raise GenesisApplyError("genesis_identity_preflight_failed")


async def stage_genesis_import(
    database: Database,
    prepared: PreparedGenesisImport,
    config: GenesisOperatorConfig,
) -> GenesisApplyStatus:
    await preflight_genesis_import(database, prepared, config)
    async with database.tenant_session(prepared.run.tenant_id) as session:
        status = await GenesisImportRepository(session).stage_import_plan(
            run=prepared.run,
            sources=prepared.sources,
            records=prepared.records,
            exclusions=prepared.exclusions,
            supersessions=prepared.supersessions,
        )
    return _safe_status(status)


async def apply_genesis_import(
    database: Database,
    prepared: PreparedGenesisImport,
    config: GenesisOperatorConfig,
) -> GenesisApplyStatus:
    await stage_genesis_import(database, prepared, config)
    engine = GenesisImportEngine(
        database.session_factory, config.mappings, config.importer_authority
    )
    principal = config.principal()
    for nomination, source_context in prepared.nominations:
        await engine.execute(
            principal,
            nomination,
            plan=prepared.plan_context,
            run=prepared.run_context,
            source_record=source_context,
        )
    return await genesis_import_status(database, prepared)


async def _replay_snapshot(
    database: Database,
    prepared: PreparedGenesisImport,
    config: GenesisOperatorConfig,
) -> _ReplaySnapshot:
    tenant_id = prepared.run.tenant_id
    async with database.tenant_session(tenant_id) as session:
        records = tuple(
            (
                await session.scalars(
                    select(GenesisImportRecord)
                    .where(
                        GenesisImportRecord.tenant_id == tenant_id,
                        GenesisImportRecord.import_run_id == prepared.run.import_run_id,
                    )
                    .order_by(GenesisImportRecord.import_record_id)
                )
            ).all()
        )
        keys = tuple(record.nomination_idempotency_key for record in records)
        receipts = tuple(
            (
                await session.scalars(
                    select(CommandReceipt).where(
                        CommandReceipt.tenant_id == tenant_id,
                        CommandReceipt.client_id == config.importer_authority.client_id,
                        CommandReceipt.idempotency_key.in_(keys),
                    )
                )
            ).all()
        )
        receipts_by_key = {receipt.idempotency_key: receipt for receipt in receipts}
        expected: dict[str, _ReplayExpected] = {}
        for record in records:
            receipt = receipts_by_key.get(record.nomination_idempotency_key)
            if (
                receipt is None
                or record.processing_state == "planned"
                or record.selection_decision_id is None
                or receipt.selection_decision_id != record.selection_decision_id
                or receipt.event_id != record.event_id
                or receipt.memory_id != record.memory_id
            ):
                raise GenesisApplyError("genesis_replay_evidence_mismatch")
            expected[record.nomination_idempotency_key] = _ReplayExpected(
                outcome=record.processing_state,
                receipt_id=receipt.receipt_id,
                decision_id=record.selection_decision_id,
                event_id=record.event_id,
                memory_id=record.memory_id,
                revision=receipt.memory_revision,
            )
        if len(expected) != len(prepared.nominations):
            raise GenesisApplyError("genesis_replay_evidence_mismatch")
        row_count_values: list[int] = []
        for model in (
            SelectionDecision,
            CommandReceipt,
            MemoryEvent,
            Memory,
            MemoryEvidence,
            OutboxJob,
        ):
            count = await session.scalar(
                select(func.count()).select_from(model).where(model.tenant_id == tenant_id)
            )
            row_count_values.append(int(count or 0))
        row_counts = tuple(row_count_values)
    return _ReplaySnapshot(expected=expected, row_counts=row_counts)


async def verify_genesis_import(
    database: Database,
    prepared: PreparedGenesisImport,
    config: GenesisOperatorConfig,
) -> GenesisApplyStatus:
    await preflight_genesis_import(database, prepared, config)
    status = await genesis_import_status(database, prepared)
    if status.planned_record_count:
        raise GenesisApplyError("genesis_import_incomplete")
    if status.completed:
        return status
    engine = GenesisImportEngine(
        database.session_factory, config.mappings, config.importer_authority
    )
    principal = config.principal()
    before = await _replay_snapshot(database, prepared, config)
    for nomination, source_context in prepared.nominations:
        result = await engine.execute(
            principal,
            nomination,
            plan=prepared.plan_context,
            run=prepared.run_context,
            source_record=source_context,
        )
        expected = before.expected.get(nomination.idempotency_key)
        if (
            expected is None
            or not result.idempotent_replay
            or result.outcome != expected.outcome
            or result.receipt_id != expected.receipt_id
            or result.decision_id != expected.decision_id
            or result.event_id != expected.event_id
            or result.memory_id != expected.memory_id
            or result.revision != expected.revision
        ):
            raise GenesisApplyError("genesis_replay_not_idempotent")
    after = await _replay_snapshot(database, prepared, config)
    if after != before:
        raise GenesisApplyError("genesis_replay_not_idempotent")
    async with database.tenant_session(prepared.run.tenant_id) as session:
        await GenesisImportRepository(session).complete_run(
            tenant_id=prepared.run.tenant_id,
            import_run_id=prepared.run.import_run_id,
            plan_sha256=bytes(prepared.run.plan_sha256),
            pre_state_sha256=bytes(prepared.run.pre_state_sha256),
            backup_reference=prepared.run.backup_reference,
            replay_verified=True,
            completed_at=datetime.now(UTC),
        )
    return await genesis_import_status(database, prepared)


async def genesis_import_status(
    database: Database, prepared: PreparedGenesisImport
) -> GenesisApplyStatus:
    async with database.tenant_session(prepared.run.tenant_id) as session:
        status = await GenesisImportRepository(session).run_status(
            tenant_id=prepared.run.tenant_id,
            plan_sha256=bytes(prepared.run.plan_sha256),
        )
    if status is None:
        raise GenesisApplyError("genesis_import_not_staged")
    return _safe_status(status)


__all__ = [
    "GenesisApplyError",
    "GenesisApplyStatus",
    "GenesisOperatorConfig",
    "PreparedGenesisImport",
    "apply_genesis_import",
    "genesis_import_status",
    "preflight_genesis_import",
    "prepare_genesis_import",
    "stage_genesis_import",
    "verify_genesis_import",
]
