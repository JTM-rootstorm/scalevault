"""Fail-closed application boundary for the protected Genesis import."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.sealed_content import SealedContentRequest
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
    SelectionEngine,
    SelectionExecutionError,
    SelectionResult,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.ingress.processor import (
    AUTHORIZED_SOURCE_SNAPSHOT,
    GenesisNominationInput,
    MappedNominationSemantics,
    NominationReviewControls,
    RelationshipBindingStatus,
)
from kivra_memory.ingress.validator import (
    FROZEN_FEDERATION_COMPAT_BLOB_SHA,
    FROZEN_FEDERATION_COMPAT_PATH,
    FROZEN_FEDERATION_COMPAT_RAW_SHA256,
)
from kivra_memory.policy import (
    EpistemicQualifier,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    NominationEvidenceReference,
    NominationProposal,
    SelectionBasis,
)
from kivra_memory.storage.genesis_import import (
    GenesisImportRepository,
    GenesisImportStorageError,
)

_DIGEST = r"^[0-9a-f]{64}$"
_GIT_SHA = r"^[0-9a-f]{40}$"
_GENESIS_SCOPE = frozenset({"memory.write.genesis_import"})
_NOMINATION_DOMAIN = b"scalevault.genesis-import.nomination.v1\x00"
_IDEMPOTENCY_DOMAIN = b"scalevault.genesis-import.idempotency.v1\x00"
_TERMINAL_SUBJECT_REFERENCE = "genesis-import:terminal"
GenesisTerminalReason = Literal[
    "source_identity_unresolved",
    "unresolved_legacy_binding",
    "source_session_unresolved",
]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GenesisImportPlanContext(_Contract):
    contract_version: Literal["scalevault-genesis-import-plan-context-v1"]
    plan_sha256: Annotated[str, Field(pattern=_DIGEST)]
    source_repository: Literal["JTM-rootstorm/scalevault-memory-ingress"]
    source_snapshot_commit: Literal["7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9"]
    mapping_version: Literal["genesis-import-mapping-v1"]
    compatibility_version: Literal["genesis-first-import-compat-v1"]
    policy_profile_sha256: Literal[
        "b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"
    ]


class GenesisImportRunContext(_Contract):
    contract_version: Literal["scalevault-genesis-import-run-context-v1"]
    import_run_id: UUID
    plan_sha256: Annotated[str, Field(pattern=_DIGEST)]

    @field_validator("import_run_id")
    @classmethod
    def validate_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="import_run_id")


class GenesisSourceRecordContext(_Contract):
    contract_version: Literal["scalevault-genesis-source-record-context-v1"]
    import_record_id: UUID
    import_source_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=255)]
    source_record_id: Annotated[str, Field(min_length=1, max_length=255)]
    source_path: Annotated[str, Field(min_length=1, max_length=2048)]
    source_git_blob_sha: Annotated[str, Field(pattern=_GIT_SHA)]
    source_raw_sha256: Annotated[str, Field(pattern=_DIGEST)]
    nomination_sha256: Annotated[str, Field(pattern=_DIGEST)]
    owner_actor_reference: Literal["kivra:genesis"] | None
    perspective_actor_reference: Literal["kivra:genesis"] | None
    compatibility_codes: Annotated[tuple[str, ...], Field(max_length=8)] = ()

    @field_validator("import_record_id", "import_source_id")
    @classmethod
    def validate_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="import_record_id")

    @field_validator("compatibility_codes")
    @classmethod
    def validate_compatibility_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not item.strip() for item in value):
            raise ValueError("compatibility codes must be unique and nonblank")
        return value

    @model_validator(mode="after")
    def validate_identity_shape(self) -> GenesisSourceRecordContext:
        if (self.owner_actor_reference is None) != (self.perspective_actor_reference is None):
            raise ValueError("source owner and perspective must resolve together")
        if self.compatibility_codes not in {(), ("frozen_federation_vocabulary",)}:
            raise ValueError("compatibility codes are not authorized")
        frozen_tuple = (
            self.source_path,
            self.source_git_blob_sha,
            self.source_raw_sha256,
        )
        expected_frozen_tuple = (
            FROZEN_FEDERATION_COMPAT_PATH,
            FROZEN_FEDERATION_COMPAT_BLOB_SHA,
            FROZEN_FEDERATION_COMPAT_RAW_SHA256,
        )
        if (self.compatibility_codes == ("frozen_federation_vocabulary",)) != (
            frozen_tuple == expected_frozen_tuple
        ):
            raise ValueError("compatibility marker does not match the frozen source")
        return self


class GenesisImporterAuthority(_Contract):
    contract_version: Literal["scalevault-genesis-importer-authority-v1"]
    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID

    @field_validator("tenant_id", "actor_id", "client_id", "transport_binding_id")
    @classmethod
    def validate_ids(cls, value: UUID, info: object) -> UUID:
        return require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))

    def matches(self, principal: CommandPrincipal) -> bool:
        return (
            principal.tenant_id == self.tenant_id
            and principal.actor_id == self.actor_id
            and principal.client_id == self.client_id
            and principal.transport_binding_id == self.transport_binding_id
            and principal.scopes == _GENESIS_SCOPE
            and principal.ingress_id is None
        )


class GenesisSubjectMapping(_Contract):
    subject_kind: SubjectKind
    source_reference: Annotated[str | None, Field(max_length=2048)]
    subject_id: UUID

    @field_validator("subject_id")
    @classmethod
    def validate_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="subject_id")


class GenesisSessionMapping(_Contract):
    source_reference: Annotated[str, Field(min_length=1, max_length=2048)]
    logical_session_id: UUID

    @field_validator("logical_session_id")
    @classmethod
    def validate_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="logical_session_id")


class GenesisCanonicalMappings(_Contract):
    contract_version: Literal["scalevault-genesis-canonical-mappings-v1"]
    genesis_actor_reference: Literal["kivra:genesis"]
    genesis_actor_id: UUID
    persona_id: UUID
    lineage_id: UUID
    branch_id: UUID
    subjects: Annotated[tuple[GenesisSubjectMapping, ...], Field(min_length=1, max_length=512)]
    sessions: Annotated[tuple[GenesisSessionMapping, ...], Field(max_length=512)] = ()

    @field_validator("genesis_actor_id", "persona_id", "lineage_id", "branch_id")
    @classmethod
    def validate_ids(cls, value: UUID, info: object) -> UUID:
        return require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))

    @model_validator(mode="after")
    def validate_mapping_keys(self) -> GenesisCanonicalMappings:
        subject_keys = tuple((item.subject_kind, item.source_reference) for item in self.subjects)
        session_keys = tuple(item.source_reference for item in self.sessions)
        if len(subject_keys) != len(set(subject_keys)):
            raise ValueError("subject mappings must be unique")
        if len(session_keys) != len(set(session_keys)):
            raise ValueError("session mappings must be unique")
        return self


def canonical_genesis_mappings_sha256(mappings: GenesisCanonicalMappings) -> bytes:
    """Hash the complete operator-approved canonical mapping deterministically."""

    return hashlib.sha256(canonical_json_bytes(mappings.model_dump(mode="python"))).digest()


class GenesisCanonicalMappingBinding(_Contract):
    persona_id: UUID
    lineage_id: UUID
    branch_id: UUID
    genesis_actor_id: UUID
    subject_id: UUID
    subject_kind: SubjectKind
    logical_session_id: UUID | None


class GenesisArchivedMappingMetadata(_Contract):
    semantics: MappedNominationSemantics
    review_controls: NominationReviewControls
    canonical_mapping: GenesisCanonicalMappingBinding


class GenesisResolvedTarget(_Contract):
    subject: GenesisSubjectMapping
    logical_session_id: UUID | None
    terminal_reason: GenesisTerminalReason | None
    mapping_metadata: GenesisArchivedMappingMetadata


class GenesisNominationCommand(_Contract):
    contract_version: Literal["scalevault-genesis-import-command-v1"]
    idempotency_key: str
    persona_id: UUID
    branch_id: UUID
    reason: Annotated[str, Field(pattern=r"^genesis_import$")] = "genesis_import"
    proposal: NominationProposal
    logical_session_id: UUID | None
    sealed_content: SealedContentRequest | None = None
    genesis_actor_id: UUID
    genesis_lineage_id: UUID
    nomination_sha256: Annotated[str, Field(pattern=_DIGEST)]
    transaction_binding_sha256: Annotated[str, Field(pattern=_DIGEST)]
    plan: GenesisImportPlanContext
    run: GenesisImportRunContext
    source_record: GenesisSourceRecordContext
    terminal_reason: GenesisTerminalReason | None = None
    mapping_metadata: GenesisArchivedMappingMetadata

    @field_validator("sealed_content")
    @classmethod
    def reject_sealed_content(
        cls, value: SealedContentRequest | None
    ) -> SealedContentRequest | None:
        if value is not None:
            raise ValueError("genesis sealed content is unsupported")
        return value


def _expected_evidence(
    source: GenesisSourceRecordContext,
) -> tuple[NominationEvidenceReference, ...]:
    return (
        NominationEvidenceReference(
            evidence_key=f"import-manifest:{source.source_raw_sha256}",
            opaque_reference=(
                f"genesis-import:{AUTHORIZED_SOURCE_SNAPSHOT}:"
                f"{source.source_raw_sha256}:{source.source_id}"
            ),
        ),
    )


def _binding_sha256(
    nomination: GenesisNominationInput,
    plan: GenesisImportPlanContext,
    run: GenesisImportRunContext,
    source: GenesisSourceRecordContext,
    mapping_metadata: GenesisArchivedMappingMetadata,
) -> str:
    material = {
        "plan": plan.model_dump(mode="python"),
        "run": run.model_dump(mode="python"),
        "source_record": source.model_dump(mode="python"),
        "nomination_sha256": nomination.nomination_sha256,
        "mapping_metadata": mapping_metadata.model_dump(mode="python"),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _nomination_material(
    nomination: GenesisNominationInput,
    plan: GenesisImportPlanContext,
    source: GenesisSourceRecordContext,
) -> dict[str, object]:
    return {
        "mapping_version": plan.mapping_version,
        "source_repository": plan.source_repository,
        "source_snapshot_commit": plan.source_snapshot_commit,
        "source_path": source.source_path,
        "source_raw_sha256": source.source_raw_sha256,
        "source_record_id": source.source_record_id,
        "semantics": nomination.semantics.model_dump(mode="python"),
        "selection_basis": SelectionBasis.IMPORTED_LEGACY,
        "epistemic_qualifiers": (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
    }


def _verify_nomination_digests(
    nomination: GenesisNominationInput,
    plan: GenesisImportPlanContext,
    source: GenesisSourceRecordContext,
) -> None:
    canonical = canonical_json_bytes(_nomination_material(nomination, plan, source))
    nomination_sha256 = hashlib.sha256(_NOMINATION_DOMAIN + canonical).hexdigest()
    idempotency_key = (
        f"genesis-import-v1:{hashlib.sha256(_IDEMPOTENCY_DOMAIN + canonical).hexdigest()}"
    )
    if (
        nomination.nomination_sha256 != nomination_sha256
        or source.nomination_sha256 != nomination_sha256
        or nomination.idempotency_key != idempotency_key
    ):
        raise SelectionExecutionError("invalid_input")


def _resolve_subject(
    nomination: GenesisNominationInput, mappings: GenesisCanonicalMappings
) -> GenesisSubjectMapping:
    selector = nomination.semantics.subject
    matches = tuple(
        item
        for item in mappings.subjects
        if item.subject_kind is selector.subject_kind
        and item.source_reference == selector.source_reference
    )
    if len(matches) != 1:
        raise SelectionExecutionError("not_found")
    return matches[0]


def _resolve_session(
    nomination: GenesisNominationInput, mappings: GenesisCanonicalMappings
) -> UUID | None:
    if nomination.semantics.scope not in {MemoryScope.EPISODIC, MemoryScope.SCENE_LOCAL}:
        return None
    reference = nomination.semantics.subject.source_reference
    if reference is None:
        raise SelectionExecutionError("not_found")
    matches = tuple(item for item in mappings.sessions if item.source_reference == reference)
    if len(matches) != 1:
        raise SelectionExecutionError("not_found")
    return matches[0].logical_session_id


def _terminal_subject(mappings: GenesisCanonicalMappings) -> GenesisSubjectMapping:
    matches = tuple(
        item
        for item in mappings.subjects
        if item.subject_kind is SubjectKind.GLOBAL
        and item.source_reference == _TERMINAL_SUBJECT_REFERENCE
    )
    if len(matches) != 1:
        raise SelectionExecutionError("not_found")
    return matches[0]


def resolve_genesis_mapping_metadata(
    nomination: GenesisNominationInput,
    mappings: GenesisCanonicalMappings,
    source_record: GenesisSourceRecordContext,
) -> GenesisResolvedTarget:
    """Resolve one explicit canonical target without creating or inferring identifiers."""

    terminal_reason: GenesisTerminalReason | None = None
    if (
        source_record.owner_actor_reference is None
        or source_record.perspective_actor_reference is None
    ):
        terminal_reason = "source_identity_unresolved"
    elif (
        nomination.review_controls.relationship_binding_status
        is RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING
    ):
        terminal_reason = "unresolved_legacy_binding"

    logical_session_id: UUID | None = None
    if terminal_reason is None and nomination.semantics.scope is MemoryScope.EPISODIC:
        # The current episode subject shape has no origin-session FK.  Treat it
        # as unresolved rather than assigning the importer or an unrelated
        # source session to the event envelope.
        terminal_reason = "source_session_unresolved"
    elif terminal_reason is None and nomination.semantics.scope is MemoryScope.SCENE_LOCAL:
        try:
            logical_session_id = _resolve_session(nomination, mappings)
        except SelectionExecutionError:
            terminal_reason = "source_session_unresolved"

    subject = (
        _resolve_subject(nomination, mappings)
        if terminal_reason is None
        else _terminal_subject(mappings)
    )
    metadata = GenesisArchivedMappingMetadata(
        semantics=nomination.semantics,
        review_controls=nomination.review_controls,
        canonical_mapping=GenesisCanonicalMappingBinding(
            persona_id=mappings.persona_id,
            lineage_id=mappings.lineage_id,
            branch_id=mappings.branch_id,
            genesis_actor_id=mappings.genesis_actor_id,
            subject_id=subject.subject_id,
            subject_kind=subject.subject_kind,
            logical_session_id=(logical_session_id if terminal_reason is None else None),
        ),
    )
    return GenesisResolvedTarget(
        subject=subject,
        logical_session_id=(logical_session_id if terminal_reason is None else None),
        terminal_reason=terminal_reason,
        mapping_metadata=metadata,
    )


def _proposal(
    nomination: GenesisNominationInput,
    *,
    subject: GenesisSubjectMapping,
    logical_session_id: UUID | None,
) -> NominationProposal:
    semantics = nomination.semantics
    return NominationProposal(
        subject_id=subject.subject_id,
        subject_kind=subject.subject_kind,
        category=semantics.category,
        ontological_status=semantics.ontological_status,
        scope=semantics.scope,
        visibility=semantics.visibility,
        statement=semantics.statement,
        reason_to_remember=semantics.reason_to_remember,
        interpretation_limits=semantics.interpretation_limits,
        confidence=semantics.confidence,
        salience=semantics.salience,
        durability=semantics.durability,
        sensitivity=semantics.sensitivity,
        origin_session_id=logical_session_id,
        metadata={},
        selection_basis=SelectionBasis.IMPORTED_LEGACY,
        epistemic_qualifiers=(EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
        evidence_references=nomination.evidence_references,
    )


def _terminal_proposal(
    nomination: GenesisNominationInput,
    *,
    subject: GenesisSubjectMapping,
) -> NominationProposal:
    return NominationProposal(
        subject_id=subject.subject_id,
        subject_kind=SubjectKind.GLOBAL,
        category=MemoryCategory.INTERPRETATION,
        ontological_status=OntologicalStatus.UNCERTAIN,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement="Genesis import record withheld from canonical memory.",
        reason_to_remember="Source binding requires authorized reconciliation.",
        interpretation_limits=("This is an import disposition, not a source memory.",),
        confidence=nomination.semantics.confidence,
        salience=nomination.semantics.salience,
        durability=nomination.semantics.durability,
        sensitivity=4,
        metadata={},
        selection_basis=SelectionBasis.IMPORTED_LEGACY,
        epistemic_qualifiers=(EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
        evidence_references=nomination.evidence_references,
    )


class GenesisImportResolver:
    """Resolve only server-pinned Genesis commands into imported policy facts."""

    def __init__(self, authority: GenesisImporterAuthority) -> None:
        self._authority = authority

    async def resolve(
        self, principal: CommandPrincipal, command: NominationCommandLike, /
    ) -> ResolvedNominationContext:
        if not isinstance(principal, CommandPrincipal) or not self._authority.matches(principal):
            raise SelectionExecutionError("forbidden")
        if not isinstance(command, GenesisNominationCommand):
            raise SelectionExecutionError("invalid_input")
        source = command.source_record
        source_identity_is_genesis = (
            source.owner_actor_reference == "kivra:genesis"
            and source.perspective_actor_reference == "kivra:genesis"
        )
        terminal_identity_is_valid = (
            command.terminal_reason == "source_identity_unresolved"
            and source.owner_actor_reference is None
            and source.perspective_actor_reference is None
        ) or (
            command.terminal_reason in {"unresolved_legacy_binding", "source_session_unresolved"}
            and source_identity_is_genesis
        )
        if (
            command.plan.plan_sha256 != command.run.plan_sha256
            or command.nomination_sha256 != source.nomination_sha256
            or (command.terminal_reason is None and not source_identity_is_genesis)
            or (command.terminal_reason is not None and not terminal_identity_is_valid)
            or command.proposal.selection_basis is not SelectionBasis.IMPORTED_LEGACY
            or command.proposal.epistemic_qualifiers
            != (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,)
            or command.proposal.evidence_references != _expected_evidence(source)
            or (
                command.terminal_reason is not None
                and (
                    command.proposal.scope is not MemoryScope.GLOBAL
                    or command.proposal.subject_kind is not SubjectKind.GLOBAL
                    or command.proposal.statement
                    != "Genesis import record withheld from canonical memory."
                )
            )
        ):
            raise SelectionExecutionError("authority_unavailable")
        evidence = tuple(
            EvidenceSummary(
                evidence_key=item.evidence_key,
                kind=EvidenceKind.IMPORT_MANIFEST,
                trust=EvidenceTrust.TRUSTED,
            )
            for item in command.proposal.evidence_references
        )
        if tuple(item.evidence_key for item in evidence) != tuple(
            item.evidence_key for item in command.proposal.evidence_references
        ):
            raise SelectionExecutionError("authority_unavailable")
        return ResolvedNominationContext(
            source_kind="genesis_import",
            effective_authority_class=(
                AuthorityClass.EXTERNAL_SOURCE
                if command.terminal_reason is not None
                else AuthorityClass.IMPORTED_LEGACY_MEMORY
            ),
            content_signals=frozenset(),
            evidence=evidence,
        )


class _GenesisTerminalParticipant:
    def __init__(
        self,
        *,
        repository_factory: Callable[[AsyncSession], GenesisImportRepository],
        command: GenesisNominationCommand,
        processed_at: datetime,
    ) -> None:
        self._repository_factory = repository_factory
        self._command = command
        self._processed_at = processed_at

    @property
    def transaction_binding_sha256(self) -> str:
        return self._command.transaction_binding_sha256

    async def stage(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        resolved: ResolvedNominationContext,
        result: SelectionResult,
    ) -> None:
        if (
            cast(object, command) is not self._command
            or resolved.source_kind != "genesis_import"
            or result.outcome not in {"candidate", "omit", "reject"}
            or (self._command.terminal_reason is not None and result.outcome != "reject")
        ):
            raise SelectionExecutionError("forbidden")
        try:
            repository = self._repository_factory(session)
            await repository.verify_planned_record_context(
                tenant_id=principal.tenant_id,
                import_run_id=self._command.run.import_run_id,
                import_record_id=self._command.source_record.import_record_id,
                plan_sha256=bytes.fromhex(self._command.plan.plan_sha256),
                source_id=self._command.source_record.import_source_id,
                source_path=self._command.source_record.source_path,
                blob_object_id=self._command.source_record.source_git_blob_sha,
                raw_sha256=bytes.fromhex(self._command.source_record.source_raw_sha256),
                nomination_sha256=bytes.fromhex(self._command.nomination_sha256),
                nomination_idempotency_key=self._command.idempotency_key,
                mapping_metadata_sha256=hashlib.sha256(
                    canonical_json_bytes(self._command.mapping_metadata.model_dump(mode="python"))
                ).digest(),
            )
            await repository.terminalize_record(
                tenant_id=principal.tenant_id,
                import_run_id=self._command.run.import_run_id,
                import_record_id=self._command.source_record.import_record_id,
                nomination_sha256=bytes.fromhex(self._command.nomination_sha256),
                outcome=cast(Literal["candidate", "omit", "reject"], result.outcome),
                selection_decision_id=result.decision_id,
                event_id=result.event_id,
                memory_id=result.memory_id,
                processed_at=self._processed_at,
            )
        except GenesisImportStorageError:
            raise SelectionExecutionError("provenance_conflict") from None


class GenesisImportEngine:
    """Map one frozen Genesis source record into the canonical selection engine."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        mappings: GenesisCanonicalMappings,
        importer_authority: GenesisImporterAuthority,
        *,
        repository_factory: Callable[[AsyncSession], GenesisImportRepository] = (
            GenesisImportRepository
        ),
    ) -> None:
        if importer_authority.actor_id == mappings.genesis_actor_id:
            raise ValueError("Genesis importer actor must be distinct from the memory owner")
        self._mappings = mappings
        self._importer_authority = importer_authority
        self._repository_factory = repository_factory
        self._selection = SelectionEngine(
            session_factory, GenesisImportResolver(importer_authority)
        )

    async def execute(
        self,
        principal: CommandPrincipal,
        nomination: GenesisNominationInput,
        *,
        plan: GenesisImportPlanContext,
        run: GenesisImportRunContext,
        source_record: GenesisSourceRecordContext,
    ) -> SelectionResult:
        if not isinstance(principal, CommandPrincipal) or not self._importer_authority.matches(
            principal
        ):
            raise SelectionExecutionError("forbidden")
        if (
            not isinstance(nomination, GenesisNominationInput)
            or not isinstance(plan, GenesisImportPlanContext)
            or not isinstance(run, GenesisImportRunContext)
            or not isinstance(source_record, GenesisSourceRecordContext)
        ):
            raise SelectionExecutionError("invalid_input")
        if (
            nomination.review_controls.automatic_promotion_allowed is not False
            or plan.plan_sha256 != run.plan_sha256
            or nomination.source_record_id != source_record.source_record_id
            or nomination.nomination_sha256 != source_record.nomination_sha256
            or nomination.evidence_references != _expected_evidence(source_record)
        ):
            raise SelectionExecutionError("invalid_input")
        _verify_nomination_digests(nomination, plan, source_record)
        target = resolve_genesis_mapping_metadata(nomination, self._mappings, source_record)
        if target.terminal_reason is None:
            proposal = _proposal(
                nomination,
                subject=target.subject,
                logical_session_id=target.logical_session_id,
            )
        else:
            proposal = _terminal_proposal(nomination, subject=target.subject)
        command = GenesisNominationCommand(
            contract_version="scalevault-genesis-import-command-v1",
            idempotency_key=nomination.idempotency_key,
            persona_id=self._mappings.persona_id,
            branch_id=self._mappings.branch_id,
            genesis_lineage_id=self._mappings.lineage_id,
            proposal=proposal,
            logical_session_id=None,
            genesis_actor_id=self._mappings.genesis_actor_id,
            nomination_sha256=nomination.nomination_sha256,
            transaction_binding_sha256=_binding_sha256(
                nomination,
                plan,
                run,
                source_record,
                target.mapping_metadata,
            ),
            plan=plan,
            run=run,
            source_record=source_record,
            terminal_reason=target.terminal_reason,
            mapping_metadata=target.mapping_metadata,
        )
        participant = _GenesisTerminalParticipant(
            repository_factory=self._repository_factory,
            command=command,
            processed_at=datetime.now(UTC),
        )
        return await self._selection.execute(
            principal,
            command,
            transaction_participant=participant,
        )


__all__ = [
    "GenesisArchivedMappingMetadata",
    "GenesisCanonicalMappingBinding",
    "GenesisCanonicalMappings",
    "GenesisImportEngine",
    "GenesisImportPlanContext",
    "GenesisImportResolver",
    "GenesisImportRunContext",
    "GenesisImporterAuthority",
    "GenesisNominationCommand",
    "GenesisResolvedTarget",
    "GenesisSessionMapping",
    "GenesisSourceRecordContext",
    "GenesisSubjectMapping",
    "canonical_genesis_mappings_sha256",
    "resolve_genesis_mapping_metadata",
]
