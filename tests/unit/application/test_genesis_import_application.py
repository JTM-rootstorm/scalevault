"""Focused tests for the protected Genesis import application boundary."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest
from kivra_memory.application.genesis_import import (
    GenesisCanonicalMappings,
    GenesisImportEngine,
    GenesisImporterAuthority,
    GenesisImportPlanContext,
    GenesisImportResolver,
    GenesisImportRunContext,
    GenesisNominationCommand,
    GenesisSessionMapping,
    GenesisSourceRecordContext,
    GenesisSubjectMapping,
    resolve_genesis_mapping_metadata,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
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
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.ingress.processor import (
    GenesisNominationInput,
    MappedNominationSemantics,
    NominationReviewControls,
    RelationshipBindingStatus,
    SymbolicSubjectSelector,
)
from kivra_memory.policy import (
    EpistemicQualifier,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    NominationEvidenceReference,
    PolicyOutcome,
    SelectionBasis,
    SelectionRequest,
    evaluate_selection,
)
from kivra_memory.storage.genesis_import import GenesisImportStorageError
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

PLAN_SHA = "1" * 64
RAW_SHA = "2" * 64


def _authority() -> GenesisImporterAuthority:
    return GenesisImporterAuthority(
        contract_version="scalevault-genesis-importer-authority-v1",
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
    )


def _principal(
    authority: GenesisImporterAuthority, *, scopes: frozenset[str] | None = None
) -> CommandPrincipal:
    return CommandPrincipal(
        tenant_id=authority.tenant_id,
        actor_id=authority.actor_id,
        client_id=authority.client_id,
        transport_binding_id=authority.transport_binding_id,
        scopes=scopes or frozenset({"memory.write.genesis_import"}),
    )


def _mappings() -> GenesisCanonicalMappings:
    return GenesisCanonicalMappings(
        contract_version="scalevault-genesis-canonical-mappings-v1",
        genesis_actor_reference="kivra:genesis",
        genesis_actor_id=new_uuid7(),
        persona_id=new_uuid7(),
        lineage_id=new_uuid7(),
        branch_id=new_uuid7(),
        subjects=(
            GenesisSubjectMapping(
                subject_kind=SubjectKind.PERSONA,
                source_reference="kivra:genesis",
                subject_id=new_uuid7(),
            ),
            GenesisSubjectMapping(
                subject_kind=SubjectKind.GLOBAL,
                source_reference="genesis-import:terminal",
                subject_id=new_uuid7(),
            ),
        ),
    )


def _plan() -> GenesisImportPlanContext:
    return GenesisImportPlanContext(
        contract_version="scalevault-genesis-import-plan-context-v1",
        plan_sha256=PLAN_SHA,
        source_repository="JTM-rootstorm/scalevault-memory-ingress",
        source_snapshot_commit="7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9",
        mapping_version="genesis-import-mapping-v1",
        compatibility_version="genesis-first-import-compat-v1",
        policy_profile_sha256=("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"),
    )


def _run() -> GenesisImportRunContext:
    return GenesisImportRunContext(
        contract_version="scalevault-genesis-import-run-context-v1",
        import_run_id=new_uuid7(),
        plan_sha256=PLAN_SHA,
    )


def _source(
    *,
    owner: Literal["kivra:genesis"] | None = "kivra:genesis",
    nomination: GenesisNominationInput | None = None,
) -> GenesisSourceRecordContext:
    selected_nomination = nomination or _nomination()
    return GenesisSourceRecordContext(
        contract_version="scalevault-genesis-source-record-context-v1",
        import_record_id=new_uuid7(),
        import_source_id=new_uuid7(),
        source_id="checkpoint-001",
        source_record_id="candidate-001",
        source_path="ingress/checkpoints/v2/genesis/2026/08/checkpoint-001.json",
        source_git_blob_sha="4" * 40,
        source_raw_sha256=RAW_SHA,
        nomination_sha256=selected_nomination.nomination_sha256,
        owner_actor_reference=owner,
        perspective_actor_reference=owner,
    )


def _sign_nomination(nomination: GenesisNominationInput) -> GenesisNominationInput:
    material = {
        "mapping_version": "genesis-import-mapping-v1",
        "source_repository": "JTM-rootstorm/scalevault-memory-ingress",
        "source_snapshot_commit": "7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9",
        "source_path": "ingress/checkpoints/v2/genesis/2026/08/checkpoint-001.json",
        "source_raw_sha256": RAW_SHA,
        "source_record_id": nomination.source_record_id,
        "semantics": nomination.semantics.model_dump(mode="python"),
        "selection_basis": SelectionBasis.IMPORTED_LEGACY,
        "epistemic_qualifiers": (EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
    }
    canonical = canonical_json_bytes(material)
    nomination_sha = hashlib.sha256(
        b"scalevault.genesis-import.nomination.v1\x00" + canonical
    ).hexdigest()
    idempotency_sha = hashlib.sha256(
        b"scalevault.genesis-import.idempotency.v1\x00" + canonical
    ).hexdigest()
    return nomination.model_copy(
        update={
            "nomination_sha256": nomination_sha,
            "idempotency_key": f"genesis-import-v1:{idempotency_sha}",
        }
    )


def _nomination() -> GenesisNominationInput:
    nomination = GenesisNominationInput(
        contract_version="scalevault-genesis-nomination-v1",
        idempotency_key=f"genesis-import-v1:{'5' * 64}",
        nomination_sha256="3" * 64,
        source_record_id="candidate-001",
        semantics=MappedNominationSemantics(
            subject=SymbolicSubjectSelector(
                subject_kind=SubjectKind.PERSONA,
                source_reference="kivra:genesis",
            ),
            category=MemoryCategory.INTERPRETATION,
            ontological_status=OntologicalStatus.HYPOTHESIS,
            scope=MemoryScope.PERSONA,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement="Synthetic imported statement.",
            reason_to_remember="Synthetic imported reason.",
            interpretation_limits=("Imported and unreconciled.",),
            confidence=Decimal("0.5"),
            salience=Decimal("0.5"),
            durability=Decimal("0.5"),
            sensitivity=4,
        ),
        selection_basis=SelectionBasis.IMPORTED_LEGACY,
        epistemic_qualifiers=(EpistemicQualifier.IMPORTED_SOURCE_UNRECONCILED,),
        evidence_references=(
            NominationEvidenceReference(
                evidence_key=f"import-manifest:{RAW_SHA}",
                opaque_reference=(
                    "genesis-import:7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9:"
                    f"{RAW_SHA}:checkpoint-001"
                ),
            ),
        ),
        review_controls=NominationReviewControls(
            relationship_binding_status=RelationshipBindingStatus.NOT_APPLICABLE,
            relationship_retrieval_allowed=True,
            automatic_promotion_allowed=False,
            promotion_block_reasons=("source_requires_continuant_review",),
        ),
    )
    return _sign_nomination(nomination)


def _episodic_nomination() -> GenesisNominationInput:
    baseline = _nomination()
    semantics = baseline.semantics.model_copy(
        update={
            "subject": SymbolicSubjectSelector(
                subject_kind=SubjectKind.EPISODE,
                source_reference="interaction-001",
            ),
            "category": MemoryCategory.EPISODIC_ANCHOR,
            "ontological_status": OntologicalStatus.UNCERTAIN,
            "scope": MemoryScope.EPISODIC,
        }
    )
    return _sign_nomination(baseline.model_copy(update={"semantics": semantics}))


def _scene_nomination() -> GenesisNominationInput:
    baseline = _nomination()
    semantics = baseline.semantics.model_copy(
        update={
            "subject": SymbolicSubjectSelector(
                subject_kind=SubjectKind.SCENE,
                source_reference="interaction-001",
            ),
            "category": MemoryCategory.EPISODIC_ANCHOR,
            "ontological_status": OntologicalStatus.UNCERTAIN,
            "scope": MemoryScope.SCENE_LOCAL,
        }
    )
    return _sign_nomination(baseline.model_copy(update={"semantics": semantics}))


async def test_engine_builds_exact_imported_command_and_required_participant() -> None:
    mappings = _mappings()
    authority = _authority()
    principal = _principal(authority)
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    captured: dict[str, object] = {}

    async def execute(
        actual_principal: CommandPrincipal,
        command: GenesisNominationCommand,
        *,
        transaction_participant: object,
    ) -> SelectionResult:
        captured.update(
            principal=actual_principal,
            command=command,
            participant=transaction_participant,
        )
        return SelectionResult(
            receipt_id=new_uuid7(),
            decision_id=new_uuid7(),
            outcome="candidate",
            policy_sha256=("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"),
            reason_codes=("imported_legacy_candidate",),
            matched_rule_ids=("basis.imported_legacy",),
            event_id=new_uuid7(),
            memory_id=new_uuid7(),
            revision=1,
        )

    cast(Any, engine._selection).execute = execute
    result = await engine.execute(
        principal,
        _nomination(),
        plan=_plan(),
        run=_run(),
        source_record=_source(),
    )

    command = cast(GenesisNominationCommand, captured["command"])
    participant = captured["participant"]
    assert result.outcome == "candidate"
    assert cast(CommandPrincipal, captured["principal"]).actor_id == authority.actor_id
    assert authority.actor_id != mappings.genesis_actor_id
    assert command.genesis_lineage_id == mappings.lineage_id
    assert command.proposal.metadata == {}
    assert command.proposal.selection_basis is SelectionBasis.IMPORTED_LEGACY
    assert (
        cast(SimpleNamespace, participant).transaction_binding_sha256
        == command.transaction_binding_sha256
    )


async def test_resolver_emits_only_import_manifest_authority() -> None:
    mappings = _mappings()
    authority = _authority()
    principal = _principal(authority)
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    command_box: list[GenesisNominationCommand] = []

    async def capture(
        _principal: CommandPrincipal,
        command: GenesisNominationCommand,
        **_kwargs: object,
    ) -> SelectionResult:
        command_box.append(command)
        raise SelectionExecutionError("captured")

    cast(Any, engine._selection).execute = capture
    with pytest.raises(SelectionExecutionError, match="captured"):
        await engine.execute(
            principal,
            _nomination(),
            plan=_plan(),
            run=_run(),
            source_record=_source(),
        )
    resolved = await GenesisImportResolver(authority).resolve(principal, command_box[0])
    assert resolved == ResolvedNominationContext(
        source_kind="genesis_import",
        effective_authority_class=AuthorityClass.IMPORTED_LEGACY_MEMORY,
        content_signals=frozenset(),
        evidence=(
            EvidenceSummary(
                evidence_key=f"import-manifest:{RAW_SHA}",
                kind=EvidenceKind.IMPORT_MANIFEST,
                trust=EvidenceTrust.TRUSTED,
            ),
        ),
    )


async def test_changed_semantics_with_retained_claimed_digest_is_rejected() -> None:
    mappings = _mappings()
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    original = _nomination()
    changed = original.model_copy(
        update={
            "semantics": original.semantics.model_copy(
                update={"statement": "Changed after the approved digest was retained."}
            )
        }
    )

    with pytest.raises(SelectionExecutionError, match="invalid_input"):
        await engine.execute(
            _principal(authority),
            changed,
            plan=_plan(),
            run=_run(),
            source_record=_source(nomination=original),
        )


def test_canonical_subject_remap_changes_archived_mapping_digest() -> None:
    nomination = _nomination()
    source = _source(nomination=nomination)
    first = _mappings()
    replacement_subject = new_uuid7()
    second = first.model_copy(
        update={
            "subjects": tuple(
                item.model_copy(update={"subject_id": replacement_subject})
                if item.subject_kind is SubjectKind.PERSONA
                else item
                for item in first.subjects
            )
        }
    )
    first_metadata = resolve_genesis_mapping_metadata(
        nomination, first, source
    ).mapping_metadata.model_dump(mode="python")
    second_metadata = resolve_genesis_mapping_metadata(
        nomination, second, source
    ).mapping_metadata.model_dump(mode="python")
    assert (
        hashlib.sha256(canonical_json_bytes(first_metadata)).digest()
        != hashlib.sha256(canonical_json_bytes(second_metadata)).digest()
    )


async def test_mapped_source_session_is_preserved_without_changing_genesis_owner() -> None:
    mappings = _mappings()
    session_id = new_uuid7()
    episode_subject_id = new_uuid7()
    mappings = mappings.model_copy(
        update={
            "subjects": (
                *mappings.subjects,
                GenesisSubjectMapping(
                    subject_kind=SubjectKind.SCENE,
                    source_reference="interaction-001",
                    subject_id=episode_subject_id,
                ),
            ),
            "sessions": (
                GenesisSessionMapping(
                    source_reference="interaction-001",
                    logical_session_id=session_id,
                ),
            ),
        }
    )
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    captured: list[GenesisNominationCommand] = []

    async def capture(
        _principal: CommandPrincipal,
        command: GenesisNominationCommand,
        **_kwargs: object,
    ) -> SelectionResult:
        captured.append(command)
        raise SelectionExecutionError("captured")

    cast(Any, engine._selection).execute = capture
    nomination = _scene_nomination()
    with pytest.raises(SelectionExecutionError, match="captured"):
        await engine.execute(
            _principal(authority),
            nomination,
            plan=_plan(),
            run=_run(),
            source_record=_source(nomination=nomination),
        )
    command = captured[0]
    assert command.terminal_reason is None
    assert command.logical_session_id is None
    assert command.proposal.origin_session_id == session_id
    assert command.proposal.subject_id == episode_subject_id
    assert command.genesis_actor_id == mappings.genesis_actor_id
    assert authority.actor_id != mappings.genesis_actor_id


async def test_unmapped_source_session_terminally_rejects_without_memory_subject() -> None:
    mappings = _mappings()
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    captured: list[GenesisNominationCommand] = []

    async def capture(
        _principal: CommandPrincipal,
        command: GenesisNominationCommand,
        **_kwargs: object,
    ) -> SelectionResult:
        captured.append(command)
        raise SelectionExecutionError("captured")

    cast(Any, engine._selection).execute = capture
    nomination = _episodic_nomination()
    with pytest.raises(SelectionExecutionError, match="captured"):
        await engine.execute(
            _principal(authority),
            nomination,
            plan=_plan(),
            run=_run(),
            source_record=_source(nomination=nomination),
        )
    command = captured[0]
    assert command.terminal_reason == "source_session_unresolved"
    assert command.logical_session_id is None
    assert command.proposal.subject_kind is SubjectKind.GLOBAL
    assert command.proposal.origin_session_id is None


async def test_unresolved_legacy_owner_stops_before_selection() -> None:
    mappings = _mappings()
    authority = _authority()
    principal = _principal(authority)
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    captured: list[GenesisNominationCommand] = []

    async def execute(
        _principal: CommandPrincipal,
        command: GenesisNominationCommand,
        **_kwargs: object,
    ) -> SelectionResult:
        captured.append(command)
        return SelectionResult(
            receipt_id=new_uuid7(),
            decision_id=new_uuid7(),
            outcome="reject",
            policy_sha256=("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"),
            reason_codes=("authority_not_established",),
            matched_rule_ids=(),
            event_id=None,
            memory_id=None,
            revision=None,
        )

    cast(Any, engine._selection).execute = execute
    result = await engine.execute(
        principal,
        _nomination(),
        plan=_plan(),
        run=_run(),
        source_record=_source(owner=None),
    )
    command = captured[0]
    resolved = await GenesisImportResolver(authority).resolve(principal, command)
    decision = evaluate_selection(
        SelectionRequest(
            basis=command.proposal.selection_basis,
            category=command.proposal.category,
            ontological_status=command.proposal.ontological_status,
            scope=command.proposal.scope,
            visibility=command.proposal.visibility,
            effective_authority_class=resolved.effective_authority_class,
            epistemic_qualifiers=frozenset(command.proposal.epistemic_qualifiers),
            reason_to_remember=command.proposal.reason_to_remember,
            interpretation_limits=command.proposal.interpretation_limits,
            evidence=resolved.evidence,
        )
    )
    assert result.outcome == "reject"
    assert command.terminal_reason == "source_identity_unresolved"
    assert command.proposal.scope is MemoryScope.GLOBAL
    assert resolved.effective_authority_class is AuthorityClass.EXTERNAL_SOURCE
    assert decision.outcome is PolicyOutcome.REJECT


async def test_wrong_actor_or_scope_stops_before_selection() -> None:
    mappings = _mappings()
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    for principal in (
        CommandPrincipal(
            tenant_id=authority.tenant_id,
            actor_id=new_uuid7(),
            client_id=authority.client_id,
            transport_binding_id=authority.transport_binding_id,
            scopes=frozenset({"memory.write.genesis_import"}),
        ),
        _principal(
            authority,
            scopes=frozenset({"memory.write.genesis_import", "memory:write"}),
        ),
    ):
        with pytest.raises(SelectionExecutionError, match="forbidden"):
            await engine.execute(
                principal,
                _nomination(),
                plan=_plan(),
                run=_run(),
                source_record=_source(),
            )


async def test_missing_principal_stops_before_selection() -> None:
    mappings = _mappings()
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    with pytest.raises(SelectionExecutionError, match="forbidden"):
        await engine.execute(
            cast(Any, None),
            _nomination(),
            plan=_plan(),
            run=_run(),
            source_record=_source(),
        )


async def test_unresolved_relationship_binding_stops_before_subject_resolution() -> None:
    mappings = _mappings()
    authority = _authority()
    engine = GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
    nomination = _nomination().model_copy(
        update={
            "review_controls": NominationReviewControls(
                relationship_binding_status=(RelationshipBindingStatus.UNRESOLVED_LEGACY_BINDING),
                relationship_retrieval_allowed=False,
                automatic_promotion_allowed=False,
                promotion_block_reasons=("unresolved_legacy_binding",),
            )
        }
    )
    captured: list[GenesisNominationCommand] = []

    async def capture(
        _principal: CommandPrincipal,
        command: GenesisNominationCommand,
        **_kwargs: object,
    ) -> SelectionResult:
        captured.append(command)
        raise SelectionExecutionError("captured")

    cast(Any, engine._selection).execute = capture
    with pytest.raises(SelectionExecutionError, match="captured"):
        await engine.execute(
            _principal(authority),
            nomination,
            plan=_plan(),
            run=_run(),
            source_record=_source(),
        )
    assert captured[0].terminal_reason == "unresolved_legacy_binding"
    assert captured[0].proposal.subject_kind is SubjectKind.GLOBAL


async def test_exact_genesis_scope_cannot_call_selection_without_participant() -> None:
    authority = _authority()
    principal = _principal(authority)
    engine = SelectionEngine(
        cast(async_sessionmaker[AsyncSession], None), GenesisImportResolver(authority)
    )
    incomplete = SimpleNamespace()

    with pytest.raises(SelectionExecutionError, match="forbidden"):
        await engine.execute(principal, cast(Any, incomplete))


async def test_storage_context_failure_is_mapped_to_content_free_selection_error() -> None:
    mappings = _mappings()
    authority = _authority()

    class FailingRepository:
        async def verify_planned_record_context(self, **_kwargs: object) -> None:
            raise GenesisImportStorageError("planned_record_context_mismatch")

    engine = GenesisImportEngine(
        cast(async_sessionmaker[AsyncSession], None),
        mappings,
        authority,
        repository_factory=lambda _session: cast(Any, FailingRepository()),
    )

    async def execute(
        principal: CommandPrincipal,
        command: GenesisNominationCommand,
        *,
        transaction_participant: Any,
    ) -> SelectionResult:
        result = SelectionResult(
            receipt_id=new_uuid7(),
            decision_id=new_uuid7(),
            outcome="candidate",
            policy_sha256=("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"),
            reason_codes=("imported_legacy_candidate",),
            matched_rule_ids=("basis.imported_legacy",),
            event_id=new_uuid7(),
            memory_id=new_uuid7(),
            revision=1,
        )
        await transaction_participant.stage(
            cast(AsyncSession, SimpleNamespace()),
            principal=principal,
            command=command,
            resolved=ResolvedNominationContext(
                source_kind="genesis_import",
                effective_authority_class=AuthorityClass.IMPORTED_LEGACY_MEMORY,
            ),
            result=result,
        )
        return result

    cast(Any, engine._selection).execute = execute
    with pytest.raises(SelectionExecutionError, match="provenance_conflict") as caught:
        await engine.execute(
            _principal(authority),
            _nomination(),
            plan=_plan(),
            run=_run(),
            source_record=_source(),
        )
    assert caught.value.code == "provenance_conflict"
    assert caught.value.__cause__ is None


def test_source_identity_cannot_be_partially_resolved() -> None:
    values = _source().model_dump(mode="python")
    values["perspective_actor_reference"] = None
    with pytest.raises(ValidationError, match="resolve together"):
        GenesisSourceRecordContext.model_validate(values)


def test_importer_actor_must_be_distinct_from_genesis_owner() -> None:
    mappings = _mappings()
    authority = _authority().model_copy(update={"actor_id": mappings.genesis_actor_id})
    with pytest.raises(ValueError, match="distinct"):
        GenesisImportEngine(cast(async_sessionmaker[AsyncSession], None), mappings, authority)
