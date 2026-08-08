"""Content-free persistence seam for protected Genesis import application code."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast
from uuid import UUID

from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.storage.models import (
    GenesisImportExclusion,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportRunResult,
    GenesisImportSource,
    GenesisImportSupersession,
)

GenesisTerminalOutcome = Literal["candidate", "omit", "reject"]


class GenesisImportStorageError(RuntimeError):
    """A stable content-free Genesis persistence failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class GenesisRecordStatus:
    import_record_id: UUID
    processing_state: Literal["planned", "candidate", "omit", "reject"]
    selection_decision_id: UUID | None
    event_id: UUID | None
    memory_id: UUID | None
    processed_at: datetime | None


@dataclass(frozen=True, slots=True)
class PendingGenesisRecord:
    import_record_id: UUID
    source_id: UUID
    nomination_sha256: bytes
    nomination_idempotency_key: str


@dataclass(frozen=True, slots=True)
class GenesisRunStatus:
    import_run_id: UUID
    plan_sha256: bytes
    source_count: int
    planned_record_count: int
    terminal_record_count: int
    completed: bool


@dataclass(frozen=True, slots=True)
class GenesisRunResultStatus:
    import_run_id: UUID
    planned_record_count: int
    candidate_count: int
    omit_count: int
    reject_count: int
    replay_verified: bool
    completed_at: datetime


def _record_status(row: GenesisImportRecord) -> GenesisRecordStatus:
    return GenesisRecordStatus(
        import_record_id=row.import_record_id,
        processing_state=row.processing_state,  # type: ignore[arg-type]
        selection_decision_id=row.selection_decision_id,
        event_id=row.event_id,
        memory_id=row.memory_id,
        processed_at=row.processed_at,
    )


class GenesisImportRepository:
    """Persist terminal links in the caller's existing SERIALIZABLE transaction.

    This repository never commits, rolls back, logs, or returns archived source
    bytes or parsed source documents.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def verify_planned_record_context(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        import_record_id: UUID,
        plan_sha256: bytes,
        source_id: UUID,
        source_path: str,
        blob_object_id: str,
        raw_sha256: bytes,
        nomination_sha256: bytes,
        nomination_idempotency_key: str,
    ) -> PendingGenesisRecord:
        """Fail closed unless every frozen archive and mapping identity matches."""

        if len(plan_sha256) != 32 or len(raw_sha256) != 32 or len(nomination_sha256) != 32:
            raise GenesisImportStorageError("invalid_context_digest")
        row = (
            await self._session.execute(
                select(
                    GenesisImportRecord.import_record_id,
                    GenesisImportRecord.source_id,
                    GenesisImportRecord.nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key,
                )
                .join(
                    GenesisImportRun,
                    (GenesisImportRun.tenant_id == GenesisImportRecord.tenant_id)
                    & (GenesisImportRun.import_run_id == GenesisImportRecord.import_run_id),
                )
                .join(
                    GenesisImportSource,
                    (GenesisImportSource.tenant_id == GenesisImportRecord.tenant_id)
                    & (GenesisImportSource.import_run_id == GenesisImportRecord.import_run_id)
                    & (GenesisImportSource.source_id == GenesisImportRecord.source_id),
                )
                .where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == import_run_id,
                    GenesisImportRecord.import_record_id == import_record_id,
                    GenesisImportRecord.source_id == source_id,
                    GenesisImportRecord.processing_state == "planned",
                    GenesisImportRecord.nomination_sha256 == nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key == nomination_idempotency_key,
                    GenesisImportRun.plan_sha256 == plan_sha256,
                    GenesisImportSource.source_path == source_path,
                    GenesisImportSource.blob_object_id == blob_object_id,
                    GenesisImportSource.raw_sha256 == raw_sha256,
                )
            )
        ).one_or_none()
        if row is None:
            raise GenesisImportStorageError("planned_record_context_mismatch")
        return PendingGenesisRecord(
            import_record_id=row.import_record_id,
            source_id=row.source_id,
            nomination_sha256=bytes(row.nomination_sha256),
            nomination_idempotency_key=row.nomination_idempotency_key,
        )

    async def stage_import_plan(
        self,
        *,
        run: GenesisImportRun,
        sources: tuple[GenesisImportSource, ...],
        records: tuple[GenesisImportRecord, ...],
        exclusions: tuple[GenesisImportExclusion, ...],
        supersessions: tuple[GenesisImportSupersession, ...],
    ) -> GenesisRunStatus:
        """Atomically archive one exact protected plan without returning content."""

        if len(run.plan_sha256) != 32 or run.source_count != len(sources):
            raise GenesisImportStorageError("invalid_import_plan")
        tenant_id = run.tenant_id
        import_run_id = run.import_run_id
        source_ids = {source.source_id for source in sources}
        record_ids = {record.import_record_id for record in records}
        exclusion_ids = {exclusion.exclusion_id for exclusion in exclusions}
        if len(source_ids) != len(sources) or len(record_ids) != len(records):
            raise GenesisImportStorageError("duplicate_plan_identity")
        if len(exclusion_ids) != len(exclusions):
            raise GenesisImportStorageError("duplicate_plan_identity")
        if any(
            source.tenant_id != tenant_id or source.import_run_id != import_run_id
            for source in sources
        ):
            raise GenesisImportStorageError("source_plan_mismatch")
        if any(
            record.tenant_id != tenant_id
            or record.import_run_id != import_run_id
            or record.source_id not in source_ids
            or record.processing_state != "planned"
            or record.selection_decision_id is not None
            or record.event_id is not None
            or record.memory_id is not None
            or record.processed_at is not None
            for record in records
        ):
            raise GenesisImportStorageError("record_plan_mismatch")
        if any(
            exclusion.tenant_id != tenant_id
            or exclusion.import_run_id != import_run_id
            or exclusion.source_id not in source_ids
            or (
                exclusion.applies_to_record_id is not None
                and exclusion.applies_to_record_id not in record_ids
            )
            for exclusion in exclusions
        ):
            raise GenesisImportStorageError("exclusion_plan_mismatch")
        if any(
            edge.tenant_id != tenant_id
            or edge.import_run_id != import_run_id
            or edge.source_id not in source_ids
            or (
                edge.predecessor_record_id is not None
                and edge.predecessor_record_id not in record_ids
            )
            or (edge.successor_record_id is not None and edge.successor_record_id not in record_ids)
            or (
                edge.predecessor_exclusion_id is not None
                and edge.predecessor_exclusion_id not in exclusion_ids
            )
            or (
                edge.successor_exclusion_id is not None
                and edge.successor_exclusion_id not in exclusion_ids
            )
            for edge in supersessions
        ):
            raise GenesisImportStorageError("supersession_plan_mismatch")
        corrected_sources = {
            source.source_id
            for source in sources
            if source.compatibility_correction_version is not None
        }
        if corrected_sources:
            corrected_record_ids = {
                record.source_item_identity
                for record in records
                if record.source_id in corrected_sources and record.record_kind == "candidate"
            }
            corrected_exclusion_ids = {
                exclusion.source_exclusion_identity
                for exclusion in exclusions
                if exclusion.source_id in corrected_sources
            }
            if "candidate-0b388348-39d8-46da-b78c-956dbe1e02e5" not in corrected_record_ids or not {
                "exclusion-dca9d34c-7b22-4ce2-885d-e3ba8f1c4f54",
                "exclusion-087d1403-46ed-43d3-93e2-14e5bbf3794c",
            } <= corrected_exclusion_ids:
                raise GenesisImportStorageError("compatibility_identity_mismatch")

        existing_run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.plan_sha256 == run.plan_sha256,
            )
        )
        if existing_run is not None:
            if (
                existing_run.source_repository != run.source_repository
                or existing_run.snapshot_commit != run.snapshot_commit
                or existing_run.manifest_version != run.manifest_version
                or existing_run.mapping_version != run.mapping_version
                or existing_run.compatibility_version != run.compatibility_version
                or existing_run.parser_schema_versions != run.parser_schema_versions
                or existing_run.policy_id != run.policy_id
                or existing_run.policy_version != run.policy_version
                or bytes(existing_run.policy_sha256) != bytes(run.policy_sha256)
                or existing_run.source_count != run.source_count
                or bytes(existing_run.pre_state_sha256) != bytes(run.pre_state_sha256)
                or existing_run.backup_reference != run.backup_reference
            ):
                raise GenesisImportStorageError("import_plan_conflict")
            existing = await self.run_status(tenant_id=tenant_id, plan_sha256=run.plan_sha256)
            if existing is None:
                raise GenesisImportStorageError("import_plan_conflict")
            return existing
        conflicting_plan = await self._session.scalar(
            select(GenesisImportRun.import_run_id).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.source_repository == run.source_repository,
                GenesisImportRun.snapshot_commit == run.snapshot_commit,
                GenesisImportRun.mapping_version == run.mapping_version,
            )
        )
        if conflicting_plan is not None:
            raise GenesisImportStorageError("import_plan_conflict")

        try:
            async with self._session.begin_nested():
                self._session.add(run)
                self._session.add_all(sources)
                self._session.add_all(records)
                self._session.add_all(exclusions)
                self._session.add_all(supersessions)
                await self._session.flush()
        except IntegrityError:
            existing = await self.run_status(tenant_id=tenant_id, plan_sha256=run.plan_sha256)
            if existing is not None:
                return existing
            raise GenesisImportStorageError("import_plan_conflict") from None
        return GenesisRunStatus(
            import_run_id=import_run_id,
            plan_sha256=bytes(run.plan_sha256),
            source_count=len(sources),
            planned_record_count=len(records),
            terminal_record_count=0,
            completed=False,
        )

    async def terminalize_record(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        import_record_id: UUID,
        nomination_sha256: bytes,
        outcome: GenesisTerminalOutcome,
        selection_decision_id: UUID,
        event_id: UUID | None = None,
        memory_id: UUID | None = None,
        processed_at: datetime,
    ) -> GenesisRecordStatus:
        if len(nomination_sha256) != 32:
            raise GenesisImportStorageError("invalid_nomination_digest")
        linked = event_id is not None and memory_id is not None
        if (outcome == "candidate") != linked or ((event_id is None) != (memory_id is None)):
            raise GenesisImportStorageError("invalid_terminal_result")

        result = await self._session.execute(
            update(GenesisImportRecord)
            .where(
                GenesisImportRecord.tenant_id == tenant_id,
                GenesisImportRecord.import_run_id == import_run_id,
                GenesisImportRecord.import_record_id == import_record_id,
                GenesisImportRecord.nomination_sha256 == nomination_sha256,
                GenesisImportRecord.processing_state == "planned",
            )
            .values(
                processing_state=outcome,
                selection_decision_id=selection_decision_id,
                event_id=event_id,
                memory_id=memory_id,
                processed_at=processed_at,
            )
        )
        if cast(CursorResult[Any], result).rowcount == 1:
            return GenesisRecordStatus(
                import_record_id=import_record_id,
                processing_state=outcome,
                selection_decision_id=selection_decision_id,
                event_id=event_id,
                memory_id=memory_id,
                processed_at=processed_at,
            )

        row = await self._session.scalar(
            select(GenesisImportRecord).where(
                GenesisImportRecord.tenant_id == tenant_id,
                GenesisImportRecord.import_run_id == import_run_id,
                GenesisImportRecord.import_record_id == import_record_id,
            )
        )
        if row is None:
            raise GenesisImportStorageError("import_record_not_found")
        if bytes(row.nomination_sha256) != nomination_sha256:
            raise GenesisImportStorageError("import_plan_mismatch")
        status = _record_status(row)
        expected = GenesisRecordStatus(
            import_record_id=import_record_id,
            processing_state=outcome,
            selection_decision_id=selection_decision_id,
            event_id=event_id,
            memory_id=memory_id,
            processed_at=processed_at,
        )
        if status != expected:
            raise GenesisImportStorageError("terminal_result_conflict")
        return status

    async def pending_records(
        self, *, tenant_id: UUID, import_run_id: UUID, limit: int = 500
    ) -> tuple[PendingGenesisRecord, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise GenesisImportStorageError("invalid_limit")
        rows = (
            await self._session.execute(
                select(
                    GenesisImportRecord.import_record_id,
                    GenesisImportRecord.source_id,
                    GenesisImportRecord.nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key,
                )
                .where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == import_run_id,
                    GenesisImportRecord.processing_state == "planned",
                )
                .order_by(GenesisImportRecord.import_record_id)
                .limit(limit)
            )
        ).all()
        return tuple(
            PendingGenesisRecord(record_id, source_id, bytes(digest), idempotency_key)
            for record_id, source_id, digest, idempotency_key in rows
        )

    async def run_status(self, *, tenant_id: UUID, plan_sha256: bytes) -> GenesisRunStatus | None:
        if len(plan_sha256) != 32:
            raise GenesisImportStorageError("invalid_plan_digest")
        run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.plan_sha256 == plan_sha256,
            )
        )
        if run is None:
            return None
        planned, terminal = (
            await self._session.execute(
                select(
                    func.count().filter(GenesisImportRecord.processing_state == "planned"),
                    func.count().filter(GenesisImportRecord.processing_state != "planned"),
                ).where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == run.import_run_id,
                )
            )
        ).one()
        completed = await self._session.scalar(
            select(GenesisImportRunResult.import_run_id).where(
                GenesisImportRunResult.tenant_id == tenant_id,
                GenesisImportRunResult.import_run_id == run.import_run_id,
            )
        )
        return GenesisRunStatus(
            import_run_id=run.import_run_id,
            plan_sha256=bytes(run.plan_sha256),
            source_count=run.source_count,
            planned_record_count=int(planned),
            terminal_record_count=int(terminal),
            completed=completed is not None,
        )

    async def complete_run(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        plan_sha256: bytes,
        pre_state_sha256: bytes,
        backup_reference: str,
        replay_verified: bool,
        completed_at: datetime,
    ) -> GenesisRunResultStatus:
        if len(plan_sha256) != 32 or len(pre_state_sha256) != 32:
            raise GenesisImportStorageError("invalid_completion_digest")
        run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.import_run_id == import_run_id,
                GenesisImportRun.plan_sha256 == plan_sha256,
            )
        )
        if run is None:
            raise GenesisImportStorageError("import_plan_not_found")
        if (
            bytes(run.pre_state_sha256) != pre_state_sha256
            or run.backup_reference != backup_reference
        ):
            raise GenesisImportStorageError("recovery_evidence_mismatch")
        if not replay_verified:
            raise GenesisImportStorageError("replay_not_verified")

        existing = await self._session.get(
            GenesisImportRunResult,
            {"tenant_id": tenant_id, "import_run_id": import_run_id},
        )
        if existing is not None:
            if existing.replay_verified != replay_verified or existing.completed_at != completed_at:
                raise GenesisImportStorageError("completion_result_conflict")
            return GenesisRunResultStatus(
                import_run_id=existing.import_run_id,
                planned_record_count=existing.planned_record_count,
                candidate_count=existing.candidate_count,
                omit_count=existing.omit_count,
                reject_count=existing.reject_count,
                replay_verified=existing.replay_verified,
                completed_at=existing.completed_at,
            )

        count_rows = (
            await self._session.execute(
                select(GenesisImportRecord.processing_state, func.count())
                .where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == import_run_id,
                )
                .group_by(GenesisImportRecord.processing_state)
            )
        ).all()
        counts: dict[str, int] = {state: int(count) for state, count in count_rows}
        if int(counts.get("planned", 0)) != 0:
            raise GenesisImportStorageError("import_plan_incomplete")
        candidate_count = int(counts.get("candidate", 0))
        omit_count = int(counts.get("omit", 0))
        reject_count = int(counts.get("reject", 0))
        planned_record_count = candidate_count + omit_count + reject_count
        await self._session.execute(
            insert(GenesisImportRunResult).values(
                tenant_id=tenant_id,
                import_run_id=import_run_id,
                planned_record_count=planned_record_count,
                candidate_count=candidate_count,
                omit_count=omit_count,
                reject_count=reject_count,
                replay_verified=replay_verified,
                completed_at=completed_at,
            )
        )
        return GenesisRunResultStatus(
            import_run_id=import_run_id,
            planned_record_count=planned_record_count,
            candidate_count=candidate_count,
            omit_count=omit_count,
            reject_count=reject_count,
            replay_verified=replay_verified,
            completed_at=completed_at,
        )
