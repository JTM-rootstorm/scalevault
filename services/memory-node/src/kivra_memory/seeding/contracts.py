"""Strict schema-backed contracts for private seed nomination bundles."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kivra_memory.domain.commands import MemoryInput
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.domain.values import UnitScore

SymbolicName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedText = Annotated[str, Field(min_length=1, max_length=4096)]

_VALIDATION_SUBJECT_ID = new_uuid7(timestamp_ms=0, random_bits=0)


class SeedContract(BaseModel):
    """Strict immutable base for local private-seed documents."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SymbolicSeedSelector(SeedContract):
    """Names resolved only by the authorized nomination service at apply time."""

    tenant: SymbolicName
    persona: SymbolicName
    lineage: SymbolicName
    branch: SymbolicName
    subject_kind: SubjectKind
    subject: SymbolicName


class SeedEvidenceReference(SeedContract):
    """Content-free provenance pointer reviewed alongside a private seed."""

    source_ref: Annotated[str, Field(min_length=1, max_length=512)]
    source_sha256: Digest


class SeedMemory(SeedContract):
    """Memory semantics without canonical identifiers or transport provenance."""

    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: Literal[MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED]
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: BoundedText
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...],
        Field(min_length=1, max_length=32),
    ]
    confidence: UnitScore
    salience: UnitScore
    durability: UnitScore
    sensitivity: Annotated[int, Field(ge=0, le=4)]

    def validate_for_selector(self, selector: SymbolicSeedSelector) -> None:
        """Delegate ontology and structural constraints to the domain command model."""

        MemoryInput(
            subject_id=_VALIDATION_SUBJECT_ID,
            subject_kind=selector.subject_kind,
            category=self.category,
            ontological_status=self.ontological_status,
            scope=self.scope,
            visibility=self.visibility,
            statement=self.statement,
            reason_to_remember=self.reason_to_remember,
            interpretation_limits=self.interpretation_limits,
            confidence=self.confidence,
            salience=self.salience,
            durability=self.durability,
            sensitivity=self.sensitivity,
            authority_class=AuthorityClass.IMPORTED_LEGACY_MEMORY,
            metadata={},
        )


class PrivateSeedRecord(SeedContract):
    """One reviewed seed nomination with symbolic resolution and provenance."""

    record_key: SymbolicName
    selector: SymbolicSeedSelector
    memory: SeedMemory
    evidence: Annotated[tuple[SeedEvidenceReference, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def validate_record(self) -> PrivateSeedRecord:
        self.memory.validate_for_selector(self.selector)
        evidence_keys = {(item.source_ref, item.source_sha256) for item in self.evidence}
        if len(evidence_keys) != len(self.evidence):
            raise ValueError("seed evidence references must be unique")
        return self


class PrivateSeedBundle(SeedContract):
    """Complete private seed input; its JSON schema is generated from this model."""

    contract_version: Literal["scalevault-private-seed-v1"]
    bundle_key: SymbolicName
    records: Annotated[tuple[PrivateSeedRecord, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def validate_unique_keys(self) -> PrivateSeedBundle:
        keys = [record.record_key for record in self.records]
        if len(keys) != len(set(keys)):
            raise ValueError("seed record keys must be unique")
        return self
