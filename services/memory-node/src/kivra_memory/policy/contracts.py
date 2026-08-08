"""Strict, transport-neutral contracts for deterministic memory selection policy."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import UnitScore, normalize_utc_datetime


class SelectionBasis(StrEnum):
    """Closed caller-declared basis evaluated against server-resolved evidence."""

    ROUTINE_BANTER = "routine_banter"
    EXPLICIT_USER_CORRECTION = "explicit_user_correction"
    EXPLICIT_USER_PREFERENCE = "explicit_user_preference"
    EXPLICIT_USER_PERMISSION = "explicit_user_permission"
    VERIFIED_PROJECT_DECISION = "verified_project_decision"
    ASSISTANT_OBSERVATION = "assistant_observation"
    ASSISTANT_INTERPRETATION = "assistant_interpretation"
    IMPORTED_LEGACY = "imported_legacy"
    MEANINGFUL_EPISODIC_ANCHOR = "meaningful_episodic_anchor"
    EXPLICIT_USER_REQUEST = "explicit_user_request"


class ContentSignal(StrEnum):
    """Structured semantic signals; the policy engine never derives these from text."""

    ROLEPLAYED_SCENE = "roleplayed_scene"
    ASSISTANT_PREFERENCE_LIKE = "assistant_preference_like"
    SUBJECTIVE_EXPERIENCE_CLAIM = "subjective_experience_claim"


class EpistemicQualifier(StrEnum):
    """Machine-readable limits that accompany human interpretation-limit prose."""

    ROLEPLAY_NOT_LITERAL = "roleplay_not_literal"
    ASSISTANT_PATTERN_NOT_SUBJECTIVE_EXPERIENCE = (
        "assistant_pattern_not_subjective_experience"
    )
    SINGLE_EPISODE_NOT_STABLE_PATTERN = "single_episode_not_stable_pattern"
    SUBJECTIVE_EXPERIENCE_UNRESOLVED = "subjective_experience_unresolved"
    IMPORTED_SOURCE_UNRECONCILED = "imported_source_unreconciled"


class EvidenceKind(StrEnum):
    USER_STATEMENT = "user_statement"
    USER_CORRECTION = "user_correction"
    USER_CONFIRMATION = "user_confirmation"
    PROJECT_SOURCE = "project_source"
    ASSISTANT_OBSERVATION = "assistant_observation"
    IMPORT_MANIFEST = "import_manifest"
    CONVERSATION_EPISODE = "conversation_episode"


class EvidenceTrust(StrEnum):
    TRUSTED = "trusted"
    CORROBORATED = "corroborated"
    UNVERIFIED = "unverified"


class PolicyOutcome(StrEnum):
    OMIT = "omit"
    REJECT = "reject"
    CANDIDATE = "candidate"
    ACTIVE = "active"


class LifecycleAction(StrEnum):
    NO_OP = "no_op"
    PROMOTE = "promote"
    RETIRE = "retire"


class LifecycleReasonCode(StrEnum):
    NOT_CANDIDATE = "not_candidate"
    POLICY_PROFILE_MISMATCH = "policy_profile_mismatch"
    TRUSTED_USER_CONFIRMATION = "trusted_user_confirmation"
    INDEPENDENT_OBSERVATIONS = "independent_observations"
    PROTECTED_CANDIDATE = "protected_candidate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    EXPIRY_NOT_DUE = "expiry_not_due"
    CANDIDATE_EXPIRED = "candidate_expired"


class PolicyReasonCode(StrEnum):
    NO_MATCHING_RULE = "no_matching_rule"
    ROUTINE_BANTER_OMITTED = "routine_banter_omitted"
    EXPLICIT_USER_CORRECTION = "explicit_user_correction"
    EXPLICIT_USER_PREFERENCE = "explicit_user_preference"
    EXPLICIT_USER_PERMISSION = "explicit_user_permission"
    VERIFIED_PROJECT_DECISION = "verified_project_decision"
    ASSISTANT_OBSERVATION_CANDIDATE = "assistant_observation_candidate"
    ASSISTANT_INTERPRETATION_CANDIDATE = "assistant_interpretation_candidate"
    IMPORTED_LEGACY_CANDIDATE = "imported_legacy_candidate"
    MEANINGFUL_EPISODIC_ANCHOR = "meaningful_episodic_anchor"
    EXPLICIT_USER_REQUEST = "explicit_user_request"
    REASON_REQUIRED = "reason_required"
    EVIDENCE_REQUIRED = "evidence_required"
    AUTHORITY_NOT_ESTABLISHED = "authority_not_established"
    BASIS_CATEGORY_INCOMPATIBLE = "basis_category_incompatible"
    CATEGORY_ONTOLOGY_INCOMPATIBLE = "category_ontology_incompatible"
    ROLEPLAY_LITERALIZATION = "roleplay_literalization"
    ROLEPLAY_SCOPE_FORBIDDEN = "roleplay_scope_forbidden"
    ROLEPLAY_VISIBILITY_FORBIDDEN = "roleplay_visibility_forbidden"
    EPISTEMIC_QUALIFICATION_REQUIRED = "epistemic_qualification_required"
    SENTIENCE_OVERCLAIM = "sentience_overclaim"


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EvidenceSummary(PolicyModel):
    """Payload-free evidence facts resolved or verified before policy evaluation."""

    evidence_key: Annotated[str, Field(min_length=1, max_length=255)]
    kind: EvidenceKind
    trust: EvidenceTrust

    @field_validator("evidence_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence key cannot be blank")
        return value


class NominationEvidenceReference(PolicyModel):
    """Untrusted opaque reference resolved into evidence facts outside the public DTO."""

    evidence_key: Annotated[str, Field(min_length=1, max_length=255)]
    opaque_reference: Annotated[str, Field(min_length=1, max_length=2048)]

    @field_validator("evidence_key", "opaque_reference")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("nomination evidence values cannot be blank")
        return value


class NominationProposal(PolicyModel):
    """Public semantic nomination before trusted authority and evidence resolution."""

    subject_id: UUID
    subject_kind: SubjectKind
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    statement: Annotated[str, Field(min_length=1, max_length=8192)]
    reason_to_remember: Annotated[str, Field(min_length=1, max_length=4096)]
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...], Field(max_length=32)
    ]
    confidence: UnitScore
    salience: UnitScore
    durability: UnitScore
    sensitivity: Annotated[int, Field(ge=0, le=4)]
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    observed_at: datetime | None = None
    origin_session_id: UUID | None = None
    metadata: Annotated[dict[str, object], Field(max_length=128)]
    selection_basis: SelectionBasis
    epistemic_qualifiers: Annotated[tuple[EpistemicQualifier, ...], Field(max_length=16)]
    evidence_references: Annotated[
        tuple[NominationEvidenceReference, ...], Field(max_length=64)
    ]

    @field_validator("subject_id", "origin_session_id")
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value

    @field_validator("valid_from", "valid_to", "observed_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        try:
            return normalize_utc_datetime(value)
        except ValueError as error:
            field_name = getattr(info, "field_name", "datetime")
            raise ValueError(f"{field_name} must be timezone-aware") from error

    @field_validator("statement", "reason_to_remember")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("nomination content cannot be blank")
        return value

    @field_validator("interpretation_limits")
    @classmethod
    def validate_interpretation_limits(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in value):
            raise ValueError("interpretation limits cannot be blank")
        if len(value) != len(set(value)):
            raise ValueError("interpretation limits must be unique")
        return value

    @model_validator(mode="after")
    def validate_nomination(self) -> NominationProposal:
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("valid_to must not precede valid_from")
        if len(self.epistemic_qualifiers) != len(set(self.epistemic_qualifiers)):
            raise ValueError("epistemic qualifiers must be unique")
        evidence_keys = tuple(item.evidence_key for item in self.evidence_references)
        if len(evidence_keys) != len(set(evidence_keys)):
            raise ValueError("nomination evidence keys must be unique")
        if len(canonical_json_bytes(self.metadata)) > 65_536:
            raise ValueError("nomination metadata exceeds 65536 canonical bytes")
        return self


class SelectionRequest(PolicyModel):
    """Structured proposal evaluated without inspecting statement or evidence payload text."""

    basis: SelectionBasis
    category: MemoryCategory
    ontological_status: OntologicalStatus
    scope: MemoryScope
    visibility: MemoryVisibility
    effective_authority_class: AuthorityClass
    content_signals: Annotated[frozenset[ContentSignal], Field(max_length=8)] = frozenset()
    epistemic_qualifiers: Annotated[
        frozenset[EpistemicQualifier], Field(max_length=16)
    ] = frozenset()
    reason_to_remember: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    interpretation_limits: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...], Field(max_length=32)
    ] = ()
    evidence: Annotated[tuple[EvidenceSummary, ...], Field(max_length=64)] = ()

    @field_validator("reason_to_remember")
    @classmethod
    def validate_reason(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("reason to remember cannot be blank")
        return value

    @field_validator("interpretation_limits")
    @classmethod
    def validate_limits(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in value):
            raise ValueError("interpretation limits cannot be blank")
        if len(value) != len(set(value)):
            raise ValueError("interpretation limits must be unique")
        return value

    @model_validator(mode="after")
    def validate_evidence_keys(self) -> SelectionRequest:
        keys = tuple(item.evidence_key for item in self.evidence)
        if len(keys) != len(set(keys)):
            raise ValueError("evidence keys must be unique")
        return self


class EvidenceRequirement(PolicyModel):
    kinds: Annotated[tuple[EvidenceKind, ...], Field(min_length=1, max_length=8)]
    trusts: Annotated[tuple[EvidenceTrust, ...], Field(min_length=1, max_length=3)]
    minimum: Annotated[int, Field(ge=1, le=64)] = 1

    @model_validator(mode="after")
    def validate_unique_values(self) -> EvidenceRequirement:
        if len(self.kinds) != len(set(self.kinds)):
            raise ValueError("evidence requirement kinds must be unique")
        if len(self.trusts) != len(set(self.trusts)):
            raise ValueError("evidence requirement trusts must be unique")
        return self


class BasisRule(PolicyModel):
    rule_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=128)]
    basis: SelectionBasis
    outcome: Literal[PolicyOutcome.OMIT, PolicyOutcome.CANDIDATE, PolicyOutcome.ACTIVE]
    reason_code: PolicyReasonCode
    allowed_categories: Annotated[tuple[MemoryCategory, ...], Field(max_length=16)] = ()
    required_authority: AuthorityClass | None = None
    evidence_requirement: EvidenceRequirement | None = None
    required_qualifiers: Annotated[tuple[EpistemicQualifier, ...], Field(max_length=16)] = ()
    requires_interpretation_limits: bool = False
    candidate_ttl_days: Annotated[int | None, Field(ge=1, le=3650)] = None

    @model_validator(mode="after")
    def validate_rule(self) -> BasisRule:
        for values, label in (
            (self.allowed_categories, "allowed categories"),
            (self.required_qualifiers, "required qualifiers"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"basis-rule {label} must be unique")
        if (self.outcome is PolicyOutcome.CANDIDATE) != (self.candidate_ttl_days is not None):
            raise ValueError("candidate rules require a TTL and non-candidate rules forbid one")
        return self


class SignalGuardrail(PolicyModel):
    rule_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=128)]
    signal: ContentSignal
    allowed_categories: Annotated[tuple[MemoryCategory, ...], Field(min_length=1, max_length=16)]
    allowed_ontologies: Annotated[
        tuple[OntologicalStatus, ...], Field(min_length=1, max_length=8)
    ]
    allowed_scopes: Annotated[tuple[MemoryScope, ...], Field(min_length=1, max_length=6)]
    allowed_visibilities: Annotated[
        tuple[MemoryVisibility, ...], Field(min_length=1, max_length=4)
    ]
    required_qualifiers: Annotated[
        tuple[EpistemicQualifier, ...], Field(min_length=1, max_length=16)
    ]
    requires_interpretation_limits: bool = True
    force_candidate: bool = False
    forced_candidate_ttl_days: Annotated[int | None, Field(ge=1, le=3650)] = None
    violation_code: PolicyReasonCode

    @model_validator(mode="after")
    def validate_unique_values(self) -> SignalGuardrail:
        for values, label in (
            (self.allowed_categories, "categories"),
            (self.allowed_ontologies, "ontologies"),
            (self.allowed_scopes, "scopes"),
            (self.allowed_visibilities, "visibilities"),
            (self.required_qualifiers, "qualifiers"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"guardrail {label} must be unique")
        if self.force_candidate != (self.forced_candidate_ttl_days is not None):
            raise ValueError("candidate-forcing guardrails require exactly one TTL")
        return self


class SelectionPolicyProfile(PolicyModel):
    policy_id: Literal["scalevault-memory-selection"]
    profile_version: Literal["selection-v1"]
    precedence: tuple[
        Literal["structural", "hard_guardrail", "evidence", "basis", "qualification"],
        Literal["structural", "hard_guardrail", "evidence", "basis", "qualification"],
        Literal["structural", "hard_guardrail", "evidence", "basis", "qualification"],
        Literal["structural", "hard_guardrail", "evidence", "basis", "qualification"],
        Literal["structural", "hard_guardrail", "evidence", "basis", "qualification"],
    ]
    default_outcome: Literal[PolicyOutcome.REJECT]
    default_reason_code: Literal[PolicyReasonCode.NO_MATCHING_RULE]
    basis_rules: Annotated[tuple[BasisRule, ...], Field(min_length=1, max_length=32)]
    signal_guardrails: Annotated[tuple[SignalGuardrail, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_complete_profile(self) -> SelectionPolicyProfile:
        expected_precedence = (
            "structural",
            "hard_guardrail",
            "evidence",
            "basis",
            "qualification",
        )
        if self.precedence != expected_precedence:
            raise ValueError("selection policy precedence must match the v1 deterministic order")
        bases = tuple(rule.basis for rule in self.basis_rules)
        if len(bases) != len(set(bases)) or set(bases) != set(SelectionBasis):
            raise ValueError("selection policy must define every basis exactly once")
        signals = tuple(rule.signal for rule in self.signal_guardrails)
        if len(signals) != len(set(signals)) or set(signals) != set(ContentSignal):
            raise ValueError("selection policy must define every content signal exactly once")
        ids = tuple(rule.rule_id for rule in self.basis_rules) + tuple(
            rule.rule_id for rule in self.signal_guardrails
        )
        if len(ids) != len(set(ids)):
            raise ValueError("selection policy rule identifiers must be unique")
        return self


class PolicyDecision(PolicyModel):
    profile_version: Literal["selection-v1"]
    profile_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    outcome: PolicyOutcome
    reason_codes: Annotated[tuple[PolicyReasonCode, ...], Field(min_length=1, max_length=8)]
    matched_rule_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    required_qualifiers: Annotated[tuple[EpistemicQualifier, ...], Field(max_length=16)] = ()
    candidate_ttl_days: Annotated[int | None, Field(ge=1, le=3650)] = None

    @model_validator(mode="after")
    def validate_decision(self) -> PolicyDecision:
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("policy decision reason codes must be unique")
        if len(self.matched_rule_ids) != len(set(self.matched_rule_ids)):
            raise ValueError("policy decision rule identifiers must be unique")
        if len(self.required_qualifiers) != len(set(self.required_qualifiers)):
            raise ValueError("policy decision qualifiers must be unique")
        if (self.outcome is PolicyOutcome.CANDIDATE) != (self.candidate_ttl_days is not None):
            raise ValueError("candidate decisions require a TTL and other outcomes forbid one")
        return self


class CandidateLifecycleState(PolicyModel):
    """Payload-free candidate facts used by promotion and expiry decisions."""

    status: MemoryStatus
    selection_basis: SelectionBasis
    content_signals: Annotated[frozenset[ContentSignal], Field(max_length=8)] = frozenset()
    evidence: Annotated[tuple[EvidenceSummary, ...], Field(max_length=64)] = ()
    policy_profile_version: Annotated[
        str, Field(pattern=r"^selection-v[1-9][0-9]*$", max_length=64)
    ]
    policy_profile_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def validate_evidence_keys(self) -> CandidateLifecycleState:
        keys = tuple(item.evidence_key for item in self.evidence)
        if len(keys) != len(set(keys)):
            raise ValueError("candidate lifecycle evidence keys must be unique")
        return self


class ExpiryEvaluation(PolicyModel):
    candidate: CandidateLifecycleState
    deadline: datetime
    evaluated_at: datetime

    @field_validator("deadline", "evaluated_at")
    @classmethod
    def normalize_datetime(cls, value: datetime) -> datetime:
        return normalize_utc_datetime(value)


class LifecycleDecision(PolicyModel):
    action: LifecycleAction
    reason_code: LifecycleReasonCode
    policy_profile_version: Literal["selection-v1"]
    policy_profile_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
