"""Strict live GitHub proposal adapter for the policy-gated selection service."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kivra_memory.domain.canonical_json import JsonValue, canonical_json_bytes
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.ingress.validator import IngressFormat, ValidatedIngress
from kivra_memory.policy import (
    EpistemicQualifier,
    NominationEvidenceReference,
    NominationProposal,
    SelectionBasis,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SCOPE_SUBJECT = {
    MemoryScope.PERSONA: SubjectKind.PERSONA,
    MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
    MemoryScope.PROJECT: SubjectKind.PROJECT,
    MemoryScope.EPISODIC: SubjectKind.EPISODE,
}


class LiveProposalAdapterError(ValueError):
    """Content-free failure while adapting an already schema-validated proposal."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
            raise ValueError("adapter error code is invalid")
        self.code = code
        super().__init__(code)


class GitHubNominationCommand(BaseModel):
    """Selection command bound to one validated ingress transaction participant."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["mcp-mutation-v2"] = "mcp-mutation-v2"
    idempotency_key: Annotated[str, Field(min_length=1, max_length=255)]
    persona_id: UUID
    branch_id: UUID
    reason: Annotated[str, Field(min_length=1, max_length=4096)]
    proposal: NominationProposal
    logical_session_id: UUID | None = None
    transaction_binding_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("persona_id", "branch_id", "logical_session_id")
    @classmethod
    def validate_uuid7(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value


def transaction_binding_sha256(
    *,
    ingress_id: UUID,
    installation_id: UUID,
    repository_external_id: str,
    immutable_path: str,
    commit_id: str,
    blob_id: str,
    payload_sha256: bytes,
) -> str:
    """Bind a selection participant to immutable, content-free discovery facts."""

    require_uuid7(ingress_id, field_name="ingress_id")
    require_uuid7(installation_id, field_name="installation_id")
    if len(payload_sha256) != 32:
        raise ValueError("payload_sha256 must contain 32 bytes")
    material = {
        "version": "scalevault.github-ingress-transaction.v1",
        "ingress_id": str(ingress_id),
        "installation_id": str(installation_id),
        "repository_external_id": repository_external_id,
        "immutable_path": immutable_path,
        "commit_id": commit_id,
        "blob_id": blob_id,
        "payload_sha256": payload_sha256.hex(),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _required(
    payload: dict[str, JsonValue],
    name: str,
    expected: type[object] | tuple[type[object], ...],
) -> object:
    value = payload.get(name)
    if not isinstance(value, expected):
        raise LiveProposalAdapterError("validated_payload_invalid")
    return value


def _optional_datetime(payload: dict[str, JsonValue], name: str) -> datetime | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise LiveProposalAdapterError("validated_payload_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LiveProposalAdapterError("validated_payload_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LiveProposalAdapterError("validated_payload_invalid")
    return parsed


def adapt_live_proposal(
    validated: ValidatedIngress,
    *,
    expected_installation_id: UUID,
    transaction_binding_sha256: str,
) -> GitHubNominationCommand:
    """Convert V2 bytes to the existing transport-neutral nomination DTO.

    The visible evidence summary is intentionally not copied into canonical metadata,
    selection audit rows, or command receipts.  Trusted resolver facts remain a
    server-side concern of :class:`SelectionEngine`.
    """

    if validated.format is not IngressFormat.PROPOSAL_V2:
        raise LiveProposalAdapterError("proposal_version_not_live")
    if _SHA256.fullmatch(transaction_binding_sha256) is None:
        raise LiveProposalAdapterError("transaction_binding_invalid")

    payload = validated.payload
    try:
        proposal_id = UUID(cast(str, _required(payload, "proposal_id", str)))
        installation_id = UUID(cast(str, _required(payload, "installation_id", str)))
        persona_id = UUID(cast(str, _required(payload, "persona_id", str)))
        branch_id = UUID(cast(str, _required(payload, "branch_id", str)))
        subject_id = UUID(cast(str, _required(payload, "subject_id", str)))
        subject_kind = SubjectKind(cast(str, _required(payload, "subject_kind", str)))
        scope = MemoryScope(cast(str, _required(payload, "scope", str)))
        visibility = MemoryVisibility(cast(str, _required(payload, "visibility", str)))
        origin_value = payload.get("origin_session_id")
        origin_session_id = UUID(origin_value) if isinstance(origin_value, str) else None
        evidence = tuple(
            NominationEvidenceReference.model_validate(item)
            for item in cast(list[JsonValue], _required(payload, "evidence_references", list))
        )
        proposal = NominationProposal(
            subject_id=subject_id,
            subject_kind=subject_kind,
            category=MemoryCategory(cast(str, _required(payload, "category", str))),
            ontological_status=OntologicalStatus(
                cast(str, _required(payload, "ontological_status", str))
            ),
            scope=scope,
            visibility=visibility,
            statement=cast(str, _required(payload, "statement", str)),
            reason_to_remember=cast(str, _required(payload, "reason_to_remember", str)),
            interpretation_limits=tuple(
                cast(list[str], _required(payload, "interpretation_limits", list))
            ),
            confidence=Decimal(str(_required(payload, "confidence", (int, float)))),
            salience=Decimal(str(_required(payload, "salience", (int, float)))),
            durability=Decimal(str(_required(payload, "durability", (int, float)))),
            sensitivity=cast(int, _required(payload, "sensitivity", int)),
            valid_from=_optional_datetime(payload, "valid_from"),
            valid_to=_optional_datetime(payload, "valid_to"),
            observed_at=_optional_datetime(payload, "observed_at"),
            origin_session_id=origin_session_id,
            metadata={},
            selection_basis=SelectionBasis(cast(str, _required(payload, "selection_basis", str))),
            epistemic_qualifiers=tuple(
                EpistemicQualifier(value)
                for value in cast(list[str], _required(payload, "epistemic_qualifiers", list))
            ),
            evidence_references=evidence,
        )
    except (TypeError, ValueError):
        raise LiveProposalAdapterError("validated_payload_invalid") from None

    if proposal_id != UUID(validated.source_id):
        raise LiveProposalAdapterError("proposal_identity_mismatch")
    if installation_id != expected_installation_id:
        raise LiveProposalAdapterError("installation_mismatch")
    if scope not in _SCOPE_SUBJECT or _SCOPE_SUBJECT[scope] is not subject_kind:
        raise LiveProposalAdapterError("scope_subject_mismatch")
    if visibility not in {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}:
        raise LiveProposalAdapterError("visibility_forbidden")
    if proposal.sensitivity != 0:
        raise LiveProposalAdapterError("sensitivity_forbidden")

    logical_session_id = origin_session_id if scope is MemoryScope.EPISODIC else None
    if (scope is MemoryScope.EPISODIC) != (origin_session_id is not None):
        raise LiveProposalAdapterError("session_scope_mismatch")
    return GitHubNominationCommand(
        idempotency_key=cast(str, _required(payload, "idempotency_key", str)),
        persona_id=persona_id,
        branch_id=branch_id,
        reason=proposal.reason_to_remember,
        proposal=proposal,
        logical_session_id=logical_session_id,
        transaction_binding_sha256=transaction_binding_sha256,
    )


__all__ = [
    "GitHubNominationCommand",
    "LiveProposalAdapterError",
    "adapt_live_proposal",
    "transaction_binding_sha256",
]
