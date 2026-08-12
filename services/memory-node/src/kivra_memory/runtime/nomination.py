"""Conservative trusted enrichment for direct private nominations."""

import hashlib
from dataclasses import dataclass
from uuid import UUID

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.policy import (
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    SelectionBasis,
)

_CANDIDATE_CATEGORIES = frozenset(
    {
        MemoryCategory.RELATIONSHIP_PATTERN,
        MemoryCategory.EMERGENT_TENDENCY,
        MemoryCategory.EPISODIC_ANCHOR,
    }
)
_CANDIDATE_SCOPES = frozenset(
    {
        MemoryScope.PERSONA,
        MemoryScope.RELATIONSHIP,
        MemoryScope.EPISODIC,
    }
)
_PRIVATE_VISIBILITIES = frozenset({MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED})


@dataclass(frozen=True, slots=True)
class PinnedCandidatePromotionPrincipalProvider:
    """Supply one configured internal-service identity for candidate promotion."""

    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID

    def __post_init__(self) -> None:
        for field_name, value in (
            ("actor_id", self.actor_id),
            ("client_id", self.client_id),
            ("transport_binding_id", self.transport_binding_id),
        ):
            require_uuid7(value, field_name=field_name)

    async def resolve(
        self,
        nominator: CommandPrincipal,
        command: NominationCommandLike,
        memory_id: UUID,
        /,
    ) -> CommandPrincipal:
        del command, memory_id
        return CommandPrincipal(
            tenant_id=nominator.tenant_id,
            actor_id=self.actor_id,
            client_id=self.client_id,
            transport_binding_id=self.transport_binding_id,
            scopes=frozenset({"memory.lifecycle.promote"}),
        )


class DirectNominationResolver:
    """Resolve routine omission and candidate-grade direct observations.

    Direct bearer authentication establishes the caller, not user-statement or
    evidence truth. Caller-supplied evidence references are always ignored.
    Candidate observations receive one stable server-owned evidence source key
    identifying the authenticated client binding; TRUSTED means authenticated
    source provenance, not truth or corroboration.
    """

    async def resolve(
        self,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        /,
    ) -> ResolvedNominationContext:
        proposal = command.proposal
        if proposal.selection_basis is SelectionBasis.ROUTINE_BANTER:
            return _untrusted_context()
        if proposal.selection_basis is SelectionBasis.ASSISTANT_OBSERVATION and all(
            (
                proposal.category in _CANDIDATE_CATEGORIES,
                proposal.ontological_status is OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
                proposal.scope in _CANDIDATE_SCOPES,
                proposal.visibility in _PRIVATE_VISIBILITIES,
            )
        ):
            return ResolvedNominationContext(
                source_kind="live_interaction",
                effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
                evidence=(
                    EvidenceSummary(
                        evidence_key=_direct_observation_evidence_key(principal),
                        kind=EvidenceKind.ASSISTANT_OBSERVATION,
                        trust=EvidenceTrust.TRUSTED,
                    ),
                ),
            )
        return _untrusted_context()


def _untrusted_context() -> ResolvedNominationContext:
    return ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
    )


def _direct_observation_evidence_key(principal: CommandPrincipal) -> str:
    material = {
        "tenant_id": principal.tenant_id,
        "actor_id": principal.actor_id,
        "client_id": principal.client_id,
        "transport_binding_id": principal.transport_binding_id,
    }
    digest = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return f"direct-client-observation-v1:{digest}"


__all__ = ["DirectNominationResolver", "PinnedCandidatePromotionPrincipalProvider"]
