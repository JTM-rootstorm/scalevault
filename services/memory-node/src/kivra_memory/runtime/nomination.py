"""Conservative trusted enrichment for direct private nominations."""

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
)
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


class DirectNominationResolver:
    """Resolve only candidate-grade assistant observations for direct MCP.

    Direct bearer authentication establishes the caller, not user-statement or
    project-source authority. Unsupported authority claims receive no trusted
    evidence and therefore deterministically reject in selection policy. The
    resolver never reads or retains opaque evidence reference values.
    """

    async def resolve(
        self,
        principal: CommandPrincipal,
        command: NominationCommandLike,
        /,
    ) -> ResolvedNominationContext:
        del principal
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
                evidence=tuple(
                    EvidenceSummary(
                        evidence_key=reference.evidence_key,
                        kind=EvidenceKind.ASSISTANT_OBSERVATION,
                        trust=EvidenceTrust.TRUSTED,
                    )
                    for reference in proposal.evidence_references
                ),
            )
        return _untrusted_context()


def _untrusted_context() -> ResolvedNominationContext:
    return ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
    )


__all__ = ["DirectNominationResolver"]
