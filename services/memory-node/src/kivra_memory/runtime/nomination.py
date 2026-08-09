"""Conservative trusted enrichment for direct private nominations."""

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
)
from kivra_memory.domain.enums import AuthorityClass
from kivra_memory.policy import SelectionBasis


class DirectNominationResolver:
    """Resolve only content-free routine-banter omission for direct MCP.

    Direct bearer authentication establishes the caller, not user-statement or
    evidence authority. Every caller-supplied evidence or authority claim
    receives no trusted evidence and therefore deterministically rejects in
    selection policy. The resolver never reads or retains evidence keys or
    opaque reference values.
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
        return _untrusted_context()


def _untrusted_context() -> ResolvedNominationContext:
    return ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
    )


__all__ = ["DirectNominationResolver"]
