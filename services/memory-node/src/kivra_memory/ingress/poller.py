"""Conditional immutable GitHub proposal snapshot polling."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from kivra_memory.ingress.github_client import (
    GitHubProposalClient,
    GitHubProposalError,
    GitHubProposalObject,
)


class GitHubAppendOnlyViolation(GitHubProposalError):
    """Raised when a previously observed create-only path changes or disappears."""


@dataclass(frozen=True, slots=True)
class GitHubSnapshotPollResult:
    """One conditional poll result without any canonical mutation authority."""

    next_etag: str | None
    unchanged: bool
    commit_id: str | None
    tree_id: str | None
    proposals: tuple[GitHubProposalObject, ...]

    def __post_init__(self) -> None:
        if self.unchanged:
            if self.commit_id is not None or self.tree_id is not None or self.proposals:
                raise ValueError("an unchanged poll cannot contain snapshot objects")
        elif self.commit_id is None or self.tree_id is None:
            raise ValueError("a changed poll requires a head commit and tree")


class GitHubSnapshotPoller:
    """Resolve, enumerate, and fetch a single immutable GitHub snapshot."""

    def __init__(self, client: GitHubProposalClient) -> None:
        self._client = client

    def poll(
        self,
        etag: str | None = None,
        *,
        trusted_commit_id: str,
        trusted_tree_id: str,
        known_objects: Mapping[str, str] | None = None,
    ) -> GitHubSnapshotPollResult:
        """Fetch one snapshot and reject changes to previously observed paths.

        ``known_objects`` maps normalized provider paths to the immutable blob IDs
        recorded when those paths were first discovered. It is deliberately an
        input: the transport has no database or mutation capability of its own.
        """

        known = known_objects or {}
        for path in known:
            self._client.validate_proposal_path(path)

        head = self._client.resolve_head(etag)
        if head.unchanged:
            return GitHubSnapshotPollResult(
                next_etag=head.next_etag,
                unchanged=True,
                commit_id=None,
                tree_id=None,
                proposals=(),
            )
        if head.commit_id is None or head.tree_id is None:
            raise GitHubProposalError("GitHub branch head response was invalid")

        self._client.verify_additive_history(
            trusted_commit_id=trusted_commit_id,
            trusted_tree_id=trusted_tree_id,
            head_commit_id=head.commit_id,
            head_tree_id=head.tree_id,
        )

        entries = self._client.enumerate_tree(head.tree_id)
        current = {entry.path: entry.blob_id for entry in entries}
        if any(current.get(path) != blob_id for path, blob_id in known.items()):
            raise GitHubAppendOnlyViolation("GitHub append-only object provenance changed")

        proposals = tuple(
            self._client.fetch_blob(
                commit_id=head.commit_id,
                path=entry.path,
                blob_id=entry.blob_id,
            )
            for entry in entries
        )
        return GitHubSnapshotPollResult(
            next_etag=head.next_etag,
            unchanged=False,
            commit_id=head.commit_id,
            tree_id=head.tree_id,
            proposals=proposals,
        )
