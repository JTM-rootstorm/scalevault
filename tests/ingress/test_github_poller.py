"""Tests for immutable conditional GitHub snapshot polling."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from uuid import UUID

import pytest
from kivra_memory.ingress.github_client import (
    GitHubProposalClient,
    GitHubProposalError,
    GitHubResponse,
)
from kivra_memory.ingress.poller import GitHubAppendOnlyViolation, GitHubSnapshotPoller

REPOSITORY_ID = 123456789
INSTALLATION_ID = UUID("019c0000-0000-7000-8000-000000000001")
COMMIT_ID = "1" * 40
TREE_ID = "2" * 40
TOKEN = "test-token"


def _blob_id(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode() + content,
        usedforsecurity=False,
    ).hexdigest()


def _response(
    document: object | None = None,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> GitHubResponse:
    body = b"" if document is None else json.dumps(document).encode()
    return GitHubResponse(status=status, body=body, headers=headers or {})


def _repository() -> dict[str, object]:
    return {
        "id": REPOSITORY_ID,
        "full_name": "JTM-rootstorm/scalevault-memory-ingress",
        "default_branch": "main",
    }


def _head(*, commit_id: str = COMMIT_ID, tree_id: str = TREE_ID) -> dict[str, object]:
    return {"sha": commit_id, "commit": {"tree": {"sha": tree_id}}}


def _commit(commit_id: str, tree_id: str, *parent_ids: str) -> dict[str, object]:
    return {
        "sha": commit_id,
        "tree": {"sha": tree_id},
        "parents": [{"sha": parent_id} for parent_id in parent_ids],
    }


def _path(index: int) -> str:
    proposal_id = UUID(f"019c0000-0000-7000-8000-{index:012d}")
    return f"ingress/v2/{INSTALLATION_ID}/2026/08/{proposal_id}.json"


def _tree_entry(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "mode": "100644",
        "type": "blob",
        "sha": _blob_id(payload),
        "size": len(payload),
    }


def _tree(entries: list[dict[str, object]], *, tree_id: str = TREE_ID) -> dict[str, object]:
    return {"sha": tree_id, "truncated": False, "tree": entries}


def _blob(payload: bytes) -> dict[str, object]:
    return {
        "sha": _blob_id(payload),
        "encoding": "base64",
        "content": base64.b64encode(payload).decode(),
        "size": len(payload),
    }


@dataclass
class StubTransport:
    responses: list[GitHubResponse]
    calls: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        self.calls.append((url, dict(headers)))
        return self.responses.pop(0)


def _client(transport: StubTransport) -> GitHubProposalClient:
    return GitHubProposalClient(
        repository_id=REPOSITORY_ID,
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        default_branch="main",
        ingress_prefix="ingress/v2",
        installation_id=INSTALLATION_ID,
        token=TOKEN,
        transport=transport,
    )


def test_poll_pins_one_head_reads_one_recursive_tree_and_fetches_immutable_blobs() -> None:
    payloads = [b'{"proposal_id":1}\n', b'{"proposal_id":2}\n']
    paths = [_path(2), _path(3)]
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(), headers={"etag": '"new-etag"'}),
            _response(
                _tree(
                    [
                        {
                            "path": f"ingress/v2/{INSTALLATION_ID}/2026",
                            "mode": "040000",
                            "type": "tree",
                            "sha": "3" * 40,
                        },
                        _tree_entry(paths[1], payloads[1]),
                        _tree_entry(paths[0], payloads[0]),
                    ]
                )
            ),
            _response(_blob(payloads[0])),
            _response(_blob(payloads[1])),
        ]
    )

    result = GitHubSnapshotPoller(_client(transport)).poll(
        '"old-etag"',
        trusted_commit_id=COMMIT_ID,
        trusted_tree_id=TREE_ID,
    )

    assert result.next_etag == '"new-etag"'
    assert result.unchanged is False
    assert result.commit_id == COMMIT_ID
    assert [proposal.path for proposal in result.proposals] == paths
    assert [proposal.raw_bytes for proposal in result.proposals] == payloads
    assert all(proposal.commit_id == COMMIT_ID for proposal in result.proposals)
    assert result.proposals[0].provenance.raw_sha256 == hashlib.sha256(payloads[0]).hexdigest()
    assert transport.calls[1][1]["If-None-Match"] == '"old-etag"'
    assert f"/git/trees/{TREE_ID}?" in transport.calls[2][0]
    assert "recursive=1" in transport.calls[2][0]
    assert "page=" not in transport.calls[2][0]
    assert transport.calls[3][0].endswith(f"/git/blobs/{_blob_id(payloads[0])}")


def test_304_returns_unchanged_without_tree_or_blob_requests() -> None:
    transport = StubTransport(
        [_response(_repository()), _response(status=304, headers={"ETag": '"same"'})]
    )

    result = GitHubSnapshotPoller(_client(transport)).poll(
        '"same"',
        trusted_commit_id=COMMIT_ID,
        trusted_tree_id=TREE_ID,
    )

    assert result.unchanged is True
    assert result.next_etag == '"same"'
    assert result.commit_id is None
    assert result.proposals == ()
    assert len(transport.calls) == 2


def test_poll_rejects_changed_or_removed_known_path_before_blob_fetch() -> None:
    old_path = _path(2)
    payload = b"changed"
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head()),
            _response(_tree([_tree_entry(old_path, payload)])),
        ]
    )

    with pytest.raises(GitHubAppendOnlyViolation, match="append-only"):
        GitHubSnapshotPoller(_client(transport)).poll(
            trusted_commit_id=COMMIT_ID,
            trusted_tree_id=TREE_ID,
            known_objects={old_path: "f" * 40, _path(3): "e" * 40},
        )

    assert len(transport.calls) == 3


def test_poll_rejects_unknown_blob_path_inside_pinned_root() -> None:
    path = f"ingress/v2/{INSTALLATION_ID}/README.md"
    payload = b"not a proposal"
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head()),
            _response(_tree([_tree_entry(path, payload)])),
        ]
    )

    with pytest.raises(GitHubProposalError, match="path"):
        GitHubSnapshotPoller(_client(transport)).poll(
            trusted_commit_id=COMMIT_ID,
            trusted_tree_id=TREE_ID,
        )


def test_poll_rejects_truncated_recursive_tree_without_blob_fetch() -> None:
    truncated_tree = _tree([])
    truncated_tree["truncated"] = True
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head()),
            _response(truncated_tree),
        ]
    )

    with pytest.raises(GitHubProposalError, match="truncated"):
        GitHubSnapshotPoller(_client(transport)).poll(
            trusted_commit_id=COMMIT_ID,
            trusted_tree_id=TREE_ID,
        )
    _assert_no_blob_fetch(transport)


def test_poll_handles_fifty_new_proposals_without_loss() -> None:
    payloads = [f'{{"index":{index}}}\n'.encode() for index in range(2, 52)]
    entries = [_tree_entry(_path(index), payload) for index, payload in enumerate(payloads, 2)]
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(), headers={"ETag": '"fifty"'}),
            _response(_tree(list(reversed(entries)))),
            *[_response(_blob(payload)) for payload in payloads],
        ]
    )

    result = GitHubSnapshotPoller(_client(transport)).poll(
        trusted_commit_id=COMMIT_ID,
        trusted_tree_id=TREE_ID,
    )

    assert len(result.proposals) == 50
    assert len({proposal.path for proposal in result.proposals}) == 50
    assert [proposal.raw_bytes for proposal in result.proposals] == payloads


def test_poll_sanitizes_transport_failure() -> None:
    private_body = "private proposal body"
    transport = StubTransport(
        [
            _response(_repository()),
            GitHubResponse(status=500, body=private_body.encode()),
        ]
    )

    with pytest.raises(GitHubProposalError) as caught:
        GitHubSnapshotPoller(_client(transport)).poll(
            trusted_commit_id=COMMIT_ID,
            trusted_tree_id=TREE_ID,
        )

    assert TOKEN not in str(caught.value)
    assert private_body not in str(caught.value)


def _history_poll(transport: StubTransport) -> None:
    GitHubSnapshotPoller(_client(transport)).poll(
        trusted_commit_id="a" * 40,
        trusted_tree_id="b" * 40,
    )


def _assert_no_blob_fetch(transport: StubTransport) -> None:
    assert all("/git/blobs/" not in url for url, _headers in transport.calls)


def test_poll_accepts_one_first_parent_regular_blob_addition() -> None:
    path = _path(79)
    payload = b'{"synthetic":"proposal"}'
    head_commit, head_tree = "c" * 40, "d" * 40
    entry = _tree_entry(path, payload)
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, "a" * 40)),
            _response(_tree([], tree_id="b" * 40)),
            _response(_tree([entry], tree_id=head_tree)),
            _response(_tree([entry], tree_id=head_tree)),
            _response(_blob(payload)),
        ]
    )

    client = _client(transport)
    snapshot = GitHubSnapshotPoller(client).poll(
        trusted_commit_id="a" * 40,
        trusted_tree_id="b" * 40,
    )

    assert snapshot.commit_id == head_commit
    assert snapshot.tree_id == head_tree
    assert snapshot.proposals[0].raw_bytes == payload
    assert "/git/blobs/" in transport.calls[-1][0]


def test_first_poll_rejects_create_then_update_before_fetching_content() -> None:
    path = _path(80)
    first_payload = b"first"
    changed_payload = b"changed"
    first_commit, first_tree = "c" * 40, "d" * 40
    head_commit, head_tree = "e" * 40, "f" * 40
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, first_commit)),
            _response(_commit(first_commit, first_tree, "a" * 40)),
            _response(_tree([], tree_id="b" * 40)),
            _response(_tree([_tree_entry(path, first_payload)], tree_id=first_tree)),
            _response(_tree([_tree_entry(path, changed_payload)], tree_id=head_tree)),
        ]
    )

    with pytest.raises(GitHubProposalError, match="changed or removed"):
        _history_poll(transport)
    _assert_no_blob_fetch(transport)


def test_first_poll_rejects_delete_and_recreate_chain_before_fetching_content() -> None:
    path = _path(81)
    add_commit, add_tree = "c" * 40, "d" * 40
    delete_commit, delete_tree = "e" * 40, "f" * 40
    head_commit, head_tree = "1" * 40, "2" * 40
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, delete_commit)),
            _response(_commit(delete_commit, delete_tree, add_commit)),
            _response(_commit(add_commit, add_tree, "a" * 40)),
            _response(_tree([], tree_id="b" * 40)),
            _response(_tree([_tree_entry(path, b"first")], tree_id=add_tree)),
            _response(_tree([], tree_id=delete_tree)),
        ]
    )

    with pytest.raises(GitHubProposalError, match="changed or removed"):
        _history_poll(transport)
    _assert_no_blob_fetch(transport)


def test_poll_rejects_force_pushed_history_that_does_not_reach_durable_head() -> None:
    head_commit, head_tree = "c" * 40, "d" * 40
    unrelated_commit = "e" * 40
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, unrelated_commit)),
            _response(_commit(unrelated_commit, "f" * 40)),
        ]
    )

    with pytest.raises(GitHubProposalError, match="first-parent linear"):
        _history_poll(transport)
    _assert_no_blob_fetch(transport)


def test_poll_rejects_merge_commit_before_fetching_content() -> None:
    head_commit, head_tree = "c" * 40, "d" * 40
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, "a" * 40, "e" * 40)),
        ]
    )

    with pytest.raises(GitHubProposalError, match="first-parent linear"):
        _history_poll(transport)
    _assert_no_blob_fetch(transport)


@pytest.mark.parametrize(
    "added_entry",
    [
        {
            "path": _path(82),
            "mode": "100755",
            "type": "blob",
            "sha": "9" * 40,
            "size": 1,
        },
        {
            "path": "ingress/v2/019c0000-0000-7000-8000-000000000099/2026/08/"
            "019c0000-0000-7000-8000-000000000082.json",
            "mode": "100644",
            "type": "blob",
            "sha": "9" * 40,
            "size": 1,
        },
    ],
)
def test_poll_rejects_wrong_mode_or_extra_ingress_path_before_content_fetch(
    added_entry: dict[str, object],
) -> None:
    head_commit, head_tree = "c" * 40, "d" * 40
    transport = StubTransport(
        [
            _response(_repository()),
            _response(_head(commit_id=head_commit, tree_id=head_tree)),
            _response(_commit(head_commit, head_tree, "a" * 40)),
            _response(_tree([], tree_id="b" * 40)),
            _response(_tree([added_entry], tree_id=head_tree)),
        ]
    )

    with pytest.raises(GitHubProposalError, match="additive history"):
        _history_poll(transport)
    _assert_no_blob_fetch(transport)
