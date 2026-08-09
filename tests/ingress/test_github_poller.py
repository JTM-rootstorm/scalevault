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


def _head() -> dict[str, object]:
    return {"sha": COMMIT_ID, "commit": {"tree": {"sha": TREE_ID}}}


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


def _tree(entries: list[dict[str, object]]) -> dict[str, object]:
    return {"sha": TREE_ID, "truncated": False, "tree": entries}


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


def test_poll_pins_one_head_follows_tree_pages_and_fetches_immutable_blobs() -> None:
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
                    ]
                ),
                headers={"Link": '<ignored>; rel="next"'},
            ),
            _response(_tree([_tree_entry(paths[0], payloads[0])])),
            _response(_blob(payloads[0])),
            _response(_blob(payloads[1])),
        ]
    )

    result = GitHubSnapshotPoller(_client(transport)).poll('"old-etag"')

    assert result.next_etag == '"new-etag"'
    assert result.unchanged is False
    assert result.commit_id == COMMIT_ID
    assert [proposal.path for proposal in result.proposals] == paths
    assert [proposal.raw_bytes for proposal in result.proposals] == payloads
    assert all(proposal.commit_id == COMMIT_ID for proposal in result.proposals)
    assert result.proposals[0].provenance.raw_sha256 == hashlib.sha256(payloads[0]).hexdigest()
    assert transport.calls[1][1]["If-None-Match"] == '"old-etag"'
    assert f"/git/trees/{TREE_ID}?" in transport.calls[2][0]
    assert "page=1" in transport.calls[2][0]
    assert "page=2" in transport.calls[3][0]
    assert transport.calls[4][0].endswith(f"/git/blobs/{_blob_id(payloads[0])}")


def test_304_returns_unchanged_without_tree_or_blob_requests() -> None:
    transport = StubTransport(
        [_response(_repository()), _response(status=304, headers={"ETag": '"same"'})]
    )

    result = GitHubSnapshotPoller(_client(transport)).poll('"same"')

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
            known_objects={old_path: "f" * 40, _path(3): "e" * 40}
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
        GitHubSnapshotPoller(_client(transport)).poll()


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

    result = GitHubSnapshotPoller(_client(transport)).poll()

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
        GitHubSnapshotPoller(_client(transport)).poll()

    assert TOKEN not in str(caught.value)
    assert private_body not in str(caught.value)
