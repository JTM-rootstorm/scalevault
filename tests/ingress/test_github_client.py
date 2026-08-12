"""Contract tests for the read-only GitHub proposal fetch client."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from uuid import UUID

import pytest
from kivra_memory.ingress.github_client import (
    MAX_PROPOSAL_BYTES,
    GitHubProposalClient,
    GitHubProposalError,
    GitHubResponse,
)

REPOSITORY_ID = 123456789
INSTALLATION_ID = UUID("019c0000-0000-7000-8000-000000000001")
PROPOSAL_PATH = f"ingress/v1/{INSTALLATION_ID}/2026/08/019c0000-0000-7000-8000-000000000002.json"
TOKEN = "test-token"


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode() + content, usedforsecurity=False
    ).hexdigest()


def _response(document: object, *, status: int = 200) -> GitHubResponse:
    return GitHubResponse(status=status, body=json.dumps(document).encode())


def _repository(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "id": REPOSITORY_ID,
        "full_name": "JTM-rootstorm/scalevault-memory-ingress",
        "default_branch": "main",
    }
    document.update(overrides)
    return document


def _content(payload: bytes, **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "type": "file",
        "path": PROPOSAL_PATH,
        "sha": _blob_sha(payload),
        "encoding": "base64",
        "content": base64.b64encode(payload).decode(),
        "size": len(payload),
    }
    document.update(overrides)
    return document


@dataclass
class StubTransport:
    responses: list[GitHubResponse]
    calls: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        self.calls.append((url, headers))
        return self.responses.pop(0)


class FailingTransport:
    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        raise RuntimeError(f"transport included {headers['Authorization']} and private content")


def _client(transport: StubTransport) -> GitHubProposalClient:
    return GitHubProposalClient(
        repository_id=REPOSITORY_ID,
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        default_branch="main",
        ingress_prefix="ingress/v1",
        installation_id=INSTALLATION_ID,
        token=TOKEN,
        transport=transport,
    )


def test_fetch_returns_exact_verified_bytes() -> None:
    payload = b'{"schema_version":1}\n'
    transport = StubTransport([_response(_repository()), _response(_content(payload))])

    result = _client(transport).fetch(PROPOSAL_PATH)

    assert result == payload
    assert transport.calls[0][0] == f"https://api.github.com/repositories/{REPOSITORY_ID}"
    assert transport.calls[1][0].endswith(f"/contents/{PROPOSAL_PATH}?ref=main")
    assert all(call[1]["Authorization"] == f"Bearer {TOKEN}" for call in transport.calls)


@pytest.mark.parametrize(
    "repository",
    [
        _repository(id=987654321),
        _repository(full_name="attacker/scalevault-memory-ingress"),
        _repository(default_branch="other"),
    ],
)
def test_fetch_rejects_repository_pin_mismatch(repository: dict[str, object]) -> None:
    transport = StubTransport([_response(repository)])

    with pytest.raises(GitHubProposalError, match="did not match the pin") as caught:
        _client(transport).fetch(PROPOSAL_PATH)

    assert len(transport.calls) == 1
    assert caught.value.category == "integrity_failed"


@pytest.mark.parametrize(
    "path",
    [
        "ingress/v1/019c0000-0000-7000-8000-000000000099/2026/08/proposal.json",
        f"ingress/v1/{INSTALLATION_ID}/../proposal.json",
        f"ingress/v1/{INSTALLATION_ID}/proposal.txt",
        f"ingress/v1/{INSTALLATION_ID}/2026/13/019c0000-0000-7000-8000-000000000002.json",
        f"ingress/v1/{INSTALLATION_ID}/2026/08/not-a-uuid.json",
        f"ingress/v1/{INSTALLATION_ID}/2026/08/extra/019c0000-0000-7000-8000-000000000002.json",
    ],
)
def test_fetch_rejects_path_outside_installation_root_without_request(path: str) -> None:
    transport = StubTransport([])

    with pytest.raises(GitHubProposalError, match="path"):
        _client(transport).fetch(path)

    assert transport.calls == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"type": "dir"}, "not a file"),
        ({"path": f"{PROPOSAL_PATH}.other"}, "path did not match"),
        ({"encoding": "utf-8"}, "encoding was unsupported"),
        ({"content": "not base64!"}, "not valid base64"),
        ({"sha": "0" * 40}, "blob SHA did not match"),
        ({"size": 999}, "size did not match"),
    ],
)
def test_fetch_rejects_unverified_content(overrides: dict[str, object], message: str) -> None:
    payload = b"verified proposal"
    transport = StubTransport([_response(_repository()), _response(_content(payload, **overrides))])

    with pytest.raises(GitHubProposalError, match=message):
        _client(transport).fetch(PROPOSAL_PATH)


def test_fetch_rejects_oversized_decoded_content() -> None:
    payload = b"x" * (MAX_PROPOSAL_BYTES + 1)
    transport = StubTransport([_response(_repository()), _response(_content(payload))])

    with pytest.raises(GitHubProposalError, match="exceeded the size limit"):
        _client(transport).fetch(PROPOSAL_PATH)


def test_fetch_does_not_include_token_or_content_in_errors() -> None:
    secret_content = "private proposal statement"
    transport = StubTransport(
        [_response(_repository()), GitHubResponse(status=403, body=secret_content.encode())]
    )

    with pytest.raises(GitHubProposalError) as caught:
        _client(transport).fetch(PROPOSAL_PATH)

    assert TOKEN not in str(caught.value)
    assert secret_content not in str(caught.value)
    assert caught.value.category == "auth_failure"


@pytest.mark.parametrize(
    ("status", "headers", "category"),
    (
        (401, {}, "auth_failure"),
        (403, {}, "auth_failure"),
        (403, {"X-RateLimit-Remaining": "0"}, "rate_limited"),
        (429, {}, "rate_limited"),
    ),
)
def test_provider_auth_and_rate_failures_are_content_free_and_classified(
    status: int, headers: dict[str, str], category: str
) -> None:
    canary = "provider response body canary"
    transport = StubTransport(
        [GitHubResponse(status=status, headers=headers, body=canary.encode())]
    )

    with pytest.raises(GitHubProposalError) as caught:
        _client(transport).verify_repository()

    assert caught.value.category == category
    assert canary not in str(caught.value)


def test_fetch_sanitizes_transport_exceptions() -> None:
    client = GitHubProposalClient(
        repository_id=REPOSITORY_ID,
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        default_branch="main",
        ingress_prefix="ingress/v1",
        installation_id=INSTALLATION_ID,
        token=TOKEN,
        transport=FailingTransport(),
    )

    with pytest.raises(GitHubProposalError, match="GitHub API request failed") as caught:
        client.fetch(PROPOSAL_PATH)

    assert caught.value.__cause__ is None
    assert caught.value.category == "provider_unavailable"
    assert TOKEN not in str(caught.value)
