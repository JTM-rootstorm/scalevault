"""Contract tests for duplicate-safe GitHub proposal fallback preparation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from kivra_memory.ingress.github_fallback import (
    DuplicateSafeGitHubProposalFallback,
    GitHubCreateFileRequest,
    GitHubCreateFileResponse,
    GitHubExistingFile,
    GitHubFallbackError,
    GitHubProposalFallbackConfig,
    prepare_github_create_request,
)
from kivra_memory.ingress.status import IngressStatusPayload, IngressStatusResult
from kivra_memory.storage.github_heads import GITHUB_INGRESS_BOOTSTRAP_COMMIT

_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE = (
    _ROOT
    / "tests"
    / "contract"
    / "fixtures"
    / "json_schemas"
    / "chatgpt-memory-proposal-v2.schema.json"
)
_INSTALLATION_ID = UUID("019c0000-0000-7000-8000-000000000022")
_PROPOSAL_ID = UUID("019c0000-0000-7000-8000-000000000021")
_PATH = f"ingress/v2/{_INSTALLATION_ID}/2026/08/{_PROPOSAL_ID}.json"


def _proposal() -> bytes:
    return _FIXTURE.read_bytes()


def _config() -> GitHubProposalFallbackConfig:
    return GitHubProposalFallbackConfig(installation_id=_INSTALLATION_ID)


def _status(ingress_id: UUID = _PROPOSAL_ID) -> IngressStatusResult:
    return IngressStatusResult(
        result=IngressStatusPayload(
            ingress_id=ingress_id,
            state="discovered",
            result_event_id=None,
            result_memory_id=None,
            error_code=None,
            discovered_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
            validated_at=None,
            processed_at=None,
        )
    )


@dataclass
class StubWriter:
    response: GitHubCreateFileResponse
    existing: GitHubExistingFile | None = None
    create_calls: list[GitHubCreateFileRequest] = field(default_factory=list)
    read_calls: list[str] = field(default_factory=list)

    async def create_file(self, request: GitHubCreateFileRequest) -> GitHubCreateFileResponse:
        self.create_calls.append(request)
        return self.response

    async def read_file(
        self,
        *,
        repository_owner: str,
        repository_name: str,
        branch: str,
        immutable_path: str,
    ) -> GitHubExistingFile:
        assert repository_owner == "JTM-rootstorm"
        assert repository_name == "scalevault-memory-ingress"
        assert branch == "main"
        self.read_calls.append(immutable_path)
        assert self.existing is not None
        return self.existing


@dataclass
class StubStatusReader:
    result: IngressStatusResult
    calls: list[UUID] = field(default_factory=list)

    async def status(self, ingress_id: UUID) -> IngressStatusResult:
        self.calls.append(ingress_id)
        return self.result


class FailingWriter:
    async def create_file(self, request: GitHubCreateFileRequest) -> GitHubCreateFileResponse:
        raise RuntimeError(f"timeout after sending {request.raw_bytes.decode()}")

    async def read_file(
        self,
        *,
        repository_owner: str,
        repository_name: str,
        branch: str,
        immutable_path: str,
    ) -> GitHubExistingFile:
        raise AssertionError("ambiguous create must return before a read")


def test_prepare_request_uses_uuid_path_and_create_only_body() -> None:
    request = prepare_github_create_request(_config(), _proposal())

    assert request.ingress_id == _PROPOSAL_ID
    assert request.immutable_path == _PATH
    assert request.repository_owner == "JTM-rootstorm"
    assert request.repository_name == "scalevault-memory-ingress"
    assert request.branch == "main"
    assert set(request.github_body()) == {"message", "content", "branch"}
    assert "sha" not in request.github_body()
    assert "statement" not in repr(request)


async def test_create_and_status_keep_one_ingress_identity() -> None:
    writer = StubWriter(
        GitHubCreateFileResponse(status_code=201, commit_id="1" * 40, blob_id="2" * 40)
    )
    status_reader = StubStatusReader(_status())
    fallback = DuplicateSafeGitHubProposalFallback(_config(), writer, status_reader)

    reference = await fallback.create_unique(_proposal())
    result = await fallback.status(reference.ingress_id)

    assert reference.ingress_id == _PROPOSAL_ID
    assert reference.immutable_path == _PATH
    assert reference.created is True
    assert result.result.ingress_id == reference.ingress_id
    assert len(writer.create_calls) == 1
    assert writer.read_calls == []
    assert status_reader.calls == [_PROPOSAL_ID]


@pytest.mark.parametrize("status_code", [409, 422])
async def test_duplicate_create_reads_and_verifies_same_object_without_second_write(
    status_code: int,
) -> None:
    writer = StubWriter(
        GitHubCreateFileResponse(status_code=status_code),
        existing=GitHubExistingFile(
            immutable_path=_PATH,
            commit_id="3" * 40,
            blob_id="4" * 40,
            raw_bytes=_proposal(),
        ),
    )
    fallback = DuplicateSafeGitHubProposalFallback(_config(), writer, StubStatusReader(_status()))

    first_retry = await fallback.create_unique(_proposal())

    assert first_retry.ingress_id == _PROPOSAL_ID
    assert first_retry.created is False
    assert len(writer.create_calls) == 1
    assert writer.read_calls == [_PATH]


async def test_timeout_is_retry_safe_and_does_not_disclose_or_mint_identity() -> None:
    fallback = DuplicateSafeGitHubProposalFallback(
        _config(),
        FailingWriter(),
        StubStatusReader(_status()),
    )

    with pytest.raises(GitHubFallbackError, match="github_create_ambiguous") as caught:
        await fallback.create_unique(_proposal())

    assert caught.value.__cause__ is None
    assert "Synthetic project decision" not in str(caught.value)
    assert "Synthetic project decision" not in repr(caught.value)
    retried = prepare_github_create_request(_config(), _proposal())
    assert retried.ingress_id == _PROPOSAL_ID
    assert retried.immutable_path == _PATH
    assert retried.raw_bytes == _proposal()


async def test_duplicate_path_with_different_bytes_fails_closed() -> None:
    writer = StubWriter(
        GitHubCreateFileResponse(status_code=422),
        existing=GitHubExistingFile(
            immutable_path=_PATH,
            commit_id="3" * 40,
            blob_id="4" * 40,
            raw_bytes=b"different private content",
        ),
    )
    fallback = DuplicateSafeGitHubProposalFallback(_config(), writer, StubStatusReader(_status()))

    with pytest.raises(GitHubFallbackError, match="github_path_collision"):
        await fallback.create_unique(_proposal())
    assert len(writer.create_calls) == 1


def test_config_rejects_wrong_external_source_or_repository() -> None:
    with pytest.raises(ValueError, match="configuration is invalid"):
        replace(_config(), external_source_commit="0" * 40)
    with pytest.raises(ValueError, match="configuration is invalid"):
        replace(_config(), repository_name="canonical-archive")
    assert _config().external_source_commit == GITHUB_INGRESS_BOOTSTRAP_COMMIT


def test_sensitive_or_wrong_installation_proposal_fails_before_creation() -> None:
    sensitive = json.loads(_proposal())
    sensitive["sensitivity"] = 1
    with pytest.raises(GitHubFallbackError, match="proposal_invalid"):
        prepare_github_create_request(_config(), json.dumps(sensitive).encode())

    wrong_installation = json.loads(_proposal())
    wrong_installation["installation_id"] = "019c0000-0000-7000-8000-000000000099"
    with pytest.raises(GitHubFallbackError, match="proposal_installation_mismatch"):
        prepare_github_create_request(_config(), json.dumps(wrong_installation).encode())


async def test_status_reader_cannot_substitute_another_ingress_id() -> None:
    other = UUID("019c0000-0000-7000-8000-000000000099")
    fallback = DuplicateSafeGitHubProposalFallback(
        _config(),
        StubWriter(GitHubCreateFileResponse(status_code=500)),
        StubStatusReader(_status(other)),
    )

    with pytest.raises(GitHubFallbackError, match="ingress_status_identity_mismatch"):
        await fallback.status(_PROPOSAL_ID)
