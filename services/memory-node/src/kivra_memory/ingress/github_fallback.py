"""Create-only GitHub proposal fallback contract without provider credentials.

The concrete ChatGPT/GitHub connector remains outside the Memory Node. This
module prepares and verifies the bounded request/response exchange so an
adapter cannot silently update a path, mint a replacement UUID after an
ambiguous duplicate, or correlate status to a different ingress identifier.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal, Protocol, cast
from uuid import UUID

from kivra_memory.domain.canonical_json import JsonValue, parse_json_strict
from kivra_memory.domain.errors import CanonicalJsonError
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import normalize_utc_datetime
from kivra_memory.ingress.github_client import MAX_PROPOSAL_BYTES
from kivra_memory.ingress.status import IngressStatusResult
from kivra_memory.ingress.validator import IngressValidationError, validate_ingress
from kivra_memory.storage.github_heads import (
    GITHUB_INGRESS_BOOTSTRAP_COMMIT,
    GITHUB_INGRESS_BOOTSTRAP_TREE,
)

GITHUB_FALLBACK_REPOSITORY_OWNER = "JTM-rootstorm"
GITHUB_FALLBACK_REPOSITORY_NAME = "scalevault-memory-ingress"
GITHUB_FALLBACK_BRANCH = "main"
GITHUB_FALLBACK_PREFIX = "ingress/v2"
GITHUB_FALLBACK_PRIVACY_WARNING: Final[Literal["github_third_party_non_sensitive_only"]] = (
    "github_third_party_non_sensitive_only"
)
_OBJECT_ID = re.compile(r"[0-9a-f]{40}")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class GitHubFallbackError(RuntimeError):
    """Payload-free proposal fallback failure."""

    def __init__(self, code: str) -> None:
        if _SAFE_CODE.fullmatch(code) is None:
            raise ValueError("fallback error code is invalid")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class GitHubProposalFallbackConfig:
    """Non-secret, fail-closed connector profile for the one private repository."""

    installation_id: UUID
    repository_owner: str = GITHUB_FALLBACK_REPOSITORY_OWNER
    repository_name: str = GITHUB_FALLBACK_REPOSITORY_NAME
    default_branch: str = GITHUB_FALLBACK_BRANCH
    ingress_prefix: str = GITHUB_FALLBACK_PREFIX
    schema_version: Literal[2] = 2
    privacy_warning: Literal["github_third_party_non_sensitive_only"] = (
        GITHUB_FALLBACK_PRIVACY_WARNING
    )
    maximum_proposal_bytes: int = MAX_PROPOSAL_BYTES
    external_source_commit: str = GITHUB_INGRESS_BOOTSTRAP_COMMIT
    external_source_tree: str = GITHUB_INGRESS_BOOTSTRAP_TREE

    def __post_init__(self) -> None:
        require_uuid7(self.installation_id, field_name="installation_id")
        if (
            self.repository_owner != GITHUB_FALLBACK_REPOSITORY_OWNER
            or self.repository_name != GITHUB_FALLBACK_REPOSITORY_NAME
            or self.default_branch != GITHUB_FALLBACK_BRANCH
            or self.ingress_prefix != GITHUB_FALLBACK_PREFIX
            or self.schema_version != 2
            or self.privacy_warning != GITHUB_FALLBACK_PRIVACY_WARNING
            or not 1 <= self.maximum_proposal_bytes <= MAX_PROPOSAL_BYTES
            or self.external_source_commit != GITHUB_INGRESS_BOOTSTRAP_COMMIT
            or self.external_source_tree != GITHUB_INGRESS_BOOTSTRAP_TREE
        ):
            raise ValueError("GitHub proposal fallback configuration is invalid")


@dataclass(frozen=True, slots=True)
class GitHubCreateFileRequest:
    """One provider create-file call; its wire body deliberately has no ``sha``."""

    repository_owner: str
    repository_name: str
    branch: str
    ingress_id: UUID
    immutable_path: str
    raw_bytes: bytes = field(repr=False)

    def github_body(self) -> dict[str, str]:
        return {
            "message": f"Queue ScaleVault proposal {self.ingress_id}",
            "content": base64.b64encode(self.raw_bytes).decode("ascii"),
            "branch": self.branch,
        }


@dataclass(frozen=True, slots=True)
class GitHubCreateFileResponse:
    status_code: int
    commit_id: str | None = None
    blob_id: str | None = None


@dataclass(frozen=True, slots=True)
class GitHubExistingFile:
    immutable_path: str
    commit_id: str
    blob_id: str
    raw_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class GitHubProposalReference:
    ingress_id: UUID
    immutable_path: str
    commit_id: str
    blob_id: str
    created: bool


class GitHubCreateOnlyWriter(Protocol):
    async def create_file(
        self,
        request: GitHubCreateFileRequest,
        /,
    ) -> GitHubCreateFileResponse: ...

    async def read_file(
        self,
        *,
        repository_owner: str,
        repository_name: str,
        branch: str,
        immutable_path: str,
    ) -> GitHubExistingFile: ...


class GitHubIngressStatusReader(Protocol):
    async def status(self, ingress_id: UUID, /) -> IngressStatusResult: ...


class GitHubProposalFallback(Protocol):
    async def create_unique(self, proposal: bytes, /) -> GitHubProposalReference: ...

    async def status(self, ingress_id: UUID, /) -> IngressStatusResult: ...


class DuplicateSafeGitHubProposalFallback:
    """Coordinate create-only submission, exact duplicate recovery, and status."""

    def __init__(
        self,
        config: GitHubProposalFallbackConfig,
        writer: GitHubCreateOnlyWriter,
        status_reader: GitHubIngressStatusReader,
    ) -> None:
        self._config = config
        self._writer = writer
        self._status_reader = status_reader

    async def create_unique(self, proposal: bytes, /) -> GitHubProposalReference:
        request = prepare_github_create_request(self._config, proposal)
        try:
            response = await self._writer.create_file(request)
        except Exception:
            raise GitHubFallbackError("github_create_ambiguous") from None
        if response.status_code == 201:
            commit_id = _object_id(response.commit_id)
            blob_id = _object_id(response.blob_id)
            return GitHubProposalReference(
                ingress_id=request.ingress_id,
                immutable_path=request.immutable_path,
                commit_id=commit_id,
                blob_id=blob_id,
                created=True,
            )
        if response.status_code not in {409, 422}:
            raise GitHubFallbackError("github_create_failed")

        try:
            existing = await self._writer.read_file(
                repository_owner=request.repository_owner,
                repository_name=request.repository_name,
                branch=request.branch,
                immutable_path=request.immutable_path,
            )
        except Exception:
            raise GitHubFallbackError("github_duplicate_read_failed") from None
        if existing.immutable_path != request.immutable_path or not hmac.compare_digest(
            hashlib.sha256(existing.raw_bytes).digest(),
            hashlib.sha256(request.raw_bytes).digest(),
        ):
            raise GitHubFallbackError("github_path_collision")
        return GitHubProposalReference(
            ingress_id=request.ingress_id,
            immutable_path=request.immutable_path,
            commit_id=_object_id(existing.commit_id),
            blob_id=_object_id(existing.blob_id),
            created=False,
        )

    async def status(self, ingress_id: UUID, /) -> IngressStatusResult:
        require_uuid7(ingress_id, field_name="ingress_id")
        try:
            result = await self._status_reader.status(ingress_id)
        except Exception:
            raise GitHubFallbackError("ingress_status_unavailable") from None
        if result.result.ingress_id != ingress_id:
            raise GitHubFallbackError("ingress_status_identity_mismatch")
        return result


def prepare_github_create_request(
    config: GitHubProposalFallbackConfig,
    proposal: bytes,
) -> GitHubCreateFileRequest:
    """Validate exact v2 bytes and derive their one deterministic create-only path."""

    if not isinstance(proposal, bytes):
        raise TypeError("proposal must be bytes")
    if not 1 <= len(proposal) <= config.maximum_proposal_bytes:
        raise GitHubFallbackError("proposal_size_invalid")
    try:
        parsed = parse_json_strict(proposal)
        document = cast(dict[str, JsonValue], parsed)
        if not isinstance(parsed, dict) or parsed.get("schema_version") != 2:
            raise ValueError
        proposal_id = UUID(cast(str, document["proposal_id"]))
        installation_id = UUID(cast(str, document["installation_id"]))
        created_at_value = cast(str, document["created_at"])
        created_at = normalize_utc_datetime(
            datetime.fromisoformat(created_at_value.replace("Z", "+00:00"))
        )
        require_uuid7(proposal_id, field_name="proposal_id")
        require_uuid7(installation_id, field_name="installation_id")
    except (CanonicalJsonError, KeyError, TypeError, ValueError):
        raise GitHubFallbackError("proposal_invalid") from None
    if installation_id != config.installation_id:
        raise GitHubFallbackError("proposal_installation_mismatch")
    path = (
        f"{config.ingress_prefix}/{installation_id}/{created_at:%Y}/{created_at:%m}/"
        f"{proposal_id}.json"
    )
    try:
        validate_ingress(proposal, path)
    except IngressValidationError:
        raise GitHubFallbackError("proposal_invalid") from None
    return GitHubCreateFileRequest(
        repository_owner=config.repository_owner,
        repository_name=config.repository_name,
        branch=config.default_branch,
        ingress_id=proposal_id,
        immutable_path=path,
        raw_bytes=proposal,
    )


def _object_id(value: str | None) -> str:
    if value is None or _OBJECT_ID.fullmatch(value) is None:
        raise GitHubFallbackError("github_create_response_invalid")
    return value


__all__ = [
    "GITHUB_FALLBACK_BRANCH",
    "GITHUB_FALLBACK_PREFIX",
    "GITHUB_FALLBACK_PRIVACY_WARNING",
    "GITHUB_FALLBACK_REPOSITORY_NAME",
    "GITHUB_FALLBACK_REPOSITORY_OWNER",
    "DuplicateSafeGitHubProposalFallback",
    "GitHubCreateFileRequest",
    "GitHubCreateFileResponse",
    "GitHubCreateOnlyWriter",
    "GitHubExistingFile",
    "GitHubFallbackError",
    "GitHubIngressStatusReader",
    "GitHubProposalFallback",
    "GitHubProposalFallbackConfig",
    "GitHubProposalReference",
    "prepare_github_create_request",
]
