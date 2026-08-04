"""Read-only GitHub proposal transport client boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import UUID

MAX_PROPOSAL_BYTES = 32 * 1024
_MAX_API_RESPONSE_BYTES = 64 * 1024
_API_ROOT = "https://api.github.com"
_API_VERSION = "2022-11-28"
_BLOB_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_SAFE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
_SAFE_PATH_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/=\r\n]*")
_YEAR_PATTERN = re.compile(r"[0-9]{4}")
_MONTH_PATTERN = re.compile(r"(?:0[1-9]|1[0-2])")


class GitHubProposalError(RuntimeError):
    """Raised when GitHub cannot provide a verified proposal object."""


@dataclass(frozen=True, slots=True)
class GitHubResponse:
    """Minimal response shape returned by an injectable HTTP transport."""

    status: int
    body: bytes


class GitHubTransport(Protocol):
    """Read-only transport used by :class:`GitHubProposalClient`."""

    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        """Issue one HTTP GET without exposing mutation operations."""


class _UrllibGitHubTransport:
    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=10) as response:
                body = response.read(_MAX_API_RESPONSE_BYTES + 1)
                if len(body) > _MAX_API_RESPONSE_BYTES:
                    raise GitHubProposalError("GitHub API response exceeded the size limit")
                return GitHubResponse(status=response.status, body=body)
        except HTTPError as exc:
            return GitHubResponse(status=exc.code, body=b"")
        except (OSError, URLError):
            raise GitHubProposalError("GitHub API request failed") from None


class GitHubProposalClient:
    """Fetch verified proposal bytes from one pinned GitHub repository."""

    def __init__(
        self,
        *,
        repository_id: int,
        repository_owner: str,
        repository_name: str,
        default_branch: str,
        ingress_prefix: str,
        installation_id: UUID,
        token: str,
        transport: GitHubTransport | None = None,
    ) -> None:
        if isinstance(repository_id, bool) or repository_id <= 0:
            raise ValueError("repository_id must be a positive integer")
        self._validate_name("repository_owner", repository_owner)
        self._validate_name("repository_name", repository_name)
        if not default_branch or any(character in default_branch for character in "\r\n\x00"):
            raise ValueError("default_branch is invalid")
        if not token or any(character in token for character in "\r\n"):
            raise ValueError("token is invalid")

        normalized_prefix = ingress_prefix.strip("/")
        self._validate_path(normalized_prefix)

        self._repository_id = repository_id
        self._repository_owner = repository_owner
        self._repository_name = repository_name
        self._default_branch = default_branch
        self._ingress_root = f"{normalized_prefix}/{installation_id}"
        self._token = token
        self._transport = transport or _UrllibGitHubTransport()

    def fetch(self, path: str) -> bytes:
        """Return exact proposal bytes after repository, path, size, and SHA checks."""

        self._validate_proposal_path(path)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "scalevault-memory-ingress",
            "X-GitHub-Api-Version": _API_VERSION,
        }

        repository = self._get_json(
            f"{_API_ROOT}/repositories/{self._repository_id}", headers, "repository metadata"
        )
        self._verify_repository(repository)

        encoded_path = quote(path, safe="/")
        query = urlencode({"ref": self._default_branch})
        content_url = (
            f"{_API_ROOT}/repos/{quote(self._repository_owner, safe='')}/"
            f"{quote(self._repository_name, safe='')}/contents/{encoded_path}?{query}"
        )
        content = self._get_json(content_url, headers, "repository content")
        return self._decode_content(content, path)

    @staticmethod
    def _validate_name(field: str, value: str) -> None:
        if not value or _SAFE_NAME_PATTERN.fullmatch(value) is None:
            raise ValueError(f"{field} is invalid")

    @staticmethod
    def _validate_path(path: str) -> None:
        segments = path.split("/")
        if (
            not path
            or path.startswith("/")
            or path.endswith("/")
            or any(
                not segment
                or segment in {".", ".."}
                or _SAFE_PATH_SEGMENT_PATTERN.fullmatch(segment) is None
                for segment in segments
            )
        ):
            raise ValueError("ingress path is invalid")

    def _validate_proposal_path(self, path: str) -> None:
        try:
            self._validate_path(path)
        except ValueError:
            raise GitHubProposalError("proposal path is invalid") from None
        root_segments = self._ingress_root.split("/")
        path_segments = path.split("/")
        if (
            path_segments[: len(root_segments)] != root_segments
            or len(path_segments) != len(root_segments) + 3
        ):
            raise GitHubProposalError("proposal path is outside the pinned ingress root")
        year, month, filename = path_segments[-3:]
        if _YEAR_PATTERN.fullmatch(year) is None or _MONTH_PATTERN.fullmatch(month) is None:
            raise GitHubProposalError("proposal path date partition is invalid")
        if not filename.endswith(".json"):
            raise GitHubProposalError("proposal path filename is invalid")
        proposal_id = filename.removesuffix(".json")
        try:
            parsed_proposal_id = UUID(proposal_id)
        except ValueError:
            raise GitHubProposalError("proposal path filename is invalid") from None
        if str(parsed_proposal_id) != proposal_id:
            raise GitHubProposalError("proposal path filename is invalid")

    def _get_json(self, url: str, headers: dict[str, str], response_name: str) -> dict[str, object]:
        try:
            response = self._transport.get(url, headers)
        except GitHubProposalError:
            raise
        except Exception:
            raise GitHubProposalError("GitHub API request failed") from None
        if response.status != 200:
            raise GitHubProposalError(f"GitHub {response_name} request was not successful")
        if len(response.body) > _MAX_API_RESPONSE_BYTES:
            raise GitHubProposalError("GitHub API response exceeded the size limit")
        try:
            document = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubProposalError(f"GitHub {response_name} response was invalid") from None
        if not isinstance(document, dict):
            raise GitHubProposalError(f"GitHub {response_name} response was invalid")
        return document

    def _verify_repository(self, repository: dict[str, object]) -> None:
        repository_id = repository.get("id")
        if isinstance(repository_id, bool) or repository_id != self._repository_id:
            raise GitHubProposalError("GitHub repository identity did not match the pin")
        if repository.get("full_name") != f"{self._repository_owner}/{self._repository_name}":
            raise GitHubProposalError("GitHub repository identity did not match the pin")
        if repository.get("default_branch") != self._default_branch:
            raise GitHubProposalError("GitHub repository branch did not match the pin")

    @staticmethod
    def _decode_content(content: dict[str, object], expected_path: str) -> bytes:
        if content.get("type") != "file":
            raise GitHubProposalError("GitHub content response was not a file")
        if content.get("path") != expected_path:
            raise GitHubProposalError("GitHub content path did not match the request")

        blob_sha = content.get("sha")
        if not isinstance(blob_sha, str) or _BLOB_SHA_PATTERN.fullmatch(blob_sha) is None:
            raise GitHubProposalError("GitHub content blob SHA was invalid")
        if content.get("encoding") != "base64":
            raise GitHubProposalError("GitHub content encoding was unsupported")
        encoded = content.get("content")
        if not isinstance(encoded, str) or _BASE64_PATTERN.fullmatch(encoded) is None:
            raise GitHubProposalError("GitHub content was not valid base64")

        compact_encoded = encoded.replace("\r", "").replace("\n", "")
        try:
            decoded = base64.b64decode(compact_encoded, validate=True)
        except (binascii.Error, ValueError):
            raise GitHubProposalError("GitHub content was not valid base64") from None
        if len(decoded) > MAX_PROPOSAL_BYTES:
            raise GitHubProposalError("GitHub proposal exceeded the size limit")

        declared_size = content.get("size")
        if isinstance(declared_size, bool) or declared_size != len(decoded):
            raise GitHubProposalError("GitHub content size did not match the decoded object")
        expected_sha = hashlib.sha1(
            f"blob {len(decoded)}\0".encode() + decoded, usedforsecurity=False
        ).hexdigest()
        if blob_sha != expected_sha:
            raise GitHubProposalError("GitHub content blob SHA did not match the decoded object")
        return decoded
