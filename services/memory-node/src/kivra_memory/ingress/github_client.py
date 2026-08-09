"""Read-only GitHub proposal transport client boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import UUID

MAX_PROPOSAL_BYTES = 32 * 1024
MAX_REPOSITORY_TREE_ENTRIES = 10_000
_MAX_API_RESPONSE_BYTES = 64 * 1024
_MAX_TREE_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_VERIFIED_COMMITS = 100
_MAX_HISTORY_TREE_ENTRIES = 100_000
_MAX_TRANSPORT_RESPONSE_BYTES = _MAX_TREE_RESPONSE_BYTES
_API_ROOT = "https://api.github.com"
_API_VERSION = "2022-11-28"
_OBJECT_ID_PATTERN = re.compile(r"[0-9a-f]{40}")
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
    headers: Mapping[str, str] = field(default_factory=dict)


class GitHubTransport(Protocol):
    """Read-only transport used by :class:`GitHubProposalClient`."""

    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        """Issue one HTTP GET without exposing mutation operations."""


class _UrllibGitHubTransport:
    def get(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=10) as response:
                body = response.read(_MAX_TRANSPORT_RESPONSE_BYTES + 1)
                if len(body) > _MAX_TRANSPORT_RESPONSE_BYTES:
                    raise GitHubProposalError("GitHub API response exceeded the size limit")
                return GitHubResponse(
                    status=response.status,
                    body=body,
                    headers=dict(response.headers.items()),
                )
        except HTTPError as exc:
            response_headers = dict(exc.headers.items()) if exc.headers is not None else {}
            return GitHubResponse(status=exc.code, body=b"", headers=response_headers)
        except (OSError, URLError):
            raise GitHubProposalError("GitHub API request failed") from None


@dataclass(frozen=True, slots=True)
class GitHubHead:
    """One exact branch head and its root tree, or an unchanged ETag result."""

    commit_id: str | None
    tree_id: str | None
    next_etag: str | None
    unchanged: bool

    def __post_init__(self) -> None:
        if self.unchanged:
            if self.commit_id is not None or self.tree_id is not None:
                raise ValueError("an unchanged head cannot contain object IDs")
        elif self.commit_id is None or self.tree_id is None:
            raise ValueError("a changed head requires commit and tree object IDs")


@dataclass(frozen=True, slots=True)
class GitHubCommit:
    """One exact Git commit object used only for history verification."""

    commit_id: str
    tree_id: str
    parent_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GitHubRepositoryEntry:
    """One non-directory Git tree entry used for additive-chain verification."""

    path: str
    mode: str
    object_type: str
    object_id: str


@dataclass(frozen=True, slots=True)
class GitHubTreeEntry:
    """One regular blob reachable from an exact Git tree."""

    path: str
    blob_id: str
    size: int | None


@dataclass(frozen=True, slots=True)
class GitHubBlobProvenance:
    """Immutable provider identity for one fetched proposal object."""

    repository_id: int
    commit_id: str
    path: str
    blob_id: str
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class GitHubProposalObject:
    """Exact proposal bytes and immutable GitHub provenance."""

    repository_id: int
    commit_id: str
    path: str
    blob_id: str
    raw_sha256: str
    raw_bytes: bytes

    @property
    def provenance(self) -> GitHubBlobProvenance:
        """Return a content-free immutable provenance view."""

        return GitHubBlobProvenance(
            repository_id=self.repository_id,
            commit_id=self.commit_id,
            path=self.path,
            blob_id=self.blob_id,
            raw_sha256=self.raw_sha256,
        )


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
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
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
        self._repository_api_root = (
            f"{_API_ROOT}/repos/{quote(repository_owner, safe='')}/"
            f"{quote(repository_name, safe='')}"
        )
        self._default_branch = default_branch
        self._ingress_root = f"{normalized_prefix}/{installation_id}"
        self._require_uuid7_paths = normalized_prefix.endswith("/v2")
        self._token = token
        self._transport = transport or _UrllibGitHubTransport()

    @property
    def repository_id(self) -> int:
        """Return the pinned numeric repository identity."""

        return self._repository_id

    def fetch(self, path: str) -> bytes:
        """Return exact proposal bytes using the legacy branch content API.

        Live polling uses :meth:`resolve_head`, :meth:`enumerate_tree`, and
        :meth:`fetch_blob` so a listing and its bytes cannot cross commits.
        """

        self._validate_proposal_path(path)
        headers = self._request_headers()
        self.verify_repository(headers=headers)

        encoded_path = quote(path, safe="/")
        query = urlencode({"ref": self._default_branch})
        content_url = f"{self._repository_api_root}/contents/{encoded_path}?{query}"
        content, _ = self._get_json(content_url, headers, "repository content")
        return self._decode_content(content, expected_path=path)

    def verify_repository(self, *, headers: dict[str, str] | None = None) -> None:
        """Verify numeric, owner/name, and default-branch repository pins."""

        request_headers = headers or self._request_headers()
        repository, _ = self._get_json(
            f"{_API_ROOT}/repositories/{self._repository_id}",
            request_headers,
            "repository metadata",
        )
        self._verify_repository(repository)

    def resolve_head(self, etag: str | None = None) -> GitHubHead:
        """Resolve exactly one branch head, conditionally when ``etag`` is present."""

        self._validate_etag(etag)
        headers = self._request_headers()
        self.verify_repository(headers=headers)
        if etag is not None:
            headers["If-None-Match"] = etag
        encoded_branch = quote(self._default_branch, safe="")
        url = f"{self._repository_api_root}/commits/{encoded_branch}"
        response = self._request(url, headers)
        next_etag = self._response_header(response.headers, "ETag")
        self._validate_etag(next_etag)

        if response.status == 304:
            if etag is None:
                raise GitHubProposalError("GitHub returned an invalid conditional response")
            return GitHubHead(
                commit_id=None,
                tree_id=None,
                next_etag=next_etag or etag,
                unchanged=True,
            )
        if response.status != 200:
            raise GitHubProposalError("GitHub branch head request was not successful")
        document = self._decode_json_object(response, "branch head")
        commit_id = self._object_id(document.get("sha"), "head commit")
        commit = document.get("commit")
        if not isinstance(commit, dict):
            raise GitHubProposalError("GitHub branch head response was invalid")
        tree = commit.get("tree")
        if not isinstance(tree, dict):
            raise GitHubProposalError("GitHub branch head response was invalid")
        tree_id = self._object_id(tree.get("sha"), "head tree")
        return GitHubHead(
            commit_id=commit_id,
            tree_id=tree_id,
            next_etag=next_etag,
            unchanged=False,
        )

    def enumerate_tree(self, tree_id: str) -> tuple[GitHubTreeEntry, ...]:
        """Enumerate regular proposal blobs from one exact recursive tree response."""

        self._require_object_id(tree_id, "tree")
        headers = self._request_headers()
        entries: list[GitHubTreeEntry] = []
        seen_paths: set[str] = set()
        query = urlencode({"recursive": "1"})
        url = f"{self._repository_api_root}/git/trees/{tree_id}?{query}"
        response = self._request(url, headers)
        if response.status != 200:
            raise GitHubProposalError("GitHub repository tree request was not successful")
        document = self._decode_json_object(
            response,
            "repository tree",
            max_bytes=_MAX_TREE_RESPONSE_BYTES,
        )
        if document.get("sha") != tree_id:
            raise GitHubProposalError("GitHub repository tree identity did not match the pin")
        if document.get("truncated") is True:
            raise GitHubProposalError("GitHub repository tree response was truncated")
        raw_entries = document.get("tree")
        if not isinstance(raw_entries, list):
            raise GitHubProposalError("GitHub repository tree response was invalid")
        self._collect_tree_entries(raw_entries, entries, seen_paths)
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def verify_additive_history(
        self,
        *,
        trusted_commit_id: str,
        trusted_tree_id: str,
        head_commit_id: str,
        head_tree_id: str,
    ) -> None:
        """Verify a linear, additive-only chain before any proposal blob fetch.

        The trusted commit/tree pair comes from the durable provider checkpoint.
        Every later commit must have exactly one parent and may only add regular,
        non-executable blobs at valid paths inside this installation's ingress
        root. Existing paths and all objects outside that root are immutable.
        """

        for value, name in (
            (trusted_commit_id, "trusted commit"),
            (trusted_tree_id, "trusted tree"),
            (head_commit_id, "head commit"),
            (head_tree_id, "head tree"),
        ):
            self._require_object_id(value, name)
        if head_commit_id == trusted_commit_id:
            if head_tree_id != trusted_tree_id:
                raise GitHubProposalError("GitHub trusted head tree did not match the pin")
            return

        reverse_chain: list[GitHubCommit] = []
        current_id = head_commit_id
        while current_id != trusted_commit_id:
            if len(reverse_chain) >= _MAX_VERIFIED_COMMITS:
                raise GitHubProposalError("GitHub additive history exceeded the verification limit")
            commit = self.get_commit(current_id)
            if len(commit.parent_ids) != 1:
                raise GitHubProposalError("GitHub additive history was not first-parent linear")
            reverse_chain.append(commit)
            current_id = commit.parent_ids[0]
        if reverse_chain[0].tree_id != head_tree_id:
            raise GitHubProposalError("GitHub head tree did not match the commit object")

        previous = self.enumerate_repository_tree(trusted_tree_id)
        cumulative_entries = len(previous)
        for commit in reversed(reverse_chain):
            current = self.enumerate_repository_tree(commit.tree_id)
            cumulative_entries += len(current)
            if cumulative_entries > _MAX_HISTORY_TREE_ENTRIES:
                raise GitHubProposalError(
                    "GitHub additive history exceeded the cumulative tree entry limit"
                )
            self._verify_additive_tree_delta(previous, current)
            previous = current

    def get_commit(self, commit_id: str) -> GitHubCommit:
        """Fetch one immutable Git commit object by object ID."""

        self._require_object_id(commit_id, "commit")
        document, _ = self._get_json(
            f"{self._repository_api_root}/git/commits/{commit_id}",
            self._request_headers(),
            "repository commit",
        )
        if document.get("sha") != commit_id:
            raise GitHubProposalError("GitHub repository commit identity did not match the pin")
        tree = document.get("tree")
        if not isinstance(tree, dict):
            raise GitHubProposalError("GitHub repository commit response was invalid")
        tree_id = self._object_id(tree.get("sha"), "commit tree")
        raw_parents = document.get("parents")
        if not isinstance(raw_parents, list):
            raise GitHubProposalError("GitHub repository commit response was invalid")
        parent_ids: list[str] = []
        for parent in raw_parents:
            if not isinstance(parent, dict):
                raise GitHubProposalError("GitHub repository commit response was invalid")
            parent_ids.append(self._object_id(parent.get("sha"), "parent commit"))
        return GitHubCommit(commit_id=commit_id, tree_id=tree_id, parent_ids=tuple(parent_ids))

    def enumerate_repository_tree(self, tree_id: str) -> tuple[GitHubRepositoryEntry, ...]:
        """Enumerate all non-directory objects in one exact repository tree."""

        self._require_object_id(tree_id, "tree")
        headers = self._request_headers()
        entries: list[GitHubRepositoryEntry] = []
        seen_paths: set[str] = set()
        query = urlencode({"recursive": "1"})
        url = f"{self._repository_api_root}/git/trees/{tree_id}?{query}"
        response = self._request(url, headers)
        if response.status != 200:
            raise GitHubProposalError("GitHub repository tree request was not successful")
        document = self._decode_json_object(
            response,
            "repository tree",
            max_bytes=_MAX_TREE_RESPONSE_BYTES,
        )
        if document.get("sha") != tree_id:
            raise GitHubProposalError("GitHub repository tree identity did not match the pin")
        if document.get("truncated") is True:
            raise GitHubProposalError("GitHub repository tree response was truncated")
        raw_entries = document.get("tree")
        if not isinstance(raw_entries, list):
            raise GitHubProposalError("GitHub repository tree response was invalid")
        self._collect_repository_entries(raw_entries, entries, seen_paths)
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def fetch_blob(self, *, commit_id: str, path: str, blob_id: str) -> GitHubProposalObject:
        """Fetch and verify one blob by immutable object ID."""

        self._require_object_id(commit_id, "commit")
        self._require_object_id(blob_id, "blob")
        self._validate_proposal_path(path)
        url = f"{self._repository_api_root}/git/blobs/{blob_id}"
        document, _ = self._get_json(url, self._request_headers(), "repository blob")
        if document.get("sha") != blob_id:
            raise GitHubProposalError("GitHub blob identity did not match the request")
        raw = self._decode_content(document, expected_path=None, expected_blob_id=blob_id)
        return GitHubProposalObject(
            repository_id=self._repository_id,
            commit_id=commit_id,
            path=path,
            blob_id=blob_id,
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=raw,
        )

    def validate_proposal_path(self, path: str) -> None:
        """Validate one normalized create-only proposal path."""

        self._validate_proposal_path(path)

    def is_within_ingress_root(self, path: str) -> bool:
        """Return whether ``path`` is inside the pinned installation root."""

        return path.startswith(f"{self._ingress_root}/")

    def _request_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "scalevault-memory-ingress",
            "X-GitHub-Api-Version": _API_VERSION,
        }

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
        if str(parsed_proposal_id) != proposal_id or (
            self._require_uuid7_paths and parsed_proposal_id.version != 7
        ):
            raise GitHubProposalError("proposal path filename is invalid")

    def _get_json(
        self,
        url: str,
        headers: dict[str, str],
        response_name: str,
    ) -> tuple[dict[str, object], GitHubResponse]:
        response = self._request(url, headers)
        if response.status != 200:
            raise GitHubProposalError(f"GitHub {response_name} request was not successful")
        return self._decode_json_object(response, response_name), response

    def _request(self, url: str, headers: dict[str, str]) -> GitHubResponse:
        try:
            response = self._transport.get(url, headers)
        except Exception:
            raise GitHubProposalError("GitHub API request failed") from None
        if isinstance(response.status, bool) or not isinstance(response.status, int):
            raise GitHubProposalError("GitHub API response was invalid")
        if not isinstance(response.body, bytes) or not isinstance(response.headers, Mapping):
            raise GitHubProposalError("GitHub API response was invalid")
        return response

    @staticmethod
    def _decode_json_object(
        response: GitHubResponse,
        response_name: str,
        *,
        max_bytes: int = _MAX_API_RESPONSE_BYTES,
    ) -> dict[str, object]:
        if len(response.body) > max_bytes:
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

    def _collect_tree_entries(
        self,
        raw_entries: list[object],
        entries: list[GitHubTreeEntry],
        seen_paths: set[str],
    ) -> None:
        if len(raw_entries) > MAX_REPOSITORY_TREE_ENTRIES:
            raise GitHubProposalError("GitHub repository tree exceeded the entry limit")
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                raise GitHubProposalError("GitHub repository tree response was invalid")
            path = raw_entry.get("path")
            if not isinstance(path, str):
                raise GitHubProposalError("GitHub repository tree response was invalid")
            if not self.is_within_ingress_root(path):
                continue
            if raw_entry.get("type") == "tree" and raw_entry.get("mode") == "040000":
                continue
            if raw_entry.get("type") != "blob" or raw_entry.get("mode") != "100644":
                raise GitHubProposalError("GitHub ingress tree entry was not a regular blob")
            self._validate_proposal_path(path)
            if path in seen_paths:
                raise GitHubProposalError("GitHub repository tree contained a duplicate path")
            seen_paths.add(path)
            blob_id = self._object_id(raw_entry.get("sha"), "tree blob")
            size = raw_entry.get("size")
            if size is not None and (
                isinstance(size, bool) or not isinstance(size, int) or size < 0
            ):
                raise GitHubProposalError("GitHub repository tree response was invalid")
            if size is not None and size > MAX_PROPOSAL_BYTES:
                raise GitHubProposalError("GitHub proposal exceeded the size limit")
            entries.append(GitHubTreeEntry(path=path, blob_id=blob_id, size=size))

    def _collect_repository_entries(
        self,
        raw_entries: list[object],
        entries: list[GitHubRepositoryEntry],
        seen_paths: set[str],
    ) -> None:
        if len(raw_entries) > MAX_REPOSITORY_TREE_ENTRIES:
            raise GitHubProposalError("GitHub repository tree exceeded the entry limit")
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                raise GitHubProposalError("GitHub repository tree response was invalid")
            path = raw_entry.get("path")
            mode = raw_entry.get("mode")
            object_type = raw_entry.get("type")
            if (
                not isinstance(path, str)
                or not path
                or path.startswith("/")
                or path.endswith("/")
                or "\x00" in path
                or not isinstance(mode, str)
                or not isinstance(object_type, str)
            ):
                raise GitHubProposalError("GitHub repository tree response was invalid")
            if object_type == "tree" and mode == "040000":
                continue
            if path in seen_paths:
                raise GitHubProposalError("GitHub repository tree contained a duplicate path")
            seen_paths.add(path)
            entries.append(
                GitHubRepositoryEntry(
                    path=path,
                    mode=mode,
                    object_type=object_type,
                    object_id=self._object_id(raw_entry.get("sha"), "tree object"),
                )
            )

    def _verify_additive_tree_delta(
        self,
        previous: tuple[GitHubRepositoryEntry, ...],
        current: tuple[GitHubRepositoryEntry, ...],
    ) -> None:
        previous_by_path = {entry.path: entry for entry in previous}
        current_by_path = {entry.path: entry for entry in current}
        if any(current_by_path.get(path) != entry for path, entry in previous_by_path.items()):
            raise GitHubProposalError("GitHub additive history changed or removed an object")
        additions = tuple(
            entry for path, entry in current_by_path.items() if path not in previous_by_path
        )
        if not additions:
            raise GitHubProposalError("GitHub additive history commit added no proposal")
        for entry in additions:
            if entry.object_type != "blob" or entry.mode != "100644":
                raise GitHubProposalError("GitHub additive history added a non-regular object")
            try:
                self._validate_proposal_path(entry.path)
            except GitHubProposalError:
                raise GitHubProposalError(
                    "GitHub additive history added an object outside the pinned ingress root"
                ) from None

    @staticmethod
    def _decode_content(
        content: dict[str, object],
        *,
        expected_path: str | None,
        expected_blob_id: str | None = None,
    ) -> bytes:
        if expected_path is not None:
            if content.get("type") != "file":
                raise GitHubProposalError("GitHub content response was not a file")
            if content.get("path") != expected_path:
                raise GitHubProposalError("GitHub content path did not match the request")

        blob_sha = content.get("sha")
        if not isinstance(blob_sha, str) or _OBJECT_ID_PATTERN.fullmatch(blob_sha) is None:
            raise GitHubProposalError("GitHub content blob SHA was invalid")
        if expected_blob_id is not None and blob_sha != expected_blob_id:
            raise GitHubProposalError("GitHub blob identity did not match the request")
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
        actual_sha = hashlib.sha1(
            f"blob {len(decoded)}\0".encode() + decoded,
            usedforsecurity=False,
        ).hexdigest()
        if blob_sha != actual_sha:
            raise GitHubProposalError("GitHub content blob SHA did not match the decoded object")
        return decoded

    @staticmethod
    def _object_id(value: object, name: str) -> str:
        if not isinstance(value, str) or _OBJECT_ID_PATTERN.fullmatch(value) is None:
            raise GitHubProposalError(f"GitHub {name} object ID was invalid")
        return value

    @staticmethod
    def _require_object_id(value: str, name: str) -> None:
        if _OBJECT_ID_PATTERN.fullmatch(value) is None:
            raise GitHubProposalError(f"GitHub {name} object ID was invalid")

    @staticmethod
    def _response_header(headers: Mapping[str, str], name: str) -> str | None:
        matches: list[str] = []
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise GitHubProposalError("GitHub API response headers were invalid")
            if key.lower() == name.lower():
                matches.append(value)
        if len(matches) > 1:
            raise GitHubProposalError("GitHub API response headers were invalid")
        return matches[0] if matches else None

    @staticmethod
    def _validate_etag(etag: str | None) -> None:
        if etag is not None and (
            not etag or len(etag) > 1024 or any(character in etag for character in "\r\n\x00")
        ):
            raise GitHubProposalError("GitHub ETag was invalid")
