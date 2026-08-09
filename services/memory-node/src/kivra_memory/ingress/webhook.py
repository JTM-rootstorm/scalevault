"""Optional GitHub webhook verifier for poller wake hints only."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from uuid import UUID

DEFAULT_MAX_WEBHOOK_BODY_BYTES = 64 * 1024
_SIGNATURE_PATTERN = re.compile(r"sha256=[0-9a-f]{64}")
_SAFE_REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+")


class WebhookVerificationError(RuntimeError):
    """Raised when an untrusted webhook cannot be accepted as a wake hint."""


@dataclass(frozen=True, slots=True)
class WebhookWakeHint:
    """Content-free signal that the normal conditional poller should wake."""

    delivery_id: UUID


class WebhookWakeHintVerifier:
    """Verify bound GitHub push deliveries without accepting webhook provenance."""

    def __init__(
        self,
        *,
        secret: bytes | None,
        repository_id: int | None,
        repository_owner: str | None,
        repository_name: str | None,
        branch: str | None,
        expected_event: str = "push",
        replay_ttl_seconds: float = 600.0,
        max_body_bytes: int = DEFAULT_MAX_WEBHOOK_BODY_BYTES,
        max_replay_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            isinstance(max_body_bytes, bool)
            or not isinstance(max_body_bytes, int)
            or max_body_bytes <= 0
        ):
            raise ValueError("max_body_bytes must be positive")
        if not math.isfinite(replay_ttl_seconds) or replay_ttl_seconds <= 0:
            raise ValueError("replay_ttl_seconds must be positive")
        if (
            isinstance(max_replay_entries, bool)
            or not isinstance(max_replay_entries, int)
            or max_replay_entries <= 0
        ):
            raise ValueError("max_replay_entries must be positive")
        if not expected_event or any(character in expected_event for character in "\r\n\x00"):
            raise ValueError("expected_event is invalid")

        configured = (
            secret is not None,
            repository_id is not None,
            repository_owner is not None,
            repository_name is not None,
            branch is not None,
        )
        if any(configured) and not all(configured):
            raise ValueError(
                "webhook credential and repository binding must be configured together"
            )

        if all(configured):
            assert secret is not None
            assert repository_id is not None
            assert repository_owner is not None
            assert repository_name is not None
            assert branch is not None
            if not secret:
                raise ValueError("webhook secret is invalid")
            if (
                isinstance(repository_id, bool)
                or not isinstance(repository_id, int)
                or repository_id <= 0
            ):
                raise ValueError("repository_id must be a positive integer")
            if _SAFE_REPOSITORY_NAME.fullmatch(repository_owner) is None:
                raise ValueError("repository_owner is invalid")
            if _SAFE_REPOSITORY_NAME.fullmatch(repository_name) is None:
                raise ValueError("repository_name is invalid")
            if not branch or any(character in branch for character in "\r\n\x00"):
                raise ValueError("branch is invalid")

        self._secret = secret
        self._repository_id = repository_id
        self._repository_full_name = (
            f"{repository_owner}/{repository_name}" if all(configured) else None
        )
        self._branch = branch
        self._expected_event = expected_event
        self._replay_ttl_seconds = replay_ttl_seconds
        self._max_body_bytes = max_body_bytes
        self._max_replay_entries = max_replay_entries
        self._clock = clock
        self._deliveries: dict[UUID, float] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Return whether both the credential and full binding are configured."""

        return self._secret is not None and self._repository_full_name is not None

    def verify(self, *, headers: Mapping[str, str], body: bytes) -> WebhookWakeHint:
        """Verify exact raw bytes and return only a content-free wake hint."""

        if not self.enabled:
            raise WebhookVerificationError("GitHub webhook verification is disabled")
        if not isinstance(body, bytes):
            raise WebhookVerificationError("GitHub webhook body was invalid")
        if len(body) > self._max_body_bytes:
            raise WebhookVerificationError("GitHub webhook body exceeded the size limit")

        content_type = self._required_header(headers, "Content-Type")
        event = self._required_header(headers, "X-GitHub-Event")
        delivery = self._required_header(headers, "X-GitHub-Delivery")
        signature = self._required_header(headers, "X-Hub-Signature-256")
        if content_type.lower() != "application/json":
            raise WebhookVerificationError("GitHub webhook media type was invalid")
        if event != self._expected_event:
            raise WebhookVerificationError("GitHub webhook event was invalid")
        try:
            delivery_id = UUID(delivery)
        except ValueError:
            raise WebhookVerificationError("GitHub webhook delivery ID was invalid") from None
        if str(delivery_id) != delivery:
            raise WebhookVerificationError("GitHub webhook delivery ID was invalid")
        if _SIGNATURE_PATTERN.fullmatch(signature) is None:
            raise WebhookVerificationError("GitHub webhook signature was invalid")

        assert self._secret is not None
        expected_signature = (
            "sha256="
            + hmac.new(
                self._secret,
                body,
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected_signature, signature):
            raise WebhookVerificationError("GitHub webhook signature was invalid")

        document = self._decode_body(body)
        self._verify_binding(document)
        self._claim_delivery(delivery_id)
        return WebhookWakeHint(delivery_id=delivery_id)

    @staticmethod
    def _required_header(headers: Mapping[str, str], name: str) -> str:
        matches: list[str] = []
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise WebhookVerificationError("GitHub webhook headers were invalid")
            if key.lower() == name.lower():
                matches.append(value)
        if len(matches) != 1 or not matches[0]:
            raise WebhookVerificationError("GitHub webhook headers were invalid")
        value = matches[0]
        if len(value) > 1024 or any(character in value for character in "\r\n\x00"):
            raise WebhookVerificationError("GitHub webhook headers were invalid")
        return value

    @staticmethod
    def _decode_body(body: bytes) -> dict[str, object]:
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise WebhookVerificationError("GitHub webhook body was invalid") from None
        if not isinstance(document, dict):
            raise WebhookVerificationError("GitHub webhook body was invalid")
        return document

    def _verify_binding(self, document: dict[str, object]) -> None:
        if document.get("ref") != f"refs/heads/{self._branch}":
            raise WebhookVerificationError("GitHub webhook branch binding did not match")
        repository = document.get("repository")
        if not isinstance(repository, dict):
            raise WebhookVerificationError("GitHub webhook repository binding did not match")
        repository_id = repository.get("id")
        if isinstance(repository_id, bool) or repository_id != self._repository_id:
            raise WebhookVerificationError("GitHub webhook repository binding did not match")
        if repository.get("full_name") != self._repository_full_name:
            raise WebhookVerificationError("GitHub webhook repository binding did not match")
        if repository.get("default_branch") != self._branch:
            raise WebhookVerificationError("GitHub webhook repository binding did not match")

    def _claim_delivery(self, delivery_id: UUID) -> None:
        now = self._clock()
        with self._lock:
            expired = [key for key, expires_at in self._deliveries.items() if expires_at <= now]
            for key in expired:
                del self._deliveries[key]
            if delivery_id in self._deliveries:
                raise WebhookVerificationError("GitHub webhook delivery was replayed")
            if len(self._deliveries) >= self._max_replay_entries:
                raise WebhookVerificationError("GitHub webhook replay window was full")
            self._deliveries[delivery_id] = now + self._replay_ttl_seconds
