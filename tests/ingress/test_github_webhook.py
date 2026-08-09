"""Tests for content-free signed GitHub webhook wake hints."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from uuid import UUID

import pytest
from kivra_memory.ingress.webhook import WebhookVerificationError, WebhookWakeHintVerifier

SECRET = b"a sufficiently long independent webhook secret"
REPOSITORY_ID = 123456789
DELIVERY_ID = UUID("019c0000-0000-7000-8000-000000000010")


def _body(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "ref": "refs/heads/main",
        "repository": {
            "id": REPOSITORY_ID,
            "full_name": "JTM-rootstorm/scalevault-memory-ingress",
            "default_branch": "main",
        },
    }
    document.update(overrides)
    return json.dumps(document, separators=(",", ":")).encode()


def _headers(body: bytes, **overrides: str) -> dict[str, str]:
    signature = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": str(DELIVERY_ID),
        "X-Hub-Signature-256": signature,
    }
    headers.update(overrides)
    return headers


def _verifier(*, clock: Callable[[], float] | None = None) -> WebhookWakeHintVerifier:
    if clock is None:
        return WebhookWakeHintVerifier(
            secret=SECRET,
            repository_id=REPOSITORY_ID,
            repository_owner="JTM-rootstorm",
            repository_name="scalevault-memory-ingress",
            branch="main",
        )
    return WebhookWakeHintVerifier(
        secret=SECRET,
        repository_id=REPOSITORY_ID,
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        branch="main",
        clock=clock,
    )


def test_valid_delivery_returns_only_content_free_wake_hint() -> None:
    body = _body()

    hint = _verifier().verify(headers=_headers(body), body=body)

    assert hint.delivery_id == DELIVERY_ID
    assert not hasattr(hint, "body")
    assert not hasattr(hint, "commit_id")


@pytest.mark.parametrize(
    ("header_overrides", "body", "message"),
    [
        ({"Content-Type": "text/plain"}, _body(), "media type"),
        ({"X-GitHub-Event": "issues"}, _body(), "event"),
        ({"X-GitHub-Delivery": "not-a-uuid"}, _body(), "delivery ID"),
        ({"X-Hub-Signature-256": "sha256=" + "0" * 64}, _body(), "signature"),
        ({}, _body(ref="refs/heads/other"), "branch binding"),
        (
            {},
            _body(
                repository={
                    "id": 987654321,
                    "full_name": "attacker/repository",
                    "default_branch": "main",
                }
            ),
            "repository binding",
        ),
    ],
)
def test_rejects_forged_or_unbound_delivery(
    header_overrides: dict[str, str],
    body: bytes,
    message: str,
) -> None:
    with pytest.raises(WebhookVerificationError, match=message):
        _verifier().verify(headers=_headers(body, **header_overrides), body=body)


def test_duplicate_delivery_is_rejected_inside_replay_window() -> None:
    body = _body()
    verifier = _verifier()
    verifier.verify(headers=_headers(body), body=body)

    with pytest.raises(WebhookVerificationError, match="replayed"):
        verifier.verify(headers=_headers(body), body=body)


def test_delivery_can_be_reused_only_after_bounded_replay_window() -> None:
    now = 100.0

    def clock() -> float:
        return now

    body = _body()
    verifier = _verifier(clock=clock)
    verifier.verify(headers=_headers(body), body=body)
    now += 601.0

    assert verifier.verify(headers=_headers(body), body=body).delivery_id == DELIVERY_ID


def test_disabled_verifier_fails_closed() -> None:
    verifier = WebhookWakeHintVerifier(
        secret=None,
        repository_id=None,
        repository_owner=None,
        repository_name=None,
        branch=None,
    )

    with pytest.raises(WebhookVerificationError, match="disabled"):
        verifier.verify(headers={}, body=b"")


def test_body_limit_is_checked_before_parsing_or_signature_details() -> None:
    private_body = b"private-memory-statement"
    verifier = WebhookWakeHintVerifier(
        secret=SECRET,
        repository_id=REPOSITORY_ID,
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        branch="main",
        max_body_bytes=4,
    )

    with pytest.raises(WebhookVerificationError, match="size limit") as caught:
        verifier.verify(headers=_headers(private_body), body=private_body)

    assert private_body.decode() not in str(caught.value)
