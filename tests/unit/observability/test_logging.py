from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from kivra_memory.observability.logging import (
    EVENT_SPECS,
    PayloadSafeExceptionMiddleware,
    log_event,
    safe_event,
)
from starlette.types import Message, Receive, Scope, Send


class CapturingLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def info(self, event: str, **fields: Any) -> None:
        self.calls.append(("info", event, fields))

    def warning(self, event: str, **fields: Any) -> None:
        self.calls.append(("warning", event, fields))

    def error(self, event: str, **fields: Any) -> None:
        self.calls.append(("error", event, fields))


def test_fixed_event_vocabulary_has_no_generic_payload_fields() -> None:
    forbidden = {"body", "credential", "exception", "payload", "statement", "stderr", "url"}
    assert len(EVENT_SPECS) == 19
    assert all(set(spec.fields).isdisjoint(forbidden) for spec in EVENT_SPECS.values())


def test_safe_event_emits_only_validated_fields() -> None:
    logger = CapturingLogger()
    log_event(logger, "queue_batch_completed", queue="embedding", count=3, duration_ms=12.5)
    assert logger.calls == [
        (
            "info",
            "queue_batch_completed",
            {"queue": "embedding", "count": 3, "duration_ms": 12.5},
        )
    ]


@pytest.mark.parametrize(
    ("event", "fields", "code"),
    [
        ("unknown", {}, "unknown_log_event"),
        ("service_started", {"service": "raw-host"}, "invalid_log_field:service"),
        ("configuration_rejected", {"error_code": "raw traceback"}, "invalid_log_field"),
        ("backup_completed", {"kind": "base", "duration_ms": -1}, "invalid_log_field"),
        ("service_started", {"payload": "canary"}, "invalid_log_fields"),
    ],
)
def test_logging_rejects_unbounded_or_payload_fields(
    event: str, fields: dict[str, object], code: str
) -> None:
    with pytest.raises(ValueError, match=code):
        safe_event(event, **fields)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_exception_middleware_omits_request_and_exception_canaries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exception_canary = "SYNTHETIC-EXCEPTION-PRIVATE-CANARY"
    request_canary = b"SYNTHETIC-REQUEST-PRIVATE-CANARY"
    logger = CapturingLogger()
    messages: list[Message] = []

    async def failing(_scope: Scope, receive: Receive, _send: Send) -> None:
        await receive()
        raise RuntimeError(exception_canary)

    received = False

    async def receive() -> Message:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": request_canary, "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": f"/{request_canary.decode()}",
        "raw_path": b"/" + request_canary,
        "query_string": b"canary=" + request_canary,
        "root_path": "",
        "headers": [(b"x-private-canary", request_canary)],
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8080),
        "state": {},
    }
    await PayloadSafeExceptionMiddleware(failing, logger=logger)(scope, receive, send)

    assert messages[0]["status"] == 500
    body = messages[1]["body"].decode("ascii")
    recovery_id = body.removeprefix('{"error":"internal_error","recovery_id":"').removesuffix('"}')
    UUID(recovery_id)
    assert logger.calls == [
        (
            "error",
            "request_failed",
            {"error_code": "internal_error", "recovery_id": recovery_id},
        )
    ]
    combined = repr(logger.calls) + body + capsys.readouterr().err
    assert exception_canary not in combined
    assert request_canary.decode() not in combined
