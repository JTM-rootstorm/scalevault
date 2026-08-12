from __future__ import annotations

from typing import Any

import pytest
from kivra_memory.observability.logging import EVENT_SPECS, log_event, safe_event


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
    assert len(EVENT_SPECS) == 18
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
