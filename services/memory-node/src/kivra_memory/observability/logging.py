"""Fixed, payload-silent production event logging.

This module intentionally has no generic ``extra`` mapping and no exception
argument.  Provider bodies, SQL diagnostics, Git stderr, request data, and
tracebacks therefore cannot accidentally cross the production log boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID

LogLevel = Literal["info", "warning", "error"]
SafeValue = bool | int | float | str


class EventLogger(Protocol):
    def info(self, event: str, **fields: SafeValue) -> object: ...
    def warning(self, event: str, **fields: SafeValue) -> object: ...
    def error(self, event: str, **fields: SafeValue) -> object: ...


@dataclass(frozen=True, slots=True)
class EventSpec:
    level: LogLevel
    fields: tuple[str, ...]


EVENT_SPECS: Mapping[str, EventSpec] = {
    "archive_export_completed": EventSpec("info", ("count", "duration_ms")),
    "archive_export_failed": EventSpec("error", ("error_code", "recovery_id")),
    "authentication_rejected": EventSpec("warning", ("error_code", "profile")),
    "backup_completed": EventSpec("info", ("kind", "duration_ms")),
    "backup_failed": EventSpec("error", ("kind", "error_code", "recovery_id")),
    "configuration_rejected": EventSpec("error", ("error_code",)),
    "github_poll_completed": EventSpec("info", ("count", "duration_ms")),
    "github_poll_failed": EventSpec("warning", ("error_code", "recovery_id")),
    "hard_forget_purge_completed": EventSpec("info", ("count",)),
    "hard_forget_purge_failed": EventSpec("error", ("error_code", "recovery_id")),
    "operator_report_completed": EventSpec("info", ("duration_ms",)),
    "operator_report_rejected": EventSpec("warning", ("error_code",)),
    "queue_batch_completed": EventSpec("info", ("queue", "count", "duration_ms")),
    "queue_batch_failed": EventSpec("error", ("queue", "error_code", "recovery_id")),
    "recovery_drill_completed": EventSpec("info", ("kind", "duration_ms")),
    "recovery_drill_failed": EventSpec("error", ("kind", "error_code", "recovery_id")),
    "service_started": EventSpec("info", ("service",)),
    "service_stopped": EventSpec("info", ("service", "state")),
}

ERROR_CODES = frozenset(
    {
        "authentication_failed",
        "configuration_invalid",
        "dependency_unavailable",
        "integrity_failed",
        "internal_error",
        "operator_not_authorized",
        "provider_unavailable",
        "serialization_exhausted",
        "storage_unavailable",
        "timeout",
        "verification_failed",
    }
)
FIELD_VALUES: Mapping[str, frozenset[str]] = {
    "kind": frozenset({"base", "git", "git_bundle", "pitr", "wal"}),
    "profile": frozenset({"canonical", "direct_private", "github", "secure_tunnel", "worker"}),
    "queue": frozenset({"archive", "embedding", "github", "lifecycle", "projection", "purge"}),
    "service": frozenset({"api", "archive", "github", "lifecycle", "sealed", "worker"}),
    "state": frozenset({"clean", "failed", "stopped"}),
}


def safe_event(event: str, **fields: SafeValue) -> tuple[LogLevel, dict[str, SafeValue]]:
    """Validate and return one event without accepting arbitrary context."""

    try:
        spec = EVENT_SPECS[event]
    except KeyError:
        raise ValueError("unknown_log_event") from None
    if tuple(fields) != spec.fields:
        raise ValueError("invalid_log_fields")
    checked: dict[str, SafeValue] = {}
    for name, value in fields.items():
        if name in {"count", "duration_ms"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"invalid_log_field:{name}")
        elif name == "recovery_id":
            if not isinstance(value, str):
                raise ValueError("invalid_log_field:recovery_id")
            try:
                parsed = UUID(value)
            except ValueError:
                raise ValueError("invalid_log_field:recovery_id") from None
            if str(parsed) != value:
                raise ValueError("invalid_log_field:recovery_id")
        elif name == "error_code":
            if value not in ERROR_CODES:
                raise ValueError("invalid_log_field:error_code")
        elif not isinstance(value, str) or value not in FIELD_VALUES[name]:
            raise ValueError(f"invalid_log_field:{name}")
        checked[name] = value
    return spec.level, checked


def log_event(logger: EventLogger, event: str, **fields: SafeValue) -> None:
    """Emit a validated event through a structlog-compatible logger."""

    level, checked = safe_event(event, **fields)
    getattr(logger, level)(event, **checked)


__all__ = ["ERROR_CODES", "EVENT_SPECS", "EventLogger", "EventSpec", "log_event", "safe_event"]
