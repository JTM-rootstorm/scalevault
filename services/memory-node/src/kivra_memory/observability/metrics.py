"""Closed, content-free Prometheus metric contract for ScaleVault.

Callers receive :class:`BoundedMetric` objects rather than raw Prometheus
collectors.  That keeps every label behind an allowlist and prevents a request,
tenant, memory, credential, host, or other user-controlled value from becoming
a time-series label.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

MetricKind = Literal["counter", "gauge", "histogram"]


@dataclass(frozen=True, slots=True)
class MetricSpec:
    name: str
    documentation: str
    kind: MetricKind
    labels: tuple[str, ...] = ()
    allowed_values: tuple[tuple[str, tuple[str, ...]], ...] = ()
    buckets: tuple[float, ...] | None = None

    def allowed_for(self, label: str) -> frozenset[str]:
        return frozenset(dict(self.allowed_values)[label])


class BoundedMetric:
    """A Prometheus collector whose labels are exact and closed."""

    def __init__(self, spec: MetricSpec, registry: CollectorRegistry) -> None:
        self.spec = spec
        if spec.kind == "counter":
            self._collector: Any = Counter(
                spec.name,
                spec.documentation,
                labelnames=spec.labels,
                registry=registry,
            )
        elif spec.kind == "gauge":
            self._collector = Gauge(
                spec.name,
                spec.documentation,
                labelnames=spec.labels,
                registry=registry,
            )
        else:
            if spec.buckets is not None:
                self._collector = Histogram(
                    spec.name,
                    spec.documentation,
                    labelnames=spec.labels,
                    registry=registry,
                    buckets=spec.buckets,
                )
            else:
                self._collector = Histogram(
                    spec.name,
                    spec.documentation,
                    labelnames=spec.labels,
                    registry=registry,
                )

    def _validate_labels(self, labels: dict[str, str]) -> None:
        if tuple(labels) != self.spec.labels:
            raise ValueError(f"invalid_labels:{self.spec.name}")
        for label, value in labels.items():
            if value not in self.spec.allowed_for(label):
                raise ValueError(f"invalid_label_value:{self.spec.name}:{label}")

    def _child(self, labels: dict[str, str]) -> Any:
        self._validate_labels(labels)
        if not labels:
            return self._collector
        return self._collector.labels(**labels)

    def labels(self, **labels: str) -> Any:
        """Return a validated child for compatibility with Prometheus call sites."""

        return self._child(labels)

    def validate_labels(self, **labels: str) -> None:
        """Validate a prospective label set without recording a sample."""

        self._validate_labels(labels)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        child = self._child(labels)
        if self.spec.kind not in {"counter", "gauge"}:
            raise TypeError(f"not_incrementable:{self.spec.name}")
        child.inc(amount)

    def set(self, value: float, **labels: str) -> None:
        child = self._child(labels)
        if self.spec.kind != "gauge":
            raise TypeError(f"not_gauge:{self.spec.name}")
        child.set(value)

    def observe(self, value: float, **labels: str) -> None:
        child = self._child(labels)
        if self.spec.kind != "histogram":
            raise TypeError(f"not_histogram:{self.spec.name}")
        child.observe(value)


TOOLS = (
    "memory_forget",
    "memory_get",
    "memory_link",
    "memory_nominate",
    "memory_observe",
    "memory_open_conflict",
    "memory_read_conflicts",
    "memory_read_context",
    "memory_read_lineage",
    "memory_read_search",
    "memory_read_selection_history",
    "memory_read_timeline",
    "memory_remember",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_revise",
    "memory_transport_status",
)
PROFILES = ("canonical", "direct_private", "github", "secure_tunnel", "worker")
# MCP outcomes deliberately collapse detailed failures into ``error``.  The
# reason-specific authentication and boundary families retain actionable cause
# without pushing the MCP call family over its 256-labelset budget.
RESULTS = ("error", "ok", "rejected")


def _allowed(**values: tuple[str, ...]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(values.items())


METRIC_SPECS = (
    MetricSpec(
        "kivra_memory_health_requests_total",
        "Health endpoint requests.",
        "counter",
        ("endpoint", "result"),
        _allowed(endpoint=("healthz", "readyz"), result=("not_ready", "ok", "ready")),
    ),
    MetricSpec(
        "kivra_memory_mcp_http_boundary_rejections_total",
        "MCP requests rejected before protocol parsing.",
        "counter",
        ("reason",),
        _allowed(
            reason=(
                "ambiguous_body_framing",
                "duplicate_singleton",
                "forwarded_header",
                "header_bytes",
                "header_count",
                "header_encoding",
                "host_count",
            )
        ),
    ),
    MetricSpec(
        "kivra_memory_mcp_calls_total",
        "MCP calls.",
        "counter",
        ("tool", "profile", "result"),
        _allowed(tool=TOOLS, profile=PROFILES, result=RESULTS),
    ),
    MetricSpec(
        "kivra_memory_mcp_duration_seconds",
        "MCP call duration.",
        "histogram",
        ("tool", "profile"),
        _allowed(tool=TOOLS, profile=PROFILES),
        (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    ),
    MetricSpec(
        "kivra_memory_mcp_context_pack_items",
        "Returned context-pack item count.",
        "histogram",
        ("profile",),
        _allowed(profile=PROFILES),
        (0, 1, 2, 4, 8, 16, 32, 64),
    ),
    MetricSpec(
        "kivra_memory_authentication_failures_total",
        "Authentication failures.",
        "counter",
        ("reason", "profile"),
        _allowed(
            reason=("expired", "invalid", "missing", "revoked", "scope", "unavailable"),
            profile=PROFILES,
        ),
    ),
    MetricSpec(
        "kivra_memory_private_ingress_events_total",
        "Private ingress boundary events.",
        "counter",
        ("category",),
        _allowed(category=("rejected", "saturated", "timed_out")),
    ),
    MetricSpec(
        "kivra_memory_write_outcomes_total",
        "Canonical write outcomes.",
        "counter",
        ("outcome",),
        _allowed(outcome=("conflict", "idempotent_replay", "ok", "rejected")),
    ),
    MetricSpec(
        "kivra_memory_serialization_retries_total",
        "Serializable transaction retry outcomes.",
        "counter",
        ("result",),
        _allowed(result=("exhausted", "retried", "succeeded")),
    ),
    MetricSpec(
        "kivra_memory_retrieval_candidate_count",
        "Retrieval candidates considered.",
        "histogram",
        ("profile",),
        _allowed(profile=("context", "search")),
        (0, 1, 2, 4, 8, 16, 32, 64, 128, 256),
    ),
    MetricSpec(
        "kivra_memory_retrieval_duration_seconds",
        "Retrieval duration.",
        "histogram",
        ("profile", "result"),
        _allowed(profile=("context", "search"), result=("error", "ok", "timeout")),
        (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    ),
    MetricSpec(
        "kivra_memory_database_pool_connections",
        "Database pool connections by state.",
        "gauge",
        ("state",),
        _allowed(state=("idle", "in_use", "overflow")),
    ),
    MetricSpec(
        "kivra_memory_database_pool_saturation_ratio", "Database pool saturation ratio.", "gauge"
    ),
    MetricSpec(
        "kivra_memory_queue_depth",
        "Queued jobs by bounded queue and state.",
        "gauge",
        ("queue", "state"),
        _allowed(
            queue=("archive", "embedding", "github", "lifecycle", "projection", "purge"),
            state=("dead", "leased", "pending"),
        ),
    ),
    MetricSpec(
        "kivra_memory_queue_oldest_age_seconds",
        "Age of oldest runnable job.",
        "gauge",
        ("queue",),
        _allowed(queue=("archive", "embedding", "github", "lifecycle", "projection", "purge")),
    ),
    MetricSpec(
        "kivra_memory_archive_lag_events",
        "Archive event lag.",
        "gauge",
        ("stage",),
        _allowed(stage=("export", "push", "source")),
    ),
    MetricSpec(
        "kivra_memory_archive_lag_seconds",
        "Archive wall-clock lag.",
        "gauge",
        ("stage",),
        _allowed(stage=("export", "push", "source")),
    ),
    MetricSpec(
        "kivra_memory_archive_verification_failures_total",
        "Archive verification failures.",
        "counter",
        ("reason",),
        _allowed(reason=("continuity", "divergence", "manifest", "signature", "unavailable")),
    ),
    MetricSpec(
        "kivra_memory_github_poll_age_seconds",
        "Age of last successful GitHub poll, including unchanged heads.",
        "gauge",
    ),
    MetricSpec(
        "kivra_memory_github_events_total",
        "GitHub ingress aggregate events.",
        "counter",
        ("category",),
        _allowed(category=("auth_failure", "discovered", "poll_success", "quarantined")),
    ),
    MetricSpec(
        "kivra_memory_github_processing_duration_seconds",
        "GitHub ingress processing duration.",
        "histogram",
        ("result",),
        _allowed(result=("accepted", "quarantined", "rejected")),
        (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
    ),
    MetricSpec(
        "kivra_memory_credentials_total",
        "Credential aggregate by profile, expiry bucket, and state.",
        "gauge",
        ("profile", "expiry", "state"),
        _allowed(
            profile=("direct_private", "github", "secure_tunnel", "service"),
            expiry=("expired", "gt_30d", "le_1d", "le_7d", "le_30d", "none"),
            state=("active", "revoked"),
        ),
    ),
    MetricSpec(
        "kivra_memory_backup_age_seconds",
        "Age of latest successful backup.",
        "gauge",
        ("kind",),
        _allowed(kind=("base", "git_bundle")),
    ),
    MetricSpec(
        "kivra_memory_backup_results_total",
        "Backup outcomes.",
        "counter",
        ("kind", "result"),
        _allowed(kind=("base", "git_bundle"), result=("failure", "success")),
    ),
    MetricSpec(
        "kivra_memory_backup_verification_results_total",
        "Backup verification outcomes.",
        "counter",
        ("kind", "result"),
        _allowed(kind=("base", "git_bundle"), result=("failure", "success")),
    ),
    MetricSpec(
        "kivra_memory_wal_archive_failures_total",
        "WAL archive failures.",
        "counter",
        ("reason",),
        _allowed(reason=("command", "storage", "timeout", "unavailable")),
    ),
    MetricSpec("kivra_memory_wal_backlog_bytes", "Unarchived WAL bytes.", "gauge"),
    MetricSpec(
        "kivra_memory_wal_oldest_age_seconds", "Age of oldest unarchived WAL segment.", "gauge"
    ),
    MetricSpec(
        "kivra_memory_offsite_copy_age_seconds",
        "Age of latest offsite copy.",
        "gauge",
        ("kind",),
        _allowed(kind=("base", "git_bundle", "wal")),
    ),
    MetricSpec(
        "kivra_memory_offsite_verification_results_total",
        "Offsite verification outcomes.",
        "counter",
        ("result",),
        _allowed(result=("failure", "success")),
    ),
    MetricSpec(
        "kivra_memory_recovery_drill_age_seconds",
        "Age of latest successful recovery drill.",
        "gauge",
        ("kind",),
        _allowed(kind=("git", "pitr")),
    ),
    MetricSpec(
        "kivra_memory_recovery_drill_results_total",
        "Recovery drill outcomes.",
        "counter",
        ("kind", "result"),
        _allowed(kind=("git", "pitr"), result=("failure", "success")),
    ),
    MetricSpec(
        "kivra_memory_service_exits_total",
        "Service fatal exits or restarts.",
        "counter",
        ("service", "cause"),
        _allowed(
            service=("api", "archive", "github", "lifecycle", "sealed", "worker"),
            cause=("fatal", "restart"),
        ),
    ),
    MetricSpec(
        "kivra_memory_tunnel_connected", "Whether the private tunnel is connected.", "gauge"
    ),
    MetricSpec(
        "kivra_memory_projection_inconsistencies",
        "Projection/event consistency failures.",
        "gauge",
        ("kind",),
        _allowed(kind=("event_gap", "projection_drift", "selection_gap")),
    ),
    MetricSpec(
        "kivra_memory_public_exposure_probe_success",
        "External probe unexpectedly reached a protected service.",
        "gauge",
        ("vantage",),
        _allowed(vantage=("external", "spoofed")),
    ),
    MetricSpec(
        "kivra_memory_public_exposure_backend_connections_total",
        "Backend connections observed during exposure probes.",
        "counter",
        ("result",),
        _allowed(result=("authorized", "unauthorized")),
    ),
    MetricSpec(
        "kivra_memory_hard_forget_purge_depth",
        "Hard-forget purge queue depth.",
        "gauge",
        ("state",),
        _allowed(state=("dead", "leased", "pending")),
    ),
    MetricSpec(
        "kivra_memory_hard_forget_purge_results_total",
        "Hard-forget purge outcomes.",
        "counter",
        ("result",),
        _allowed(result=("failure", "success")),
    ),
    MetricSpec(
        "kivra_memory_storage_free_bytes",
        "Free bytes in bounded storage classes.",
        "gauge",
        ("component",),
        _allowed(component=("backup", "database", "monitoring", "wal")),
    ),
)


class MetricRegistry:
    """One isolated registry and all M10 metric handles."""

    def __init__(self) -> None:
        self.prometheus = CollectorRegistry(auto_describe=True)
        self.metrics = {spec.name: BoundedMetric(spec, self.prometheus) for spec in METRIC_SPECS}

    def __getitem__(self, name: str) -> BoundedMetric:
        return self.metrics[name]


REGISTRY = MetricRegistry()


__all__ = [
    "METRIC_SPECS",
    "PROFILES",
    "REGISTRY",
    "RESULTS",
    "TOOLS",
    "BoundedMetric",
    "MetricRegistry",
    "MetricSpec",
]
