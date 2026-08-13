from __future__ import annotations

from math import prod

import pytest
from kivra_memory.observability.metrics import METRIC_SPECS, MetricRegistry
from prometheus_client import generate_latest

FORBIDDEN_LABELS = {
    "actor",
    "client",
    "credential",
    "hostname",
    "ingress",
    "memory",
    "path",
    "repository",
    "request",
    "subject",
    "tenant",
    "user",
}


def test_metric_contract_is_unique_complete_and_content_free() -> None:
    names = [spec.name for spec in METRIC_SPECS]
    assert len(names) == len(set(names)) == 43
    assert all(name.startswith("kivra_memory_") for name in names)

    for spec in METRIC_SPECS:
        assert set(spec.labels).isdisjoint(FORBIDDEN_LABELS)
        assert tuple(label for label, _ in spec.allowed_values) == spec.labels
        for label, values in spec.allowed_values:
            assert label
            assert values
            assert len(values) == len(set(values))
            assert all(value and value == value.strip() for value in values)


def test_metric_cardinality_contract_stays_within_adr_budgets() -> None:
    family_labelsets = {
        spec.name: prod(len(values) for _, values in spec.allowed_values)
        if spec.allowed_values
        else 1
        for spec in METRIC_SPECS
    }
    assert max(family_labelsets.values()) <= 256
    assert sum(family_labelsets.values()) <= 4096
    assert family_labelsets["kivra_memory_mcp_calls_total"] == 255


def test_every_allowed_label_value_can_be_instantiated() -> None:
    registry = MetricRegistry()
    for spec in METRIC_SPECS:
        metric = registry[spec.name]
        labels = {label: values[0] for label, values in spec.allowed_values}
        if spec.kind == "counter":
            metric.labels(**labels).inc()
        elif spec.kind == "gauge":
            metric.set(1, **labels)
        else:
            metric.observe(1, **labels)

    rendered = generate_latest(registry.prometheus).decode("ascii")
    for spec in METRIC_SPECS:
        assert spec.name.removesuffix("_total") in rendered


def test_metric_labels_fail_closed() -> None:
    registry = MetricRegistry()
    metric = registry["kivra_memory_authentication_failures_total"]
    with pytest.raises(ValueError, match="invalid_labels"):
        metric.inc(reason="invalid")
    with pytest.raises(ValueError, match="invalid_label_value"):
        metric.inc(reason="raw-user-value", profile="direct_private")
    with pytest.raises(ValueError, match="invalid_labels"):
        metric.inc(
            reason="invalid",
            profile="direct_private",
            tenant="01900000-0000-7000-8000-000000000000",
        )


def test_registries_are_isolated_without_duplicate_registration() -> None:
    first = MetricRegistry()
    second = MetricRegistry()
    first["kivra_memory_tunnel_connected"].set(1)
    second["kivra_memory_tunnel_connected"].set(0)
    assert b"kivra_memory_tunnel_connected 1.0" in generate_latest(first.prometheus)
    assert b"kivra_memory_tunnel_connected 0.0" in generate_latest(second.prometheus)
