from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[3]
UNIT = REPOSITORY_ROOT / "deploy/memory-node/systemd/kivra-memory-metrics-exporter.service"


def test_metrics_exporter_is_loopback_function_only_and_credential_bound() -> None:
    unit = UNIT.read_text()
    assert "User=memory-metrics" in unit
    assert "Group=memory-metrics" in unit
    assert "Group=kivra-memory" not in unit
    assert "LoadCredential=database-url:" in unit
    assert "LoadCredential=tenant-id:" in unit
    assert "SocketBindAllow=tcp:9098" in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=localhost" in unit
    assert "NoNewPrivileges=true" in unit
    assert "LimitCORE=0" in unit
    assert "TasksMax=8" in unit
    assert "MemoryMax=192M" in unit
    assert "CPUQuota=50%" in unit
    assert "EnvironmentFile=" not in unit

    exporter = (
        REPOSITORY_ROOT / "services/memory-node/src/kivra_memory/observability/metrics_exporter.py"
    ).read_text()
    assert "class _BoundedHTTPServer(HTTPServer)" in exporter
    assert "request_queue_size = 8" in exporter
    assert "MAXIMUM_REQUEST_LINE_BYTES" in exporter
    assert "REQUEST_TIMEOUT_SECONDS" in exporter
    assert "connection.settimeout" in exporter
    assert "ThreadingHTTPServer" not in exporter
    assert "start_http_server" not in exporter


def test_prometheus_scrapes_dedicated_exporter_only_on_loopback() -> None:
    config = (REPOSITORY_ROOT / "deploy/memory-node/monitoring/prometheus.yml.example").read_text()
    assert "job_name: scalevault-database-metrics" in config
    assert "127.0.0.1:9098" in config
    assert "0.0.0.0" not in config


def test_install_contract_creates_private_account_and_credentials() -> None:
    documentation = (REPOSITORY_ROOT / "deploy/memory-node/systemd/README.md").read_text()
    assert "--user-group --no-create-home" in documentation
    assert "memory-metrics" in documentation
    assert "kivra_memory_metrics" in documentation
    assert "/etc/kivra-memory/metrics-tenant-id" in documentation
    assert "systemctl enable --now kivra-memory-metrics-exporter.service" in documentation
