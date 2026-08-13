from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[3]
UNIT = (
    REPOSITORY_ROOT / "deploy" / "memory-node" / "systemd" / "kivra-memory-operator-report@.service"
)


def test_operator_report_template_supplies_both_protected_credentials() -> None:
    unit = UNIT.read_text()
    assert (
        "LoadCredential=database-url:"
        "/etc/kivra-memory/credentials/operator-report-database-url" in unit
    )
    assert "LoadCredential=tenant-id:/etc/kivra-memory/operator-report-scopes/%i" in unit
    assert (
        "ExecStart=/opt/kivra-memory/app/.venv/bin/"
        "kivra-memory-operator-report-run --report-id %i" in unit
    )
    assert "Environment=HOME=/nonexistent" in unit
    assert "EnvironmentFile=" not in unit


def test_operator_report_database_boundary_requires_dedicated_login() -> None:
    source = (
        REPOSITORY_ROOT
        / "services"
        / "memory-node"
        / "src"
        / "kivra_memory"
        / "observability"
        / "report_main.py"
    ).read_text()
    assert 'url.username != "kivra_memory_operator_report_login"' in source
    assert 'url.username != "kivra_memory_api"' not in source


def test_operator_report_template_owns_private_output_and_emits_no_report_stdout() -> None:
    unit = UNIT.read_text()
    assert "User=root" in unit
    assert "Group=root" in unit
    assert "UMask=0077" in unit
    assert "StateDirectory=kivra-memory/operator-reports" in unit
    assert "StateDirectoryMode=0700" in unit
    assert "StandardOutput=null" in unit
    assert "StandardError=journal" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=true" in unit
    assert "NoNewPrivileges=true" in unit
    assert "LimitCORE=0" in unit
    assert "CapabilityBoundingSet=\n" in unit
