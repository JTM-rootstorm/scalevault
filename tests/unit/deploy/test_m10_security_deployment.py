"""Static M10 service-hardening and NPM drift-check contracts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SYSTEMD_ROOT = ROOT / "deploy/memory-node/systemd"
NPM_CHECKER = ROOT / "deploy/memory-node/scripts/kivra-memory-npm-config-check"
NON_BACKUP_UNITS = tuple(
    path
    for path in sorted(SYSTEMD_ROOT.glob("kivra-memory-*.service"))
    if "backup" not in path.name
)


@pytest.mark.parametrize("unit_path", NON_BACKUP_UNITS, ids=lambda path: path.name)
def test_installed_service_uses_common_secret_process_hardening(unit_path: Path) -> None:
    unit = unit_path.read_text(encoding="utf-8")

    for directive in (
        "LimitCORE=0",
        "PrivateMounts=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "ProtectKernelLogs=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RemoveIPC=true",
        "RestrictNamespaces=true",
        "RestrictRealtime=true",
        "KeyringMode=private",
        "SystemCallArchitectures=native",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=",
        "TimeoutStopSec=30s",
    ):
        assert directive in unit

    assert "StartLimitIntervalSec=300" in unit
    assert "StartLimitBurst=5" in unit
    assert "Environment=KIVRA_MEMORY_DATABASE_URL=" not in unit
    assert "Environment=KIVRA_MEMORY_PURGE_DATABASE_URL=" not in unit


@pytest.mark.parametrize(
    ("unit_name", "credential_name"),
    (
        ("kivra-memory-api.service", "database-url"),
        ("kivra-memory-codex-ingress.service", "database-url"),
        ("kivra-memory-worker.service", "database-url"),
        ("kivra-memory-lifecycle-worker.service", "database-url"),
        ("kivra-memory-sealed-worker.service", "database-url"),
        ("kivra-memory-archive-exporter.service", "database-url"),
        ("kivra-memory-github-ingress.service", "ingress-database-url"),
        ("kivra-memory-github-ingress.service", "command-database-url"),
    ),
)
def test_database_secrets_use_service_scoped_credentials(
    unit_name: str, credential_name: str
) -> None:
    unit = (SYSTEMD_ROOT / unit_name).read_text(encoding="utf-8")

    assert f"LoadCredential={credential_name}:" in unit


def test_npm_checker_accepts_sanitized_contract(tmp_path: Path) -> None:
    configuration = tmp_path / "nginx.conf"
    configuration.write_text(
        "server {\n"
        "  set_real_ip_from 10.0.0.0/8;\n"
        "  include conf.d/include/block-exploits.conf;\n"
        "  location / { proxy_pass http://UNRELATED:9000; }\n"
        "}\n"
        "server {\n"
        "  set_real_ip_from unix:;\n"
        "  real_ip_recursive off;\n"
        "  location /mcp {\n"
        "    proxy_pass_request_headers off;\n"
        "    proxy_next_upstream off;\n"
        "    proxy_redirect off;\n"
        "    access_log off;\n"
        "    proxy_pass http://PRIVATE_BACKEND:8443;\n"
        "  }\n"
        "  location ~ ^/(?!mcp$) {\n"
        "    access_log off;\n"
        "    return 404;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    configuration.chmod(0o600)

    result = subprocess.run(
        [NPM_CHECKER, configuration], text=True, capture_output=True, check=False
    )

    assert result.returncode == 0
    assert result.stdout == "NPM configuration contract satisfied\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("nasty", "expected"),
    (
        ("include conf.d/include/block-exploits.conf;", "Block Common Exploits"),
        ("auth_basic restricted;", "Basic authentication"),
        ("set_real_ip_from 10.0.0.0/8;", "broad RFC1918"),
        ('proxy_set_header Authorization "";', "must not clear Authorization"),
        ("proxy_ssl_verify off;", "backend TLS"),
        ("return 301 https://private.invalid$request_uri;", "Force SSL"),
    ),
)
def test_npm_checker_rejects_known_drift_without_dumping_configuration(
    tmp_path: Path, nasty: str, expected: str
) -> None:
    configuration = tmp_path / "nginx.conf"
    canary = "PRIVATE_PAYLOAD_CANARY_MUST_NOT_BE_PRINTED"
    configuration.write_text(
        "server {\n"
        "  set_real_ip_from unix:;\n"
        "  real_ip_recursive off;\n"
        "  location /mcp {\n"
        "    proxy_pass_request_headers off;\n"
        "    proxy_next_upstream off;\n"
        "    proxy_redirect off;\n"
        "    access_log off;\n"
        "    proxy_pass http://PRIVATE_BACKEND:8443;\n"
        f"    # {canary}\n"
        f"    {nasty}\n"
        "  }\n"
        "  location ~ ^/(?!mcp$) {\n"
        "    access_log off;\n"
        "    return 404;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    configuration.chmod(0o600)

    result = subprocess.run(
        [NPM_CHECKER, configuration], text=True, capture_output=True, check=False
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert canary not in result.stdout + result.stderr


def test_npm_checker_rejects_linked_input(tmp_path: Path) -> None:
    configuration = tmp_path / "nginx.conf"
    configuration.write_text("unused", encoding="utf-8")
    configuration.chmod(0o600)
    link = tmp_path / "linked"
    os.link(configuration, link)

    result = subprocess.run(
        [NPM_CHECKER, configuration], text=True, capture_output=True, check=False
    )

    assert result.returncode != 0
    assert "exactly one hard link" in result.stderr
