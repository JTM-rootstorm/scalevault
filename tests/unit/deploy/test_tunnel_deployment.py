"""Deployment checks for the fixed-identity ChatGPT tunnel."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "deploy/memory-node/systemd/kivra-memory-tunnel.service"
PREFLIGHT = ROOT / "deploy/memory-node/tunnel/kivra-memory-tunnel-preflight"
README = ROOT / "deploy/memory-node/tunnel/README.md"
ENV_EXAMPLE = ROOT / "deploy/memory-node/tunnel/tunnel.env.example"

TENANT_ID = "0198a8f0-1111-7000-8000-000000000001"
CREDENTIAL_ID = "0198a8f0-1111-7000-8000-000000000002"
SECRET = "A" * 43
AUTHORIZATION = f"Bearer svb1.{TENANT_ID}.{CREDENTIAL_ID}.{SECRET}"


def test_tunnel_unit_uses_fixed_authenticated_read_route() -> None:
    unit = UNIT.read_text(encoding="utf-8")

    target = "--mcp.server-url=url=http://127.0.0.1:8080/chatgpt/mcp,channel=main"
    header = '"Authorization: file:%d/chatgpt-mcp-authorization"'

    assert unit.count(target) == 2
    assert unit.count(f"--mcp.extra-headers={header}") == 2
    assert unit.count(f"--mcp.discovery-extra-headers={header}") == 2
    assert "LoadCredential=chatgpt-mcp-authorization:" in unit
    assert "http://127.0.0.1:8080/mcp,channel=main" not in unit
    assert "Bearer svb1." not in unit
    assert "RequiresMountsFor=/mnt/memory" not in unit
    assert "ConditionPathIsMountPoint=/mnt/memory" not in unit
    assert "--log.http-raw-unsafe" not in unit
    assert "--allow-remote-ui" not in unit
    assert "--open-web-ui" not in unit


def test_tunnel_unit_doctors_before_run_with_secret_environment_removed() -> None:
    unit = UNIT.read_text(encoding="utf-8")

    doctor = next(
        line
        for line in unit.splitlines()
        if line.startswith("ExecStartPre=/usr/local/bin/tunnel-client doctor")
    )
    run = next(
        line
        for line in unit.splitlines()
        if line.startswith("ExecStart=/usr/local/bin/tunnel-client run")
    )
    unset = " ".join(line for line in unit.splitlines() if line.startswith("UnsetEnvironment="))

    assert "/chatgpt/mcp" in doctor
    assert "/chatgpt/mcp" in run
    assert "OPENAI_API_KEY" in unset
    assert "CONTROL_PLANE_API_KEY" in unset
    assert "MCP_EXTRA_HEADERS" in unset
    assert "MCP_DISCOVERY_EXTRA_HEADERS" in unset
    assert "LOG_HTTP_RAW_UNSAFE" in unset
    assert "http_proxy" in unset
    assert "https_proxy" in unset
    assert "--log.file=stdout" in doctor
    assert "--log.file=stdout" in run


def test_tunnel_settings_and_documentation_expose_no_secret_value() -> None:
    example = ENV_EXAMPLE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    settings = [line for line in example.splitlines() if line and not line.startswith("#")]
    assert settings == ["CONTROL_PLANE_TUNNEL_ID=tunnel_REPLACE_WITH_32_LOWERCASE_HEX_CHARACTERS"]
    assert "Bearer svb1.<tenant-uuid7>.<credential-uuid7>." in readme
    assert AUTHORIZATION not in readme
    assert "never forwards" in readme
    assert "`/chatgpt/mcp`" in readme


def test_preflight_accepts_supported_client_and_exact_authorization(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_preflight_rejects_wrong_authorization_without_echoing_it(tmp_path: Path) -> None:
    malformed = "Bearer this-must-never-be-logged"
    result = _run_preflight(tmp_path, authorization=malformed)

    assert result.returncode != 0
    assert "invalid format" in result.stderr
    assert malformed not in result.stderr


def test_preflight_rejects_client_without_static_header_support(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, include_header_flags=False)

    assert result.returncode != 0
    assert "lacks static MCP request headers" in result.stderr


def test_preflight_rejects_unsupported_client_version(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, version="0.0.7+test")

    assert result.returncode != 0
    assert "0.0.8 or newer is required" in result.stderr


def test_preflight_rejects_noncanonical_tunnel_id(tmp_path: Path) -> None:
    tunnel_id = "tunnel_0123456789ABCDEF0123456789abcdef"
    result = _run_preflight(tmp_path, tunnel_id=tunnel_id)

    assert result.returncode != 0
    assert "32 lowercase hexadecimal" in result.stderr
    assert tunnel_id not in result.stderr


def _run_preflight(
    tmp_path: Path,
    *,
    authorization: str = AUTHORIZATION,
    include_header_flags: bool = True,
    tunnel_id: str = "tunnel_0123456789abcdef0123456789abcdef",
    version: str = "0.0.10+test",
) -> subprocess.CompletedProcess[str]:
    tunnel_client = tmp_path / "tunnel-client"
    flags = "--mcp.extra-headers --mcp.discovery-extra-headers" if include_header_flags else ""
    tunnel_client.write_text(
        "#!/bin/sh\n"
        'if [ "${1-}" = "--version" ]; then\n'
        f"  echo '{version}'\n"
        'elif [ "${1-}" = "run" ] && [ "${2-}" = "--help" ]; then\n'
        f"  echo '{flags}'\n"
        "else\n"
        "  exit 2\n"
        "fi\n",
        encoding="utf-8",
    )
    tunnel_client.chmod(0o755)
    control_plane = tmp_path / "control-plane-api-key"
    control_plane.write_text("sk-test-control-plane-credential\n", encoding="utf-8")
    chatgpt_authorization = tmp_path / "chatgpt-mcp-authorization"
    chatgpt_authorization.write_text(authorization + "\n", encoding="utf-8")

    environment = os.environ.copy()
    environment["CONTROL_PLANE_TUNNEL_ID"] = tunnel_id
    return subprocess.run(
        [
            str(PREFLIGHT),
            str(tunnel_client),
            str(control_plane),
            str(chatgpt_authorization),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
