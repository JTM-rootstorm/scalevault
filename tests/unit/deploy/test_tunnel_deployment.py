"""Deployment checks for the fixed-identity ChatGPT tunnel."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "deploy/memory-node/systemd/kivra-memory-tunnel.service"
PREFLIGHT = ROOT / "deploy/memory-node/tunnel/kivra-memory-tunnel-preflight"
MCP_PROBE = ROOT / "deploy/memory-node/tunnel/kivra-memory-tunnel-mcp-probe"
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

    assert unit.count(target) == 1
    assert unit.count(f"--mcp.extra-headers={header}") == 1
    assert unit.count(f"--mcp.discovery-extra-headers={header}") == 1
    assert "LoadCredential=chatgpt-mcp-authorization:" in unit
    assert "http://127.0.0.1:8080/mcp,channel=main" not in unit
    assert "Bearer svb1." not in unit
    assert "RequiresMountsFor=/mnt/memory" not in unit
    assert "ConditionPathIsMountPoint=/mnt/memory" not in unit
    assert "--log.http-raw-unsafe" not in unit
    assert "--allow-remote-ui" not in unit
    assert "--open-web-ui" not in unit


def test_tunnel_unit_probes_before_run_with_secret_environment_removed() -> None:
    unit = UNIT.read_text(encoding="utf-8")

    probe = next(
        line
        for line in unit.splitlines()
        if line.startswith("ExecStartPre=/usr/local/libexec/kivra-memory-tunnel-mcp-probe")
    )
    run = next(
        line
        for line in unit.splitlines()
        if line.startswith("ExecStart=/usr/local/bin/tunnel-client run")
    )
    unset = " ".join(line for line in unit.splitlines() if line.startswith("UnsetEnvironment="))

    assert "/chatgpt/mcp" in probe
    assert "/chatgpt/mcp" in run
    assert "OPENAI_API_KEY" in unset
    assert "CONTROL_PLANE_API_KEY" in unset
    assert "MCP_EXTRA_HEADERS" in unset
    assert "MCP_DISCOVERY_EXTRA_HEADERS" in unset
    assert "LOG_HTTP_RAW_UNSAFE" in unset
    assert "http_proxy" in unset
    assert "https_proxy" in unset
    assert "--log.file=stdout" in run
    assert "tunnel-client doctor" not in unit


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


def test_preflight_rejects_hard_linked_credential(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, hard_link_authorization=True)

    assert result.returncode != 0
    assert "exactly one hard link" in result.stderr
    assert AUTHORIZATION not in result.stderr


def test_preflight_rejects_group_readable_credential(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, authorization_mode=0o640)

    assert result.returncode != 0
    assert "must not grant group or other permissions" in result.stderr
    assert AUTHORIZATION not in result.stderr


def test_preflight_rejects_hard_linked_control_plane_credential(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, hard_link_control_plane=True)

    assert result.returncode != 0
    assert "exactly one hard link" in result.stderr


def test_preflight_rejects_group_readable_control_plane_credential(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, control_plane_mode=0o640)

    assert result.returncode != 0
    assert "must not grant group or other permissions" in result.stderr


def test_mcp_probe_keeps_authorization_out_of_argv_and_output(tmp_path: Path) -> None:
    result, arguments, config = _run_mcp_probe(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert AUTHORIZATION not in arguments
    assert config == f'header = "Authorization: {AUTHORIZATION}"\n'
    assert "http://127.0.0.1:8080/chatgpt/mcp" in arguments
    assert "--max-filesize\n65536\n" in arguments
    assert "--max-time\n20\n" in arguments
    assert "--show-error" not in arguments


def test_mcp_probe_rejects_bad_credential_without_calling_curl(tmp_path: Path) -> None:
    malformed = "Bearer do-not-log-this-value"
    result, arguments, _config = _run_mcp_probe(tmp_path, authorization=malformed)

    assert result.returncode != 0
    assert "invalid format" in result.stderr
    assert malformed not in result.stderr
    assert arguments == ""


def test_mcp_probe_fails_closed_on_non_success_http_status(tmp_path: Path) -> None:
    result, arguments, _config = _run_mcp_probe(tmp_path, curl_exit=22)

    assert result.returncode != 0
    assert "authenticated initialize request failed" in result.stderr
    assert AUTHORIZATION not in result.stderr
    assert AUTHORIZATION not in arguments


def test_mcp_probe_rejects_hard_linked_or_readable_by_group_credential(
    tmp_path: Path,
) -> None:
    linked, linked_arguments, _config = _run_mcp_probe(
        tmp_path / "linked", hard_link_authorization=True
    )
    readable, readable_arguments, _config = _run_mcp_probe(
        tmp_path / "readable", authorization_mode=0o640
    )

    assert linked.returncode != 0
    assert "exactly one hard link" in linked.stderr
    assert readable.returncode != 0
    assert "must not grant group or other permissions" in readable.stderr
    assert linked_arguments == readable_arguments == ""
    assert AUTHORIZATION not in linked.stderr
    assert AUTHORIZATION not in readable.stderr


def _run_preflight(
    tmp_path: Path,
    *,
    authorization: str = AUTHORIZATION,
    include_header_flags: bool = True,
    tunnel_id: str = "tunnel_0123456789abcdef0123456789abcdef",
    version: str = "0.0.10+test",
    authorization_mode: int = 0o600,
    hard_link_authorization: bool = False,
    control_plane_mode: int = 0o600,
    hard_link_control_plane: bool = False,
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
    control_plane.chmod(control_plane_mode)
    if hard_link_control_plane:
        os.link(control_plane, tmp_path / "control-plane-api-key-linked")
    chatgpt_authorization = tmp_path / "chatgpt-mcp-authorization"
    chatgpt_authorization.write_text(authorization + "\n", encoding="utf-8")
    chatgpt_authorization.chmod(authorization_mode)
    if hard_link_authorization:
        os.link(chatgpt_authorization, tmp_path / "chatgpt-mcp-authorization-linked")

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


def _run_mcp_probe(
    tmp_path: Path,
    *,
    authorization: str = AUTHORIZATION,
    curl_exit: int = 0,
    authorization_mode: int = 0o600,
    hard_link_authorization: bool = False,
) -> tuple[subprocess.CompletedProcess[str], str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    arguments_path = tmp_path / "curl-arguments"
    config_path = tmp_path / "curl-config"
    curl_command = tmp_path / "curl"
    curl_command.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" > "$PROBE_ARGUMENTS_PATH"\n'
        'cat > "$PROBE_CONFIG_PATH"\n'
        'exit "$PROBE_CURL_EXIT"\n',
        encoding="utf-8",
    )
    curl_command.chmod(0o755)
    credential = tmp_path / "chatgpt-mcp-authorization"
    credential.write_text(authorization + "\n", encoding="utf-8")
    credential.chmod(authorization_mode)
    if hard_link_authorization:
        os.link(credential, tmp_path / "chatgpt-mcp-authorization-linked")
    environment = os.environ.copy()
    environment["PROBE_ARGUMENTS_PATH"] = str(arguments_path)
    environment["PROBE_CONFIG_PATH"] = str(config_path)
    environment["PROBE_CURL_EXIT"] = str(curl_exit)

    result = subprocess.run(
        [
            str(MCP_PROBE),
            str(curl_command),
            str(credential),
            "http://127.0.0.1:8080/chatgpt/mcp",
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    arguments = arguments_path.read_text(encoding="utf-8") if arguments_path.exists() else ""
    config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    return result, arguments, config
