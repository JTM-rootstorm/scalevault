"""Static deployment checks for the private Codex MCP ingress."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "deploy/memory-node/systemd/kivra-memory-codex-ingress.service"
DEPLOY_ROOT = ROOT / "deploy/memory-node/private-ingress"
ENV_EXAMPLE = DEPLOY_ROOT / "memory-codex-ingress.env.example"
NETWORK_EXAMPLE = DEPLOY_ROOT / "kivra-memory-codex-ingress-network.conf.example"
NPM_EXAMPLE = DEPLOY_ROOT / "npm-location.conf.example"
README = DEPLOY_ROOT / "README.md"
SEALED_DROP_IN = (
    ROOT / "deploy/memory-node/systemd/sealed-content/"
    "kivra-memory-codex-ingress.service.d/20-sealed-content.conf"
)


def test_unit_is_independent_direct_only_and_credential_scoped() -> None:
    unit = UNIT.read_text(encoding="utf-8")

    assert "ExecStart=/opt/kivra-memory/app/.venv/bin/kivra-memory-codex-ingress" in unit
    assert "EnvironmentFile=/etc/kivra-memory/memory-codex-ingress.env" in unit
    assert "User=memory-api" in unit
    assert "Group=kivra-memory" in unit
    assert "Requires=postgresql@17-main.service" in unit
    assert "kivra-memory-tunnel.service" not in unit
    assert "kivra-memory-api.service" not in unit
    assert "KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_ENABLED" in unit
    assert "KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_INSTALLATION_ID" in unit

    credential_root = "/run/credentials/kivra-memory-codex-ingress.service/"
    assert f"{credential_root}client-token-pepper" in unit
    assert unit.count("LoadCredential=client-token-pepper:") == 1
    assert "CODEX_INGRESS_TLS" not in unit
    assert "backend-tls" not in unit


def test_unit_fails_closed_until_exact_network_override_is_installed() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    override = NETWORK_EXAMPLE.read_text(encoding="utf-8")

    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=localhost" in unit
    assert "SocketBindDeny=any" in unit
    assert "SocketBindAllow=tcp:8443" in unit
    assert "ProtectProc=invisible" in unit
    assert "ProcSubset=pid" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "IPAddressAllow=REPLACE_WITH_EXACT_NPM_EGRESS_CIDR" in override
    assert "/32" in override
    assert "/128" in override


def test_environment_template_freezes_profile_port_and_exact_placeholders() -> None:
    example = ENV_EXAMPLE.read_text(encoding="utf-8")
    settings = {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in example.splitlines()
        if line and not line.startswith("#")
    }

    assert settings["KIVRA_MEMORY_SERVER_PROFILE"] == "codex_private_ingress"
    assert settings["KIVRA_MEMORY_CODEX_INGRESS_PORT"] == "8443"
    assert settings["KIVRA_MEMORY_CODEX_INGRESS_HOST"] == ("REPLACE_WITH_EXACT_PRIVATE_LISTENER_IP")
    assert settings["KIVRA_MEMORY_CODEX_INGRESS_EXTERNAL_HOSTNAME"] == (
        "REPLACE_WITH_PRIVATE_TLS_HOSTNAME"
    )
    assert settings["KIVRA_MEMORY_CODEX_INGRESS_TRUSTED_PROXY_CIDRS"] == (
        "'[\"REPLACE_WITH_EXACT_NPM_EGRESS_CIDR\"]'"
    )
    assert settings["KIVRA_MEMORY_CODEX_INGRESS_MAX_CONCURRENCY"] == "4"
    assert settings["KIVRA_MEMORY_METRICS_ENABLED"] == "false"
    assert "CLIENT_CIDRS" not in example
    assert "0.0.0.0" not in example
    assert "proxy" not in settings["KIVRA_MEMORY_DATABASE_URL"].lower()


def test_npm_template_is_exact_verified_bounded_and_never_retries() -> None:
    template = NPM_EXAMPLE.read_text(encoding="utf-8")
    template_prose = " ".join(template.split())

    pre_location, locations = template.split("location = /mcp", maxsplit=1)
    exact_location, catch_all = locations.split("location /", maxsplit=1)
    assert "Remove every NPM Custom Location" in template_prose
    assert "Proxy Host's Advanced field after" in template_prose
    assert "access_log off;" not in pre_location
    assert "access_log off;" in exact_location
    assert "access_log off;" in catch_all
    assert "location = /mcp" in template
    assert "location /" in template
    assert "return 404" in template
    assert "allow REPLACE_WITH_APPROVED_LAN_OR_VPN_CIDR" in template
    assert "deny all" in template
    assert "if ($scheme != https) { return 404; }" in template
    assert "if ($request_uri != /mcp) { return 404; }" in template
    assert "proxy_pass http://REPLACE_WITH_EXACT_BACKEND_PRIVATE_IP:8443/mcp" in template
    assert "proxy_ssl_" not in template
    assert "PINNED_BACKEND_CA" not in template
    assert "proxy_pass_request_headers off" in template
    assert "proxy_next_upstream off" in template
    assert "proxy_redirect off" in template
    assert "client_max_body_size 1m" in template
    assert "client_body_buffer_size 1m" in template
    assert "proxy_connect_timeout 5s" in template
    assert "proxy_send_timeout 30s" in template
    assert "proxy_read_timeout 310s" in template
    assert "proxy_request_buffering on" in template
    assert "proxy_buffering off" in template
    assert "gzip off" in template
    assert "access_log off" in template
    assert "proxy_cache off" in template


def test_npm_template_reconstructs_only_allowlisted_nonforwarding_headers() -> None:
    template = NPM_EXAMPLE.read_text(encoding="utf-8")
    reconstructed = re.findall(r"^\s*proxy_set_header\s+([^ ]+)", template, re.MULTILINE)

    assert set(reconstructed) == {
        "Host",
        "Authorization",
        "Origin",
        "Accept",
        "Content-Type",
        "Content-Length",
        "MCP-Protocol-Version",
        "MCP-Session-Id",
        "Last-Event-ID",
        "Connection",
    }
    assert not any(name.lower().startswith("x-forwarded-") for name in reconstructed)
    assert "Forwarded" not in reconstructed
    assert "Via" not in reconstructed
    assert "X-Real-IP" not in reconstructed


def test_runbook_requires_live_private_and_no_payload_log_evidence() -> None:
    readme = README.read_text(encoding="utf-8")
    prose = " ".join(readme.split())

    assert "`/32` or `/128`" in readme
    assert "LXC firewall" in readme
    assert "no upstream retry" in readme
    assert "GET/SSE" in readme
    assert "mutation is never retried" in readme
    assert "no Authorization value, MCP body" in readme
    assert "non-VPN external network" in readme
    assert "Private DNS absence alone is not proof" in prose
    assert "exact private HTTP upstream" in prose
    assert "NPM-generated `Forwarded`, `Via`" in readme
    assert "`X-Real-IP`, or `X-Forwarded-*`" in readme
    assert "never uses them as" in readme
    assert "custom CA handoff" in readme
    assert "Disable Force SSL redirects" in readme
    assert "Client HTTP must never redirect" in readme
    assert "complete `nginx -T` output" in readme
    assert "Global `real_ip_header`, `set_real_ip_from`, `real_ip_recursive`" in readme
    assert "spoofed LAN values" in readme
    assert "`Forwarded`, `X-Forwarded-For`, and `X-Real-IP`" in readme
    assert "shared or public edge listener is acceptable only" in readme
    assert "paste the entire template into the Proxy Host's" in prose
    assert "remove every NPM Custom Location" in prose
    assert "does not inject the UI Access List" in prose
    assert "scheme `http`" in readme
    assert "exactly the template's `location = /mcp`" in prose
    assert "no generated proxy catch-all" in prose
    assert "must not include NPM's Force SSL configuration" in prose
    assert "access logging is disabled inside both owned locations" in prose
    assert "before selecting or connecting" in readme
    assert "hard 30-second" in readme
    assert "hard five-minute GET/SSE" in readme
    assert "multi-process atomicity test" in readme
    assert "backend connection or firewall counter must remain at zero" in prose
    assert "never spooled to a temporary file" in prose


def test_optional_sealed_drop_in_uses_ingress_credential_namespace() -> None:
    drop_in = SEALED_DROP_IN.read_text(encoding="utf-8")

    assert "SupplementaryGroups=kivra-sealed" in drop_in
    assert "LoadCredential=sealed-digest-binding:" in drop_in
    assert "KIVRA_MEMORY_SEALED_CONTENT_ENABLED=true" in drop_in
    assert "KIVRA_MEMORY_SEALED_KEY_PROVIDER_ROOT=/var/lib/kivra-memory-sealed/keys" in drop_in
    assert (
        "KIVRA_MEMORY_SEALED_DIGEST_BINDING_CREDENTIAL="
        "/run/credentials/kivra-memory-codex-ingress.service/sealed-digest-binding"
    ) in drop_in
    assert "/run/credentials/kivra-memory-api.service/" not in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/control" in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/material" in drop_in


def test_private_ingress_artifacts_contain_no_completed_external_coordinates() -> None:
    artifacts = [UNIT, ENV_EXAMPLE, NETWORK_EXAMPLE, NPM_EXAMPLE, README, SEALED_DROP_IN]
    text = "\n".join(path.read_text(encoding="utf-8") for path in artifacts)

    assert "REPLACE_WITH_EXACT_PRIVATE_LISTENER_IP" in text
    assert "REPLACE_WITH_PRIVATE_TLS_HOSTNAME" in text
    assert "REPLACE_WITH_EXACT_NPM_EGRESS_CIDR" in text
    assert re.search(r"(?<![A-Z_])(?:10|172|192)\.\d+\.\d+\.\d+", text) is None
    assert re.search(r"(?<!REPLACE_WITH_)PRIVATE_TLS_HOSTNAME=[^R\n]", text) is None
