"""Static deployment checks for the private Codex MCP ingress."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
UNIT = ROOT / "deploy/memory-node/systemd/kivra-memory-codex-ingress.service"
DEPLOY_ROOT = ROOT / "deploy/memory-node/private-ingress"
ENV_EXAMPLE = DEPLOY_ROOT / "memory-codex-ingress.env.example"
NETWORK_EXAMPLE = DEPLOY_ROOT / "kivra-memory-codex-ingress-network.conf.example"
NPM_HOST_ADVANCED = DEPLOY_ROOT / "npm-host-advanced.conf.example"
NPM_MCP_ADVANCED = DEPLOY_ROOT / "npm-mcp-custom-location-advanced.conf.example"
README = DEPLOY_ROOT / "README.md"
ADR_INDEX = ROOT / "docs/adr/README.md"
ADR_0022 = ROOT / "docs/adr/0022-private-single-owner-access-topology.md"
ADR_0024 = ROOT / "docs/adr/0024-dedicated-private-codex-ingress.md"
ADR_0025 = ROOT / "docs/adr/0025-proxy-terminated-tls-for-private-ingress.md"
ADR_0026 = ROOT / "docs/adr/0026-npm-static-acme-renewal-exception.md"
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
    host = NPM_HOST_ADVANCED.read_text(encoding="utf-8")
    location = NPM_MCP_ADVANCED.read_text(encoding="utf-8")

    pre_location, _ = host.split("location ~ ^/(?!mcp$) {", maxsplit=1)
    assert "location ~ ^/(?!mcp$) {" in host
    assert "location / {" not in host
    assert host.count("set_real_ip_from unix:;") == 1
    assert host.count("real_ip_recursive off;") == 1
    assert "set_real_ip_from unix:;" in pre_location
    assert "real_ip_recursive off;" in pre_location
    assert "10.0.0.0/8" not in host
    assert "172.16.0.0/12" not in host
    assert "192.168.0.0/16" not in host
    assert "access_log off;" not in pre_location
    assert "access_log off;" in host
    assert "return 404" in host
    assert "proxy_pass" not in host
    assert "location " not in location
    assert "proxy_pass " not in location
    assert "allow " not in location
    assert "deny " not in location
    assert "if ($scheme != https) { return 404; }" in location
    assert "if ($request_method !~ ^(GET|POST|DELETE)$) { return 405; }" in location
    assert "if ($request_uri != /mcp) { return 404; }" in location
    assert "proxy_ssl_" not in location
    assert "PINNED_BACKEND_CA" not in location
    assert "proxy_pass_request_headers off" in location
    assert "proxy_next_upstream off" in location
    assert "proxy_redirect off" in location
    assert "client_max_body_size 1m" in location
    assert "client_body_buffer_size 1m" in location
    assert "proxy_connect_timeout 5s" in location
    assert "proxy_send_timeout 30s" in location
    assert "proxy_read_timeout 310s" in location
    assert "proxy_request_buffering on" in location
    assert "proxy_buffering off" in location
    assert "gzip off" in location
    assert "access_log off" in location
    assert "proxy_cache off" in location


def test_npm_template_reconstructs_only_allowlisted_nonforwarding_headers() -> None:
    template = NPM_MCP_ADVANCED.read_text(encoding="utf-8")
    reconstructed = re.findall(r"^\s*proxy_set_header\s+([^ ]+)", template, re.MULTILINE)

    assert set(reconstructed) == {
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
    assert "ScaleVault client HTTP must receive" in prose
    assert "Client HTTP application requests must never redirect" in prose
    assert "complete `nginx -T` output" in readme
    assert "Global `real_ip_header`, `set_real_ip_from`, `real_ip_recursive`" in readme
    assert "`set_real_ip_from unix:;` and `real_ip_recursive off;`" in prose
    assert "replaces NPM's inherited broad RFC1918 trust" in prose
    assert "must also contain exactly one `set_real_ip_from unix:;`" in prose
    assert "changes from edge `403` to backend `401`" in prose
    assert "spoofed LAN values" in readme
    assert "`Forwarded`, `X-Forwarded-For`, and `X-Real-IP`" in readme
    assert "shared or public edge listener is acceptable only" in readme
    assert "exactly one NPM Custom Location" in prose
    assert "source CIDRs only" in prose
    assert "Block Common Exploits" in readme
    assert "renders the attached UI Access List" in prose
    assert "loopback TCP port proven closed" in prose
    assert "scheme `http`" in readme
    assert "exactly one NPM-rendered `location /mcp`" in prose
    assert "deny-only Advanced regex location" in prose
    assert "verified-closed loopback target" in prose
    assert "generated Let's Encrypt handler" in prose
    assert "non-LAN/VPN ScaleVault application request" in prose
    assert "static ACME prefix is tested separately" in prose
    assert "exact installed NPM and Nginx versions" in prose
    assert "immutable NPM container image digest" in prose
    assert "location ^~ /.well-known/acme-challenge/" in prose
    assert "location = /.well-known/acme-challenge/" in prose
    assert "A valid provisioned token may return `200`" in prose
    assert "Generated configuration must show the distinct" in prose
    assert "static-only and has no upstream" in prose
    assert "ScaleVault application probe" in prose
    assert "excluded from this application-route assertion" in prose
    assert "must not include NPM's Force SSL configuration" in prose
    assert "or `block-exploits.conf`" in prose
    assert "access logging is disabled inside both owned locations" in prose
    assert "before selecting or connecting" in readme
    assert "hard 30-second" in readme
    assert "hard five-minute GET/SSE" in readme
    assert "multi-process atomicity test" in readme
    assert "backend connection or firewall counter must remain at zero" in prose
    assert "unapproved LAN/VPN source" in prose
    assert "Status codes need not match" in prose
    assert "never spooled to a temporary file" in prose


def test_acme_exception_is_accepted_precise_and_amends_prior_contracts() -> None:
    index = ADR_INDEX.read_text(encoding="utf-8")
    adr_0022 = ADR_0022.read_text(encoding="utf-8")
    adr_0024 = ADR_0024.read_text(encoding="utf-8")
    adr_0025 = ADR_0025.read_text(encoding="utf-8")
    adr_0026 = ADR_0026.read_text(encoding="utf-8")

    assert "[0026](0026-npm-static-acme-renewal-exception.md) | Accepted" in index
    assert "Amended by: ADR 0024, ADR 0025, and ADR 0026" in adr_0022
    assert "Amended by: ADR 0025 and ADR 0026" in adr_0024
    assert "Amended by: ADR 0026" in adr_0025
    assert "- Status: Accepted" in adr_0026
    assert "Amends: ADR 0022, ADR 0024, and ADR 0025" in adr_0026
    assert "location ^~ /.well-known/acme-challenge/" in adr_0026
    assert "location = /.well-known/acme-challenge/" in adr_0026
    assert "dedicated static ACME webroot" in adr_0026
    assert "authentication disabled and `allow all`" in adr_0026
    assert "neither location contains `proxy_pass`" in adr_0026.lower()
    assert "valid provisioned challenge token may return `200`" in adr_0026
    assert "generated configuration proves the prefix is static-only" in adr_0026
    assert "exact installed NPM and Nginx versions" in adr_0026
    assert "immutable NPM container image digest" in adr_0026


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
    artifacts = [
        UNIT,
        ENV_EXAMPLE,
        NETWORK_EXAMPLE,
        NPM_HOST_ADVANCED,
        NPM_MCP_ADVANCED,
        README,
        SEALED_DROP_IN,
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in artifacts)

    assert "REPLACE_WITH_EXACT_PRIVATE_LISTENER_IP" in text
    assert "REPLACE_WITH_PRIVATE_TLS_HOSTNAME" in text
    assert "REPLACE_WITH_EXACT_NPM_EGRESS_CIDR" in text
    assert re.search(r"(?<![A-Z_])(?:10|172|192)\.\d+\.\d+\.\d+", text) is None
    assert re.search(r"(?<!REPLACE_WITH_)PRIVATE_TLS_HOSTNAME=[^R\n]", text) is None
