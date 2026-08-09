from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def test_api_uses_bounded_systemd_pepper_credential_without_secret_environment() -> None:
    drop_in = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/client-auth/"
        "kivra-memory-api.service.d/30-client-token-auth.conf"
    ).read_text()
    base_unit = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/kivra-memory-api.service"
    ).read_text()

    assert (
        "LoadCredential=client-token-pepper:/etc/kivra-memory/client-token-pepper"
        in drop_in
    )
    assert (
        "KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_CREDENTIAL="
        "/run/credentials/kivra-memory-api.service/client-token-pepper"
        in drop_in
    )
    assert "client-token-pepper" not in base_unit
    assert "KIVRA_MEMORY_CLIENT_TOKEN_PEPPER=" not in drop_in
    assert "KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_KEY_ID=codex-primary-v1" in drop_in


def test_operator_documentation_uses_protected_files_and_explicit_secret_output() -> None:
    documentation = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/README.md"
    ).read_text()

    assert '"database_url_file"' in documentation
    assert '"token_pepper_file"' in documentation
    assert "--secret-output" in documentation
    assert "--secret-stdout" in documentation
    assert "never placed in an environment variable" in documentation
    assert "mode-`0600`" in documentation
    assert "Legacy aggregate or observe/remember/revise scopes" in documentation


def test_console_entry_is_registered() -> None:
    project = REPOSITORY_ROOT.joinpath("pyproject.toml").read_text()

    assert (
        'kivra-memory-credential-admin = "kivra_memory.admin.credentials_main:main"'
        in project
    )
