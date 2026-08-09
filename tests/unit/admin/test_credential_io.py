from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from kivra_memory.admin.credential_io import (
    CredentialAdminSettings,
    load_or_create_authorization,
    write_one_time_secret,
)
from kivra_memory.admin.credentials import CredentialAdminError
from kivra_memory.auth import BearerTokenCodec, BearerTokenHasher
from kivra_memory.domain.identifiers import new_uuid7


def _protected_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def _settings(tmp_path: Path, *, database_url: str | None = None) -> CredentialAdminSettings:
    database = _protected_file(
        tmp_path / "database-url",
        (
            database_url
            or "postgresql+psycopg://kivra_memory_credential_admin:secret@127.0.0.1/kivra_memory"
        ).encode(),
    )
    pepper = _protected_file(tmp_path / "pepper", bytes(range(32)))
    config = _protected_file(
        tmp_path / "admin.json",
        json.dumps(
            {
                "database_url_file": str(database),
                "secret_hash_key_id": "codex-primary-v1",
                "token_pepper_file": str(pepper),
            },
            separators=(",", ":"),
        ).encode(),
    )
    return CredentialAdminSettings.from_file(config)


def test_settings_load_only_protected_files_and_redact_secrets(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    assert settings.secret_hash_key_id == "codex-primary-v1"
    assert settings.token_pepper == bytes(range(32))
    assert ":secret@" not in repr(settings)
    assert bytes(range(32)).hex() not in repr(settings)


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://kivra_memory_api@127.0.0.1/kivra_memory",
        "postgresql+psycopg://kivra_memory_credential_admin@example.invalid/kivra_memory",
        "sqlite:///tmp/test.db",
    ],
)
def test_settings_reject_wrong_role_and_nonlocal_database(
    tmp_path: Path, database_url: str
) -> None:
    with pytest.raises(CredentialAdminError, match="configuration_invalid"):
        _settings(tmp_path, database_url=database_url)


def test_settings_reject_symlink_duplicate_fields_and_weak_modes(tmp_path: Path) -> None:
    database = _protected_file(
        tmp_path / "database",
        b"postgresql+psycopg://kivra_memory_credential_admin@127.0.0.1/kivra_memory",
    )
    pepper = _protected_file(tmp_path / "pepper", b"p" * 32)
    config = _protected_file(
        tmp_path / "config.json",
        (
            '{"database_url_file":"'
            + str(database)
            + '","database_url_file":"'
            + str(database)
            + '","secret_hash_key_id":"primary","token_pepper_file":"'
            + str(pepper)
            + '"}'
        ).encode(),
    )
    with pytest.raises(CredentialAdminError, match="configuration_invalid"):
        CredentialAdminSettings.from_file(config)

    config.unlink()
    target = _protected_file(tmp_path / "target.json", b"{}")
    config.symlink_to(target)
    with pytest.raises(CredentialAdminError, match="configuration_invalid"):
        CredentialAdminSettings.from_file(config)

    config.unlink()
    _protected_file(config, b"{}").chmod(0o640)
    with pytest.raises(CredentialAdminError, match="configuration_invalid"):
        CredentialAdminSettings.from_file(config)


def test_settings_reject_invalid_key_id(tmp_path: Path) -> None:
    database = _protected_file(
        tmp_path / "database",
        b"postgresql+psycopg://kivra_memory_credential_admin@127.0.0.1/kivra_memory",
    )
    pepper = _protected_file(tmp_path / "pepper", b"p" * 32)
    config = _protected_file(
        tmp_path / "config.json",
        json.dumps(
            {
                "database_url_file": str(database),
                "secret_hash_key_id": "INVALID KEY ID",
                "token_pepper_file": str(pepper),
            }
        ).encode(),
    )

    with pytest.raises(CredentialAdminError, match="configuration_invalid"):
        CredentialAdminSettings.from_file(config)


def test_one_time_secret_is_atomic_mode_0600_and_never_overwrites(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    output = protected / "codex-token"
    token = "svb1." + "a" * 120

    write_one_time_secret(output, token)

    assert output.read_text() == token + "\n"
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CredentialAdminError, match="secret_output_failed"):
        write_one_time_secret(output, "svb1." + "b" * 120)
    assert output.read_text() == token + "\n"
    assert not tuple(protected.glob(".credential-*.tmp"))


def test_authorization_artifact_is_retry_safe_and_never_replaced(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    output = protected / "chatgpt-authorization"
    issued = BearerTokenCodec.issue(
        new_uuid7(),
        new_uuid7(),
        BearerTokenHasher(bytes(range(32))),
    )
    authorization = f"Bearer {issued.token}"
    other = BearerTokenCodec.issue(
        new_uuid7(),
        new_uuid7(),
        BearerTokenHasher(bytes(range(32))),
    )

    assert load_or_create_authorization(output, authorization) == authorization
    assert load_or_create_authorization(output, f"Bearer {other.token}") == authorization
    assert output.read_text() == authorization + "\n"
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_nlink == 1


@pytest.mark.parametrize("contents", [b"svb1.not-an-authorization\n", b"Bearer bad\r\n"])
def test_authorization_artifact_rejects_invalid_existing_content(
    tmp_path: Path,
    contents: bytes,
) -> None:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    output = _protected_file(protected / "chatgpt-authorization", contents)
    issued = BearerTokenCodec.issue(
        new_uuid7(),
        new_uuid7(),
        BearerTokenHasher(bytes(range(32))),
    )

    with pytest.raises(CredentialAdminError, match="secret_output_failed"):
        load_or_create_authorization(output, f"Bearer {issued.token}")
    assert output.read_bytes() == contents


def test_one_time_secret_rejects_symlink_and_unprotected_parent(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    target = protected / "target"
    target.write_text("sentinel")
    output = protected / "token"
    output.symlink_to(target)

    with pytest.raises(CredentialAdminError, match="secret_output_failed"):
        write_one_time_secret(output, "svb1." + "a" * 120)
    assert target.read_text() == "sentinel"

    output.unlink()
    protected.chmod(0o750)
    with pytest.raises(CredentialAdminError, match="secret_output_failed"):
        write_one_time_secret(output, "svb1." + "a" * 120)
    assert not output.exists()


def test_one_time_secret_cleans_reservation_and_temporary_on_publish_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    output = protected / "token"

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(CredentialAdminError, match="secret_output_failed"):
        write_one_time_secret(output, "svb1." + "a" * 120)

    assert not output.exists()
    assert not tuple(protected.iterdir())


def test_settings_do_not_consume_secret_environment_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KIVRA_MEMORY_TOKEN_PEPPER", "ENVIRONMENT-CANARY")
    settings = _settings(tmp_path)

    assert settings.token_pepper == bytes(range(32))
    assert "ENVIRONMENT-CANARY" not in repr(settings)
