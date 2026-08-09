from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import Settings
from kivra_memory.runtime.composition import (
    MemoryNodeRuntime,
    _read_client_token_pepper,
)
from pydantic import PostgresDsn

DATABASE_URL = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")


def credential(tmp_path: Path, value: bytes = b"p" * 32) -> Path:
    path = tmp_path / "client-token-pepper"
    path.write_bytes(value)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("size", [32, 64, 128])
def test_pepper_reader_accepts_bounded_private_regular_file(tmp_path: Path, size: int) -> None:
    path = credential(tmp_path, b"p" * size)

    assert _read_client_token_pepper(path, required_owner_uid=os.getuid()) == b"p" * size


def test_pepper_reader_accepts_systemd_materialized_mode(tmp_path: Path) -> None:
    path = credential(tmp_path)
    path.chmod(0o400)

    assert _read_client_token_pepper(path, required_owner_uid=os.geteuid()) == b"p" * 32


@pytest.mark.parametrize("size", [31, 129])
def test_pepper_reader_rejects_out_of_bounds_secret(tmp_path: Path, size: int) -> None:
    path = credential(tmp_path, b"p" * size)

    with pytest.raises(ValueError):
        _read_client_token_pepper(path, required_owner_uid=None)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_pepper_reader_rejects_group_or_world_permissions(tmp_path: Path, mode: int) -> None:
    path = credential(tmp_path)
    path.chmod(mode)

    with pytest.raises(ValueError):
        _read_client_token_pepper(path, required_owner_uid=None)


def test_pepper_reader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    path = credential(tmp_path)
    symlink = tmp_path / "pepper-symlink"
    symlink.symlink_to(path)
    hardlink = tmp_path / "pepper-hardlink"
    hardlink.hardlink_to(path)

    with pytest.raises(ValueError):
        _read_client_token_pepper(symlink, required_owner_uid=None)
    with pytest.raises(ValueError):
        _read_client_token_pepper(path, required_owner_uid=None)


def test_pepper_reader_rejects_non_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "pepper-directory"
    directory.mkdir(mode=0o700)

    with pytest.raises(ValueError):
        _read_client_token_pepper(directory, required_owner_uid=None)


def test_pepper_reader_rejects_unexpected_owner(tmp_path: Path) -> None:
    path = credential(tmp_path)

    with pytest.raises(ValueError):
        _read_client_token_pepper(path, required_owner_uid=os.getuid() + 1)


def test_pepper_reader_rejects_size_change_during_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = credential(tmp_path)
    real_fstat = os.fstat

    def changed_size(descriptor: int) -> object:
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_nlink=metadata.st_nlink,
            st_uid=metadata.st_uid,
            st_size=metadata.st_size + 1,
        )

    monkeypatch.setattr("kivra_memory.runtime.composition.os.fstat", changed_size)

    with pytest.raises(ValueError):
        _read_client_token_pepper(path, required_owner_uid=None)


@pytest.mark.parametrize(
    "settings",
    [
        Settings.model_construct(
            environment="test",
            database_url=None,
            client_token_pepper_credential=Path("/unused"),
            client_token_pepper_key_id="codex-primary-v1",
        ),
        Settings.model_construct(
            environment="test",
            database_url=DATABASE_URL,
            client_token_pepper_credential=None,
            client_token_pepper_key_id="codex-primary-v1",
        ),
        Settings.model_construct(
            environment="test",
            database_url=DATABASE_URL,
            client_token_pepper_credential=Path("/unused"),
            client_token_pepper_key_id=None,
        ),
    ],
)
def test_runtime_composition_defensively_rejects_missing_dependencies(settings: Settings) -> None:
    with pytest.raises(RuntimeError, match=r"^invalid_runtime_configuration$"):
        MemoryNodeRuntime.from_settings(
            settings,
            sealed_runtime=SealedRuntime(key_provider=None, digest_binder=None),
        )


def test_runtime_composition_sanitizes_credential_failure(tmp_path: Path) -> None:
    sentinel = "PRIVATE-PATH-MUST-NOT-APPEAR"
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        client_token_pepper_credential=tmp_path / sentinel,
        client_token_pepper_key_id="codex-primary-v1",
    )

    with pytest.raises(RuntimeError) as caught:
        MemoryNodeRuntime.from_settings(
            settings,
            sealed_runtime=SealedRuntime(key_provider=None, digest_binder=None),
        )

    assert str(caught.value) == "invalid_runtime_configuration"
    assert sentinel not in str(caught.value)


async def test_runtime_composition_installs_only_configured_pepper_key(
    tmp_path: Path,
) -> None:
    path = credential(tmp_path)
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        client_token_pepper_credential=path,
        client_token_pepper_key_id="direct-client-v7",
    )

    runtime = MemoryNodeRuntime.from_settings(
        settings,
        sealed_runtime=SealedRuntime(key_provider=None, digest_binder=None),
    )
    hashers = vars(runtime.authenticator)["_hashers"]

    assert set(hashers) == {"direct-client-v7"}
    await runtime.dispose()


async def test_production_composition_requires_effective_service_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_construct(
        environment="production",
        database_url=DATABASE_URL,
        client_token_pepper_credential=Path(
            "/run/credentials/kivra-memory-api.service/client-token-pepper"
        ),
        client_token_pepper_key_id="codex-primary-v1",
    )
    seen_owner: list[int | None] = []

    def reject_after_capture(path: Path, *, required_owner_uid: int | None) -> bytes:
        del path
        seen_owner.append(required_owner_uid)
        raise ValueError

    monkeypatch.setattr(
        "kivra_memory.runtime.composition._read_client_token_pepper",
        reject_after_capture,
    )

    with pytest.raises(RuntimeError, match=r"^invalid_runtime_configuration$"):
        MemoryNodeRuntime.from_settings(
            settings,
            sealed_runtime=SealedRuntime(key_provider=None, digest_binder=None),
        )

    assert seen_owner == [os.geteuid()]
