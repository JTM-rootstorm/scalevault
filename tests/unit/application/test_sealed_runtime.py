from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import Settings
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
)


def _key_root(tmp_path: Path) -> Path:
    root = tmp_path / "sealed-keys"
    root.mkdir(mode=0o710)
    root.chmod(0o2710)
    for directory_name in (CONTROL_DIRECTORY_NAME, MATERIAL_DIRECTORY_NAME):
        directory = root / directory_name
        directory.mkdir(mode=0o770)
        directory.chmod(0o2770)
    return root


def _binding_credential(tmp_path: Path, secret: bytes = b"b" * 32) -> Path:
    credential = tmp_path / "sealed-digest-binding"
    credential.write_bytes(secret)
    credential.chmod(0o600)
    return credential


def test_disabled_runtime_does_not_claim_sealed_content_support() -> None:
    runtime = SealedRuntime.from_settings(Settings())

    assert runtime.enabled is False
    assert runtime.key_provider is None
    assert runtime.digest_binder is None


def test_enabled_runtime_injects_same_provider_into_selection_and_reads(tmp_path: Path) -> None:
    runtime = SealedRuntime.from_settings(
        Settings(
            sealed_content_enabled=True,
            sealed_key_provider_root=_key_root(tmp_path),
            sealed_digest_binding_credential=_binding_credential(tmp_path),
        )
    )
    session_factory = MagicMock()
    resolver = MagicMock()
    repository_factory = MagicMock()

    selection = runtime.selection_engine(session_factory, resolver)
    query = runtime.query_engine(session_factory, repository_factory)

    assert runtime.enabled is True
    assert selection._key_provider is runtime.key_provider
    assert selection._sealed_digest_binder is runtime.digest_binder
    assert query._key_provider is runtime.key_provider


def test_enabled_runtime_fails_closed_for_invalid_provider_root(tmp_path: Path) -> None:
    root = _key_root(tmp_path)
    root.chmod(0o2777)
    settings = Settings(
        sealed_content_enabled=True,
        sealed_key_provider_root=root,
        sealed_digest_binding_credential=_binding_credential(tmp_path),
    )

    with pytest.raises(RuntimeError, match="invalid_sealed_content_configuration"):
        SealedRuntime.from_settings(settings)


def test_digest_credential_is_bounded_canonical_and_never_reflected(tmp_path: Path) -> None:
    root = _key_root(tmp_path)
    credential = _binding_credential(tmp_path, b"sensitive-canary")
    settings = Settings(
        sealed_content_enabled=True,
        sealed_key_provider_root=root,
        sealed_digest_binding_credential=credential,
    )

    with pytest.raises(RuntimeError) as caught:
        SealedRuntime.from_settings(settings)
    assert str(caught.value) == "invalid_sealed_content_configuration"
    assert "sensitive-canary" not in str(caught.value)

    credential.unlink()
    target = _binding_credential(tmp_path, b"x" * 32)
    target.rename(tmp_path / "binding-target")
    credential.symlink_to(tmp_path / "binding-target")
    with pytest.raises(RuntimeError, match="invalid_sealed_content_configuration"):
        SealedRuntime.from_settings(settings)
