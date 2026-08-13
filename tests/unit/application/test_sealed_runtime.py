from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from kivra_memory.application import sealed_runtime
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import Settings
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerAnchor,
    initialize_empty_destruction_ledger_anchor,
)
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


def _ledger_root(tmp_path: Path) -> Path:
    ledger = tmp_path / "destruction-ledger"
    ledger.mkdir(mode=0o770)
    ledger.chmod(0o2770)
    return ledger


def _anchor_path(tmp_path: Path, ledger_root: Path) -> Path:
    parent = tmp_path / "destruction-anchor"
    parent.mkdir(mode=0o770)
    parent.chmod(0o2770)
    anchor = parent / "current.json"
    initialize_empty_destruction_ledger_anchor(ledger_root, anchor)
    return anchor


def test_disabled_runtime_does_not_claim_sealed_content_support() -> None:
    runtime = SealedRuntime.from_settings(Settings())

    assert runtime.enabled is False
    assert runtime.key_provider is None
    assert runtime.digest_binder is None


def test_enabled_runtime_injects_same_provider_into_selection_and_reads(tmp_path: Path) -> None:
    ledger_root = _ledger_root(tmp_path)
    runtime = SealedRuntime.from_settings(
        Settings(
            sealed_content_enabled=True,
            sealed_key_provider_root=_key_root(tmp_path),
            sealed_destruction_ledger_root=ledger_root,
            sealed_destruction_ledger_anchor_path=_anchor_path(tmp_path, ledger_root),
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
    ledger_root = _ledger_root(tmp_path)
    root.chmod(0o2777)
    settings = Settings(
        sealed_content_enabled=True,
        sealed_key_provider_root=root,
        sealed_destruction_ledger_root=ledger_root,
        sealed_destruction_ledger_anchor_path=_anchor_path(tmp_path, ledger_root),
        sealed_digest_binding_credential=_binding_credential(tmp_path),
    )

    with pytest.raises(RuntimeError, match="invalid_sealed_content_configuration"):
        SealedRuntime.from_settings(settings)


def test_digest_credential_is_bounded_canonical_and_never_reflected(tmp_path: Path) -> None:
    root = _key_root(tmp_path)
    credential = _binding_credential(tmp_path, b"sensitive-canary")
    ledger_root = _ledger_root(tmp_path)
    settings = Settings(
        sealed_content_enabled=True,
        sealed_key_provider_root=root,
        sealed_destruction_ledger_root=ledger_root,
        sealed_destruction_ledger_anchor_path=_anchor_path(tmp_path, ledger_root),
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


def test_production_digest_credential_requires_service_effective_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("/var/lib/kivra-memory-sealed/keys")
    ledger_root = Path("/var/lib/kivra-memory-sealed/destruction-ledger")
    anchor_path = Path("/var/lib/kivra-memory-destruction-anchor/current.json")
    anchor_credential = Path("/run/credentials/kivra-memory-api.service/destruction-ledger-anchor")
    credential = Path("/run/credentials/kivra-memory-api.service/sealed-digest-binding")
    settings = Settings.model_construct(
        environment="production",
        sealed_content_enabled=True,
        sealed_key_provider_root=root,
        sealed_destruction_ledger_root=ledger_root,
        sealed_destruction_ledger_anchor_path=anchor_path,
        sealed_destruction_ledger_anchor_credential=anchor_credential,
        sealed_digest_binding_credential=credential,
    )
    provider = MagicMock()
    provider_factory = MagicMock(return_value=provider)
    reader = MagicMock(return_value=b"b" * 32)
    expected_anchor = DestructionLedgerAnchor(
        entry_count=0,
        aggregate_sha256="a" * 64,
    )
    anchor_reader = MagicMock(return_value=expected_anchor)
    monkeypatch.setattr(os, "geteuid", MagicMock(return_value=971))
    monkeypatch.setattr(sealed_runtime, "LocalDirectoryKeyProvider", provider_factory)
    monkeypatch.setattr(sealed_runtime, "_read_digest_binding_secret", reader)
    monkeypatch.setattr(sealed_runtime, "_read_destruction_ledger_anchor", anchor_reader)

    runtime = SealedRuntime.from_settings(settings)

    provider_factory.assert_called_once_with(
        root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=expected_anchor,
        read_only_destruction_authority=True,
        required_owner_uid=0,
    )
    anchor_reader.assert_called_once_with(anchor_credential, required_owner_uid=971)
    reader.assert_called_once_with(credential, required_owner_uid=971)
    assert runtime.key_provider is provider


def test_digest_credential_reader_rejects_owner_other_than_effective_uid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    credential = _binding_credential(tmp_path)
    actual = credential.stat()
    foreign = list(actual)
    foreign[4] = actual.st_uid + 1
    monkeypatch.setattr(
        os,
        "fstat",
        MagicMock(return_value=os.stat_result(foreign)),
    )

    with pytest.raises(ValueError):
        sealed_runtime._read_digest_binding_secret(
            credential,
            required_owner_uid=actual.st_uid,
        )
