"""Operator archive recovery configuration and result tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from kivra_memory.tools.archive_recovery import (
    ArchiveRecoverySettings,
    RecoveryConfigurationError,
)


def _config(tmp_path: Path) -> dict[str, object]:
    (tmp_path / "allowed_signers").write_text("public trust anchor\n")
    return {
        "repository": str(tmp_path / "archive.git"),
        "branch_name": "main",
        "expected_head": "a" * 40,
        "expected_manifest_sha256": "b" * 64,
        "expected_high_water_sequence": 42,
        "expected_application_version": "0.1.0",
        "expected_alembic_revision": "0010_ingress_provider_heads",
        "signer_epochs": [
            {
                "first_event_sequence": 1,
                "last_event_sequence": None,
                "allowed_signers_file": str(tmp_path / "allowed_signers"),
                "signer_principal": "archive@scalevault",
                "author_name": "ScaleVault Archive",
                "author_email": "archive@scalevault.invalid",
            }
        ],
    }


def test_config_has_no_signing_private_key_and_pins_external_head(tmp_path: Path) -> None:
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps(_config(tmp_path)))
    settings = ArchiveRecoverySettings.load(config)

    assert settings.expected_head == "a" * 40
    assert settings.source().expected_head == "a" * 40
    assert not hasattr(settings, "signing_key")
    assert not hasattr(settings.signer_epochs[0], "signing_key")


def test_config_rejects_private_key_fields_and_gapped_epochs(tmp_path: Path) -> None:
    value = _config(tmp_path)
    epochs = value["signer_epochs"]
    assert isinstance(epochs, list)
    epoch = epochs[0]
    assert isinstance(epoch, dict)
    epoch["signing_key"] = str(tmp_path / "private")
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps(value))
    with pytest.raises(RecoveryConfigurationError):
        ArchiveRecoverySettings.load(config)

    value = _config(tmp_path)
    epochs = value["signer_epochs"]
    assert isinstance(epochs, list)
    epoch = epochs[0]
    assert isinstance(epoch, dict)
    epoch["first_event_sequence"] = 2
    config.write_text(json.dumps(value))
    with pytest.raises(RecoveryConfigurationError):
        ArchiveRecoverySettings.load(config)
