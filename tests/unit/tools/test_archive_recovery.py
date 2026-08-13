"""Operator archive recovery configuration and result tests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.tools import archive_recovery as module
from kivra_memory.tools.archive_recovery import (
    ArchiveRecoverySettings,
    RecoveryConfigurationError,
)


def _config(tmp_path: Path) -> dict[str, object]:
    (tmp_path / "allowed_signers").write_text("public trust anchor\n")
    key_type = b"ssh-ed25519"
    key = len(key_type).to_bytes(4, "big") + key_type + b"x" * 32
    (tmp_path / "archive.pub").write_text(
        "ssh-ed25519 " + base64.b64encode(key).decode("ascii") + "\n"
    )
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip(
        "="
    )
    return {
        "archive_target_id": "archive-primary",
        "repository": str(tmp_path / "archive.git"),
        "branch_name": "main",
        "expected_head": "a" * 40,
        "expected_manifest_sha256": "b" * 64,
        "expected_high_water_sequence": 42,
        "expected_application_version": "0.1.0",
        "expected_alembic_revision": "0011_observability_aggregates",
        "signer_epochs": [
            {
                "epoch_id": "archive-epoch-1",
                "first_event_sequence": 1,
                "last_event_sequence": None,
                "allowed_signers_file": str(tmp_path / "allowed_signers"),
                "public_key_file": str(tmp_path / "archive.pub"),
                "public_key_fingerprint": fingerprint,
                "signer_principal": "archive@scalevault",
                "author_name": "ScaleVault Archive",
                "author_email": "archive@scalevault.invalid",
                "transition_record_id": None,
                "compromised_last_commit": None,
                "compromised_last_event_sequence": None,
            }
        ],
        "transition_evidence": [],
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


def test_continue_new_target_cli_passes_explicit_operator_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps(_config(tmp_path)))
    target = tmp_path / "new-target.git"
    target.mkdir()
    target_id = str(new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=910))
    checkpoint_id = str(new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=911))
    sentinel = object()
    called: dict[str, object] = {}

    monkeypatch.setattr(module, "_verified", lambda settings: sentinel)

    async def continuation(
        settings: ArchiveRecoverySettings,
        verified: object,
        **kwargs: object,
    ) -> dict[str, object]:
        called.update(kwargs)
        assert verified is sentinel
        assert not hasattr(settings, "signing_key")
        return {
            "ok": True,
            "archive_target_id": target_id,
            "checkpoint_id": checkpoint_id,
            "head": "a" * 40,
            "final_high_water_sequence": 42,
            "continuation": "normal_exporter_activation_required",
        }

    monkeypatch.setattr(module, "_continue_new_target", continuation)
    module.main(
        (
            "--config",
            str(config),
            "continue-new-target",
            "--confirmation",
            "continue-to-new-immutable-target",
            "--target-repository",
            str(target),
            "--target-id",
            target_id,
            "--checkpoint-id",
            checkpoint_id,
            "--target-name",
            "recovered-primary",
            "--repository-reference",
            "ssh://git@archive.invalid/recovered.git",
            "--target-branch",
            "main",
        )
    )

    assert called == {
        "confirmation": "continue-to-new-immutable-target",
        "target_repository": target,
        "target_id": target_id,
        "checkpoint_id": checkpoint_id,
        "target_name": "recovered-primary",
        "repository_reference": "ssh://git@archive.invalid/recovered.git",
        "target_branch": "main",
    }
    output = json.loads(capsys.readouterr().out)
    assert output["continuation"] == "normal_exporter_activation_required"
    assert "signing_key" not in output


@pytest.mark.asyncio
async def test_continue_new_target_rejects_before_copy_without_exact_confirmation(
    tmp_path: Path,
) -> None:
    config = tmp_path / "recovery.json"
    config.write_text(json.dumps(_config(tmp_path)))
    settings = ArchiveRecoverySettings.load(config)

    with pytest.raises(RecoveryConfigurationError, match="confirmation"):
        await module._continue_new_target(
            settings,
            object(),  # type: ignore[arg-type]
            confirmation="wrong",
            target_repository=tmp_path / "target.git",
            target_id=str(new_uuid7()),
            checkpoint_id=str(new_uuid7()),
            target_name="recovered-primary",
            repository_reference="ssh://git@archive.invalid/recovered.git",
            target_branch="main",
        )
