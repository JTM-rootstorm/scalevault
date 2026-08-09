from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from kivra_memory.application.genesis_apply import GenesisApplyError
from kivra_memory.domain.canonical_json import canonical_json_bytes

from scripts import apply_genesis_import as cli


def _config_document() -> dict[str, object]:
    return {
        "contract_version": "scalevault-genesis-operator-config-v1",
        "expected_plan_sha256": "a" * 64,
        "import_run_id": "019c0000-0000-7000-8000-000000000001",
        "pre_state_sha256": "b" * 64,
        "backup_reference": "verified-backup-reference",
        "mappings": {
            "contract_version": "scalevault-genesis-canonical-mappings-v1",
            "genesis_actor_reference": "kivra:genesis",
            "genesis_actor_id": "019c0000-0000-7000-8000-000000000002",
            "persona_id": "019c0000-0000-7000-8000-000000000003",
            "lineage_id": "019c0000-0000-7000-8000-000000000004",
            "branch_id": "019c0000-0000-7000-8000-000000000005",
            "subjects": [
                {
                    "subject_kind": "global",
                    "source_reference": "global",
                    "subject_id": "019c0000-0000-7000-8000-000000000006",
                },
                {
                    "subject_kind": "global",
                    "source_reference": "genesis-import:terminal",
                    "subject_id": "019c0000-0000-7000-8000-00000000000b",
                },
            ],
            "sessions": [],
        },
        "importer_authority": {
            "contract_version": "scalevault-genesis-importer-authority-v1",
            "tenant_id": "019c0000-0000-7000-8000-000000000007",
            "actor_id": "019c0000-0000-7000-8000-000000000008",
            "client_id": "019c0000-0000-7000-8000-000000000009",
            "transport_binding_id": "019c0000-0000-7000-8000-00000000000a",
        },
    }


def test_operator_config_requires_root_owned_regular_exact_0600(tmp_path: Path) -> None:
    path = tmp_path / "operator.json"
    path.write_bytes(canonical_json_bytes(_config_document()))
    path.chmod(0o600)

    with pytest.raises(GenesisApplyError, match="unsafe_operator_config"):
        cli._read_operator_config(path)


def test_operator_config_accepts_strict_json_through_safe_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "operator.json"
    path.write_bytes(canonical_json_bytes(_config_document()))
    path.chmod(0o600)
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0),
    )

    config = cli._read_operator_config(path)

    assert config.backup_reference == "verified-backup-reference"
    assert config.importer_authority.actor_id != config.mappings.genesis_actor_id


def test_operator_config_requires_explicit_terminal_audit_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _config_document()
    mappings = document["mappings"]
    assert isinstance(mappings, dict)
    subjects = mappings["subjects"]
    assert isinstance(subjects, list)
    subjects.pop()
    path = tmp_path / "operator.json"
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0),
    )

    with pytest.raises(GenesisApplyError, match="invalid_operator_config"):
        cli._read_operator_config(path)


def test_operator_config_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "operator.json"
    target.write_bytes(canonical_json_bytes(_config_document()))
    target.chmod(0o600)
    link = tmp_path / "operator-link.json"
    link.symlink_to(target)

    with pytest.raises(GenesisApplyError, match="operator_config_unavailable"):
        cli._read_operator_config(link)


@pytest.mark.parametrize(
    "database_url",
    (
        "postgresql+psycopg://kivra_memory_api:secret@127.0.0.1/kivra_memory",
        "sqlite:///tmp/scalevault.db",
    ),
)
def test_database_url_requires_dedicated_importer_role(database_url: str) -> None:
    with pytest.raises(GenesisApplyError, match="invalid_database_role"):
        cli._database_url({"KIVRA_MEMORY_DATABASE_URL": database_url})


def test_database_url_accepts_dedicated_importer_role() -> None:
    value = "postgresql+psycopg://kivra_memory_genesis_importer:secret@127.0.0.1/kivra_memory"
    assert cli._database_url({"KIVRA_MEMORY_DATABASE_URL": value}) == value


def test_cli_failure_output_cannot_echo_operator_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "unsafe.json"
    private_marker = "private-memory-payload-marker"
    config.write_text(private_marker)
    config.chmod(0o644)

    result = cli.main(
        ["plan", "--repository", str(tmp_path), "--config", str(config)],
        environment={},
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == '{"error":"genesis_import_failed","ok":false}\n'
    assert private_marker not in captured.err
