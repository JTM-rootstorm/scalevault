from __future__ import annotations

import argparse
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kivra_memory.admin import credentials_main
from kivra_memory.admin.credential_io import CredentialAdminSettings
from kivra_memory.admin.credentials import CredentialMetadata
from kivra_memory.auth import ClientCapabilityProfile, ReadCapability
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def _metadata() -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=new_uuid7(),
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        host_label="workstation",
        environment_label="production",
        public_hint="codex:production:workstation",
        scopes=("memory.status.transport", "memory.write.nominate"),
        capability_profile=ClientCapabilityProfile(
            contract_version="scalevault-client-capability-v1",
            read=None,
        ),
        created_at=NOW,
        expires_at=None,
        last_used_at=None,
        revoked_at=None,
    )


def test_default_create_profile_is_read_write_without_destructive_scopes() -> None:
    arguments = credentials_main._parser().parse_args(
        [
            "create",
            "--tenant-id",
            str(new_uuid7()),
            "--host-label",
            "workstation",
            "--environment-label",
            "production",
            "--secret-stdout",
        ]
    )
    scopes = credentials_main._DEFAULT_SCOPES
    capability = credentials_main._capability_from_arguments(arguments, scopes=scopes)

    assert "memory.write.nominate" in scopes
    assert "memory.status.transport" in scopes
    assert not {
        "memory.write.conflict.open",
        "memory.write.conflict.resolve",
        "memory.write.forget",
        "memory.write.link",
        "memory.write.retire",
    } & set(scopes)
    assert capability.read is not None
    assert capability.read.max_sensitivity == 3
    assert capability.read.allow_candidates is False
    assert MemoryScope.SCENE_LOCAL not in capability.read.allowed_memory_scopes


def test_custom_profile_is_typed_and_rejects_read_capability_without_scope() -> None:
    arguments = credentials_main._parser().parse_args(
        [
            "create",
            "--tenant-id",
            str(new_uuid7()),
            "--host-label",
            "workstation",
            "--environment-label",
            "development",
            "--scope",
            "memory.read.get",
            "--read-memory-scope",
            "project",
            "--read-visibility",
            "restricted",
            "--max-sensitivity",
            "2",
            "--allow-candidates",
            "--secret-stdout",
        ]
    )
    capability = credentials_main._capability_from_arguments(
        arguments,
        scopes=("memory.read.get",),
    )
    assert capability.read == ReadCapability(
        allowed_memory_scopes=frozenset({MemoryScope.PROJECT}),
        allowed_visibilities=frozenset({MemoryVisibility.RESTRICTED}),
        max_sensitivity=2,
        allow_candidates=True,
    )

    arguments.scope = ["memory.write.nominate"]
    with pytest.raises(RuntimeError, match="credential_request_invalid"):
        credentials_main._capability_from_arguments(
            arguments,
            scopes=("memory.write.nominate",),
        )


def test_create_and_rotate_require_explicit_secret_output_policy() -> None:
    parser = credentials_main._parser()
    with pytest.raises(SystemExit) as create:
        parser.parse_args(
            [
                "create",
                "--tenant-id",
                str(new_uuid7()),
                "--host-label",
                "host",
                "--environment-label",
                "test",
            ]
        )
    with pytest.raises(SystemExit) as rotate:
        parser.parse_args(
            [
                "rotate",
                "--tenant-id",
                str(new_uuid7()),
                "--credential-id",
                str(new_uuid7()),
            ]
        )
    assert create.value.code == 2
    assert rotate.value.code == 2


def test_secure_tunnel_requires_file_output_and_exposes_only_read_status_scopes() -> None:
    parser = credentials_main._parser()
    base = [
        "create-secure-tunnel",
        "--tenant-id",
        str(new_uuid7()),
        "--actor-id",
        str(new_uuid7()),
        "--installation-id",
        str(new_uuid7()),
        "--tunnel-label",
        "workspace-one",
    ]
    with pytest.raises(SystemExit) as missing_output:
        parser.parse_args(base)
    with pytest.raises(SystemExit) as stdout_rejected:
        parser.parse_args([*base, "--secret-stdout"])

    parsed = parser.parse_args([*base, "--secret-output", "/root/authorization"])
    assert parsed.secret_output == Path("/root/authorization")
    assert missing_output.value.code == 2
    assert stdout_rejected.value.code == 2
    assert set(credentials_main._DEFAULT_SECURE_TUNNEL_SCOPES) == {
        "memory.read.conflicts",
        "memory.read.context",
        "memory.read.get",
        "memory.read.lineage",
        "memory.read.search",
        "memory.read.selection_history",
        "memory.read.timeline",
        "memory.status.ingress",
        "memory.status.transport",
    }

    secure_rotate = [
        "rotate-secure-tunnel",
        "--tenant-id",
        str(new_uuid7()),
        "--credential-id",
        str(new_uuid7()),
    ]
    with pytest.raises(SystemExit) as missing_rotation_output:
        parser.parse_args(secure_rotate)
    with pytest.raises(SystemExit) as rotation_stdout_rejected:
        parser.parse_args([*secure_rotate, "--secret-stdout"])
    assert missing_rotation_output.value.code == 2
    assert rotation_stdout_rejected.value.code == 2


def test_secret_stdout_contains_only_token(capsys: pytest.CaptureFixture[str]) -> None:
    token = "svb1." + "a" * 120
    arguments = SimpleNamespace(secret_output=None, secret_stdout=True)

    credentials_main._emit_secret(
        argparse.Namespace(**vars(arguments)),
        token,
    )

    captured = capsys.readouterr()
    assert captured.out == token + "\n"
    assert captured.err == ""


def test_metadata_output_never_contains_token_or_verifier(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _metadata()
    credentials_main._emit_metadata((record,))

    captured = capsys.readouterr()
    assert str(record.credential_id) in captured.out
    assert "secret_hash" not in captured.out
    assert "token" not in captured.out
    assert "hmac-sha256" not in captured.out


def test_metadata_output_sorts_capability_sets_deterministically(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = replace(
        _metadata(),
        capability_profile=ClientCapabilityProfile(
            contract_version="scalevault-client-capability-v1",
            read=ReadCapability(
                allowed_memory_scopes=frozenset(
                    {MemoryScope.RELATIONSHIP, MemoryScope.GLOBAL, MemoryScope.PERSONA}
                ),
                allowed_visibilities=frozenset(
                    {MemoryVisibility.RESTRICTED, MemoryVisibility.PRIVATE_ROOT}
                ),
                max_sensitivity=3,
                allow_candidates=False,
            ),
        ),
    )

    credentials_main._emit_metadata((record,))

    profile = json.loads(capsys.readouterr().out)[0]["capability_profile"]["read"]
    assert profile["allowed_memory_scopes"] == ["global", "persona", "relationship"]
    assert profile["allowed_visibilities"] == ["private_root", "restricted"]


def test_main_reports_only_fixed_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "SENTINEL-DATABASE-PASSWORD"
    monkeypatch.setattr(
        credentials_main,
        "_parser",
        MagicMock(
            return_value=SimpleNamespace(
                parse_args=MagicMock(return_value=SimpleNamespace(config=Path("/safe/config")))
            )
        ),
    )
    monkeypatch.setattr(
        CredentialAdminSettings,
        "from_file",
        MagicMock(side_effect=RuntimeError(canary)),
    )

    with pytest.raises(SystemExit) as caught:
        credentials_main.main()

    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert captured.out == ""
    assert captured.err == "ScaleVault credential administration failed\n"
    assert canary not in captured.err
