"""Deployment and fail-closed behavior checks for PostgreSQL recovery helpers."""

from __future__ import annotations

import importlib.util
import json
import stat
from datetime import UTC, datetime, timedelta
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/memory-node/scripts/kivra-memory-postgres-backup"
BACKUP_ROOT = ROOT / "deploy/memory-node/backup"
SYSTEMD = ROOT / "deploy/memory-node/systemd"


def _load() -> Any:
    specification = importlib.util.spec_from_loader(
        "postgres_backup", SourceFileLoader("postgres_backup", str(SCRIPT))
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _configure(module: Any, temporary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backup_mount = temporary / "backup"
    recovery_mount = temporary / "recovery"
    plaintext_staging_mount = temporary / "plaintext-staging"
    pg_data = temporary / "pg"
    for path in (backup_mount, recovery_mount, plaintext_staging_mount, pg_data / "pg_wal"):
        path.mkdir(parents=True, mode=0o700)
    module.BACKUP_MOUNT = backup_mount
    module.PLAINTEXT_STAGING_MOUNT = plaintext_staging_mount
    module.STORE = backup_mount / "kivra-memory-postgres"
    module.BASE_ROOT = module.STORE / "base"
    module.WAL_ROOT = module.STORE / "wal"
    module.STATUS_ROOT = module.STORE / "status"
    module.VERIFICATION_ROOT = module.STORE / "verification"
    module.STAGING_ROOT = module.STORE / ".staging"
    module.RECOVERY_MOUNT = recovery_mount
    module.PG_DATA = pg_data
    module.PG_WAL = pg_data / "pg_wal"
    for path, mode in {
        module.STORE: 0o2750,
        module.BASE_ROOT: 0o2750,
        module.WAL_ROOT: 0o2770,
        module.STATUS_ROOT: 0o2770,
        module.VERIFICATION_ROOT: 0o2750,
        module.STAGING_ROOT: 0o2770,
    }.items():
        path.mkdir(mode=mode)
        path.chmod(mode)
    monkeypatch.setattr(module, "_require_owned", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        module.os.path, "ismount", lambda path: Path(path) in {backup_mount, recovery_mount}
    )


def _index(backup_id: str, created: datetime) -> dict[str, object]:
    return {
        "created_at": created.isoformat(),
        "kind": "base_backup",
        "manifest_ciphertext_sha256": "1" * 64,
        "manifest_version": 1,
        "object_id": backup_id,
        "verification": "source_pg_verifybackup_ok",
    }


def test_helper_uses_fixed_paths_arguments_and_no_environment_redirects() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    assert 'PG_BINDIR = Path("/usr/lib/postgresql/17/bin")' in source
    assert 'BACKUP_MOUNT = Path("/mnt/memory-backup")' in source
    assert 'PLAINTEXT_STAGING_MOUNT = Path("/mnt/memory-backup-staging")' in source
    assert 'RECOVERY_MOUNT = Path("/mnt/memory-recovery")' in source
    assert "os.environ" not in source
    assert "shell=True" not in source
    assert "stderr=subprocess.DEVNULL" in source
    assert "O_EXCL" in source
    assert "O_NOFOLLOW" in source
    assert "os.fsync" in source
    assert "os.rename" in source
    assert "pg_verifybackup" in source
    assert "--wal-method=stream" in source
    assert "shutil.copyfileobj" in source


def test_archive_wal_is_atomic_idempotent_and_rejects_mismatched_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    wal_name = "00000001000000000000000A"
    source = module.PG_WAL / wal_name
    source.write_bytes(b"synthetic-wal-a")
    monkeypatch.setattr(module, "_validate_recipient", lambda: None)
    monkeypatch.setattr(
        module,
        "_encrypt_file",
        lambda source, destination: destination.write_bytes(source.read_bytes()[::-1]),
    )
    monkeypatch.setattr(
        module,
        "_publish_encrypted_manifest",
        lambda _stage, _value: "3" * 64,
    )

    module.archive_wal(str(source), wal_name)
    published = module.WAL_ROOT / wal_name
    assert sorted(path.name for path in published.iterdir()) == ["index.json", "segment.age"]
    assert not list(module.STAGING_ROOT.iterdir())
    module.archive_wal(str(source), wal_name)

    source.write_bytes(b"synthetic-wal-b")
    with pytest.raises(module.BackupError, match=r"^wal_duplicate_mismatch$"):
        module.archive_wal(str(source), wal_name)
    assert json.loads((published / "index.json").read_text())["plaintext_sha256"] != module._sha256(
        source
    )


def test_archive_failure_never_publishes_partial_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    wal_name = "00000001000000000000000B"
    source = module.PG_WAL / wal_name
    source.write_bytes(b"synthetic-wal")
    monkeypatch.setattr(module, "_validate_recipient", lambda: None)

    def interrupt(_source: Path, destination: Path) -> None:
        destination.write_bytes(b"partial")
        raise module.BackupError("injected_interruption")

    monkeypatch.setattr(module, "_encrypt_file", interrupt)
    with pytest.raises(module.BackupError, match=r"^injected_interruption$"):
        module.archive_wal(str(source), wal_name)
    assert not (module.WAL_ROOT / wal_name).exists()
    assert not list(module.STAGING_ROOT.iterdir())


@pytest.mark.parametrize(
    ("source", "name", "code"),
    [
        ("relative", "000000010000000000000001", "wal_source_invalid"),
        ("relative", "../000000010000000000000001", "wal_name_invalid"),
        ("relative", "00000001000000000000000g", "wal_name_invalid"),
    ],
)
def test_wal_path_and_name_validation_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    name: str,
    code: str,
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    with pytest.raises(module.BackupError, match=f"^{code}$"):
        module.archive_wal(source, name)


def test_recovery_destination_is_exact_empty_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)

    accepted = module.RECOVERY_MOUNT / "drill-01"
    module._require_recovery_destination(accepted)
    assert accepted.is_dir()
    with pytest.raises(module.BackupError, match=r"^recovery_destination_invalid$"):
        module._require_recovery_destination(module.RECOVERY_MOUNT / "nested" / "drill")
    occupied = module.RECOVERY_MOUNT / "occupied"
    occupied.mkdir(mode=0o700)
    (occupied / "PG_VERSION").write_text("17")
    with pytest.raises(module.BackupError, match=r"^recovery_destination_not_empty$"):
        module._require_recovery_destination(occupied)


def test_safe_extract_rejects_traversal_and_links(tmp_path: Path) -> None:
    module = _load()
    import io
    import tarfile

    for name, link in (("../escape", False), ("unsafe-link", True)):
        archive_path = tmp_path / f"{name.replace('/', '-')}.tar"
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo(name)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "target"
                archive.addfile(member)
            else:
                payload = b"synthetic"
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        destination = tmp_path / f"restore-{int(link)}"
        destination.mkdir()
        with pytest.raises(module.BackupError, match=r"^backup_member_unsafe$"):
            module._safe_extract(archive_path, destination)
    assert not (tmp_path.parent / "escape").exists()


def test_encrypted_manifest_digest_authentication_and_exact_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    backup_id = "20260812T021500Z-0000000000000001"
    root = module.BASE_ROOT / backup_id
    root.mkdir(mode=0o770)
    root.chmod(0o770)
    encrypted = root / "recovery-manifest.json.age"
    encrypted.write_bytes(b"synthetic-ciphertext")
    manifest = {
        "ciphertext_sha256": "1" * 64,
        "configuration_manifest_sha256": "2" * 64,
        "created_at": "2026-08-12T02:15:00+00:00",
        "end_lsn": "0/2000000",
        "kind": "base_backup",
        "manifest_version": 1,
        "migration_revision": "0010_ingress_provider_heads",
        "object_id": backup_id,
        "plaintext_sha256": "3" * 64,
        "postgres_major": 17,
        "release_revision": "4" * 40,
        "start_lsn": "0/1000000",
        "start_wal": "000000010000000000000001",
        "system_identifier": "123456789",
        "timeline": 1,
        "verification": "pg_verifybackup_ok",
        "verified_at": "2026-08-12T02:16:00+00:00",
    }
    index = {
        "created_at": "2026-08-12T02:15:00+00:00",
        "kind": "base_backup",
        "manifest_ciphertext_sha256": module._sha256(encrypted),
        "manifest_version": 1,
        "object_id": backup_id,
        "verification": "pg_verifybackup_ok",
    }

    def decrypt(_source: Path, destination: Path) -> None:
        destination.write_text(json.dumps(manifest), encoding="utf-8")
        destination.chmod(0o600)

    monkeypatch.setattr(module, "_decrypt_file", decrypt)
    assert (
        module._encrypted_manifest(
            root, index, kind="base_backup", temporary_root=module.RECOVERY_MOUNT
        )["system_identifier"]
        == "123456789"
    )

    manifest["unexpected"] = "synthetic"
    with pytest.raises(module.BackupError, match=r"^manifest_invalid$"):
        module._encrypted_manifest(
            root, index, kind="base_backup", temporary_root=module.RECOVERY_MOUNT
        )


def test_recovery_time_requires_explicit_utc(tmp_path: Path) -> None:
    module = _load()
    (tmp_path / "postgresql.auto.conf").write_text("", encoding="utf-8")
    with pytest.raises(module.BackupError, match=r"^recovery_target_invalid$"):
        module._write_recovery_settings(tmp_path, "time", "2026-08-12T02:15:00-05:00")


def test_retention_keeps_eight_daily_five_weekly_and_last_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    now = datetime(2026, 8, 12, 2, tzinfo=UTC)
    ids = []
    for index in range(50):
        created = now - timedelta(days=index)
        backup_id = created.strftime("%Y%m%dT%H%M%SZ") + f"-{index:016x}"
        ids.append(backup_id)
        root = module.BASE_ROOT / backup_id
        root.mkdir(mode=0o770)
        root.chmod(0o770)
        (root / "index.json").write_text(json.dumps(_index(backup_id, created)), encoding="utf-8")
        encrypted_manifest = root / "recovery-manifest.json.age"
        encrypted_manifest.write_bytes(b"synthetic-manifest")
        manifest_sha = module._sha256(encrypted_manifest)
        index_value = json.loads((root / "index.json").read_text())
        index_value["manifest_ciphertext_sha256"] = manifest_sha
        (root / "index.json").write_text(json.dumps(index_value), encoding="utf-8")
        (module.VERIFICATION_ROOT / f"{backup_id}.json").write_text(
            json.dumps(
                {
                    "manifest_ciphertext_sha256": manifest_sha,
                    "object_id": backup_id,
                    "result": "isolated_pg_verifybackup_ok",
                    "verified_at": created.isoformat(),
                }
            ),
            encoding="utf-8",
        )
    hold_id = ids[-1]
    (module.BASE_ROOT / hold_id / "HOLD").write_text("operator_hold\n")
    for segment in (
        "00000001000000000000000E",
        "000000010000000000000010",
        "000000020000000000000001",
    ):
        (module.WAL_ROOT / segment).mkdir(mode=0o770)
        (module.WAL_ROOT / segment).chmod(0o770)

    module.retain()

    retained = {path.name for path in module.BASE_ROOT.iterdir()}
    assert ids[0] in retained
    assert len(retained) >= 8
    retained_weeks = {
        datetime.strptime(name[:15], "%Y%m%dT%H%M%S").isocalendar()[:2] for name in retained
    }
    assert len(retained_weeks) >= 5
    assert hold_id in retained
    assert (module.WAL_ROOT / "00000001000000000000000E").exists()
    assert (module.WAL_ROOT / "000000010000000000000010").exists()
    assert (module.WAL_ROOT / "000000020000000000000001").exists()


def test_retention_refuses_to_run_without_a_verified_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    with pytest.raises(module.BackupError, match=r"^no_verified_recovery_chain$"):
        module.retain()


def test_units_are_mount_gated_sandboxed_and_have_bounded_schedules() -> None:
    base = (SYSTEMD / "kivra-memory-base-backup.service").read_text()
    verify = (SYSTEMD / "kivra-memory-backup-verify.service").read_text()
    retention = (SYSTEMD / "kivra-memory-backup-retention.service").read_text()
    all_services = (base, verify, retention)

    assert "ConditionPathIsMountPoint=/mnt/memory-backup" in base
    assert "ConditionPathIsMountPoint=/mnt/memory-backup-staging" in base
    assert "LoadCredential=postgres-pgpass:" in base
    assert "PGPASSFILE=/run/credentials/" in base
    assert "backup-age-identity" not in base
    assert "Group=kivra-backup" in base
    assert "ConditionPathIsMountPoint=/mnt/memory-recovery" in verify
    assert "ConditionPathIsRegularFile=/etc/kivra-memory/backup-age-identity" in verify
    assert "Group=memory-recovery" in verify
    assert "SupplementaryGroups=kivra-backup" in verify
    for unit in all_services:
        for setting in (
            "NoNewPrivileges=true",
            "PrivateMounts=true",
            "ProtectSystem=strict",
            "ProtectKernelLogs=true",
            "ProtectProc=invisible",
            "RestrictNamespaces=true",
            "RestrictRealtime=true",
            "KeyringMode=private",
            "LimitCORE=0",
            "CapabilityBoundingSet=",
            "IPAddressDeny=any",
        ):
            assert setting in unit
        assert "UnsetEnvironment=HTTP_PROXY HTTPS_PROXY" in unit
    for timer_name in (
        "kivra-memory-base-backup.timer",
        "kivra-memory-backup-verify.timer",
        "kivra-memory-backup-retention.timer",
    ):
        timer = SYSTEMD / timer_name
        value = timer.read_text()
        assert "Persistent=true" in value
        assert "RandomizedDelaySec=15m" in value


def test_examples_and_runbook_freeze_recovery_invariants() -> None:
    postgres = (BACKUP_ROOT / "postgresql.conf.example").read_text()
    readme = (BACKUP_ROOT / "README.md").read_text()
    prose = " ".join(readme.split())

    assert "archive_mode = on" in postgres
    assert "archive_timeout = '60s'" in postgres
    assert "full_page_writes = on" in postgres
    assert "fsync = on" in postgres
    assert "15-minute RPO" in prose
    assert "four-hour RTO" in prose
    assert "eight UTC days" in prose
    assert "five ISO weeks" in prose
    assert "private age identity" in prose
    assert "do not enable the verification timer on the routine node" in prose.lower()
    assert "does not start PostgreSQL" in prose
    assert "Stop immediately" in readme
