"""Deployment and fail-closed behavior checks for PostgreSQL recovery helpers."""

from __future__ import annotations

import importlib.util
import io
import json
import stat
import tarfile
from datetime import UTC, datetime, timedelta
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any, cast

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
    assert "_stream_stable_fd" in source
    assert "_scan_tar" in source


def test_archive_wal_is_atomic_idempotent_and_rejects_mismatched_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    wal_name = "00000001000000000000000A"
    source = module.PG_WAL / wal_name
    source.write_bytes(b"synthetic-wal-a")
    monkeypatch.setattr(module, "_validate_recipient", lambda: None)

    def encrypt(source_fd: int, destination: Path, *, max_bytes: int) -> str:
        sink = io.BytesIO()
        digest = module._stream_stable_fd(source_fd, sink, max_bytes=max_bytes)
        destination.write_bytes(sink.getvalue()[::-1])
        destination.chmod(0o640)
        return cast(str, digest)

    def publish_manifest(stage: Path, _value: object) -> str:
        manifest = stage / "recovery-manifest.json.age"
        manifest.write_bytes(b"synthetic-manifest")
        manifest.chmod(0o640)
        return cast(str, module._sha256(manifest))

    monkeypatch.setattr(module, "_encrypt_fd", encrypt)
    monkeypatch.setattr(module, "_publish_encrypted_manifest", publish_manifest)

    module.archive_wal(str(source), wal_name)
    published = module.WAL_ROOT / wal_name
    assert sorted(path.name for path in published.iterdir()) == [
        "index.json",
        "recovery-manifest.json.age",
        "segment.age",
    ]
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

    def interrupt(_source_fd: int, destination: Path, *, max_bytes: int) -> str:
        del max_bytes
        destination.write_bytes(b"partial")
        raise module.BackupError("injected_interruption")

    monkeypatch.setattr(module, "_encrypt_fd", interrupt)
    with pytest.raises(module.BackupError, match=r"^injected_interruption$"):
        module.archive_wal(str(source), wal_name)
    assert not (module.WAL_ROOT / wal_name).exists()
    assert not list(module.STAGING_ROOT.iterdir())


def test_wal_stable_descriptor_detects_concurrent_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    source = tmp_path / "wal"
    source.write_bytes(b"a" * 128)
    source_fd = module.os.open(source, module.os.O_RDONLY | module.os.O_NOFOLLOW)

    original_fingerprint = module._source_fingerprint
    calls = 0

    def changing_fingerprint(info: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        fingerprint = original_fingerprint(info)
        return (*fingerprint[:-1], fingerprint[-1] + int(calls > 1))

    try:
        monkeypatch.setattr(module, "_source_fingerprint", changing_fingerprint)
        with pytest.raises(module.BackupError, match=r"^source_changed_during_read$"):
            module._stream_stable_fd(source_fd, io.BytesIO(), max_bytes=1024)
    finally:
        module.os.close(source_fd)


def test_wal_symlink_source_and_missing_or_corrupt_duplicate_manifest_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    wal_name = "00000001000000000000000C"
    source = module.PG_WAL / wal_name
    source.write_bytes(b"synthetic-wal")
    monkeypatch.setattr(module, "_validate_recipient", lambda: None)

    def encrypt(source_fd: int, destination: Path, *, max_bytes: int) -> str:
        sink = io.BytesIO()
        digest = module._stream_stable_fd(source_fd, sink, max_bytes=max_bytes)
        destination.write_bytes(sink.getvalue())
        destination.chmod(0o640)
        return cast(str, digest)

    def publish_manifest(stage: Path, _value: object) -> str:
        manifest = stage / "recovery-manifest.json.age"
        manifest.write_bytes(b"synthetic-manifest")
        manifest.chmod(0o640)
        return cast(str, module._sha256(manifest))

    monkeypatch.setattr(module, "_encrypt_fd", encrypt)
    monkeypatch.setattr(module, "_publish_encrypted_manifest", publish_manifest)
    module.archive_wal(str(source), wal_name)
    manifest = module.WAL_ROOT / wal_name / "recovery-manifest.json.age"
    manifest.unlink()
    with pytest.raises(module.BackupError, match=r"^required_file_missing$"):
        module.archive_wal(str(source), wal_name)
    manifest.write_bytes(b"corrupt-manifest")
    manifest.chmod(0o640)
    with pytest.raises(module.BackupError, match=r"^wal_duplicate_mismatch$"):
        module.archive_wal(str(source), wal_name)

    other = module.PG_WAL / "other"
    other.write_bytes(b"other")
    source.unlink()
    source.symlink_to(other)
    with pytest.raises(module.BackupError, match=r"^wal_source_invalid$"):
        module.archive_wal(str(source), wal_name)


def test_restore_wal_rejects_valid_name_symlinked_to_external_object_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    wal_name = "00000001000000000000000D"
    external = tmp_path / "crafted"
    external.mkdir(mode=0o770)
    for name in ("index.json", "recovery-manifest.json.age", "segment.age"):
        (external / name).write_bytes(b"crafted")
        (external / name).chmod(0o640)
    (module.WAL_ROOT / wal_name).symlink_to(external, target_is_directory=True)
    drill = module.RECOVERY_MOUNT / "drill" / "pg_wal"
    drill.mkdir(parents=True)
    reached = False

    def decrypt(*_args: object, **_kwargs: object) -> None:
        nonlocal reached
        reached = True

    monkeypatch.setattr(module, "_decrypt_fd", decrypt)
    with pytest.raises(module.BackupError, match=r"^wal_object_invalid$"):
        module.restore_wal(wal_name, str(drill / wal_name))
    assert not reached


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
        destination.mkdir(mode=0o700)
        with pytest.raises(module.BackupError, match=r"^backup_member_unsafe$"):
            module._safe_extract(archive_path, destination)
    assert not (tmp_path.parent / "escape").exists()


def test_tar_creation_is_normalized_deterministic_and_rejects_symlink_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    source = tmp_path / "source"
    source.mkdir()
    (source / "directory").mkdir()
    payload = source / "directory" / "payload"
    payload.write_bytes(b"synthetic")
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    module._create_tar(source, first)
    payload.chmod(0o777)
    payload.touch()
    (source / "directory").touch()
    module._create_tar(source, second)
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:") as archive:
        members = archive.getmembers()
    assert all(member.uid == member.gid == member.mtime == 0 for member in members)
    assert all(member.uname == member.gname == "" for member in members)
    assert {member.mode for member in members} == {0o600, 0o700}

    victim = source / "victim"
    victim.write_bytes(b"original")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    original_stat = module.os.stat
    swapped = False

    def racing_stat(path: object, *args: object, **kwargs: object) -> object:
        nonlocal swapped
        result = original_stat(path, *args, **kwargs)
        if path == "victim" and kwargs.get("dir_fd") is not None and not swapped:
            victim.unlink()
            victim.symlink_to(outside)
            swapped = True
        return result

    monkeypatch.setattr(module.os, "stat", racing_stat)
    with pytest.raises(module.BackupError, match=r"^backup_member_unsafe$"):
        module._create_tar(source, tmp_path / "raced.tar")


def _single_member_tar(path: Path, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    with tarfile.open(path, "w") as archive:
        archive.addfile(member, io.BytesIO(payload))


def test_extract_rejects_member_and_aggregate_size_before_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    huge = tmp_path / "huge.tar"
    _single_member_tar(huge, "huge", b"12345")
    monkeypatch.setattr(module, "MAX_TAR_MEMBER_BYTES", 4)
    destination = tmp_path / "huge-out"
    destination.mkdir(mode=0o700)
    with pytest.raises(module.BackupError, match=r"^backup_member_size_exceeded$"):
        module._safe_extract(huge, destination)
    assert not list(destination.iterdir())

    aggregate = tmp_path / "aggregate.tar"
    with tarfile.open(aggregate, "w") as archive:
        for name in ("one", "two"):
            member = tarfile.TarInfo(name)
            member.size = 3
            archive.addfile(member, io.BytesIO(b"123"))
    monkeypatch.setattr(module, "MAX_TAR_MEMBER_BYTES", 10)
    monkeypatch.setattr(module, "MAX_TAR_EXPANDED_BYTES", 5)
    with pytest.raises(module.BackupError, match=r"^backup_expanded_size_exceeded$"):
        module._safe_extract(aggregate, destination)
    assert not list(destination.iterdir())


def test_extract_rejects_count_depth_path_and_sparse_before_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    destination = tmp_path / "out"
    destination.mkdir(mode=0o700)

    count_archive = tmp_path / "count.tar"
    with tarfile.open(count_archive, "w") as archive:
        for name in ("one", "two"):
            archive.addfile(tarfile.TarInfo(name), io.BytesIO())
    monkeypatch.setattr(module, "MAX_TAR_MEMBERS", 1)
    with pytest.raises(module.BackupError, match=r"^backup_member_count_exceeded$"):
        module._safe_extract(count_archive, destination)

    monkeypatch.setattr(module, "MAX_TAR_MEMBERS", 10)
    monkeypatch.setattr(module, "MAX_TAR_DEPTH", 2)
    depth_archive = tmp_path / "depth.tar"
    _single_member_tar(depth_archive, "one/two/three", b"x")
    with pytest.raises(module.BackupError, match=r"^backup_member_unsafe$"):
        module._safe_extract(depth_archive, destination)

    monkeypatch.setattr(module, "MAX_TAR_DEPTH", 32)
    monkeypatch.setattr(module, "MAX_TAR_PATH_BYTES", 4)
    path_archive = tmp_path / "path.tar"
    _single_member_tar(path_archive, "12345", b"x")
    with pytest.raises(module.BackupError, match=r"^backup_member_unsafe$"):
        module._safe_extract(path_archive, destination)

    sparse_archive = tmp_path / "sparse.tar"
    sparse = tarfile.TarInfo("sparse")
    sparse.type = tarfile.GNUTYPE_SPARSE
    sparse.size = 0
    with tarfile.open(sparse_archive, "w", format=tarfile.GNU_FORMAT) as archive:
        archive.addfile(sparse)
    monkeypatch.setattr(module, "MAX_TAR_PATH_BYTES", 4096)
    with pytest.raises(module.BackupError, match=r"^backup_member_sparse$"):
        module._safe_extract(sparse_archive, destination)
    assert not list(destination.iterdir())


def test_extract_intermediate_symlink_swap_fails_before_any_external_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    archive_path = tmp_path / "race.tar"
    _single_member_tar(archive_path, "intermediate/payload", b"private-synthetic")
    destination = tmp_path / "restore"
    destination.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    detached = tmp_path / "detached"
    original_open = module.os.open
    swapped = False

    def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if path == "payload" and flags & module.os.O_WRONLY and not swapped:
            (destination / "intermediate").rename(detached)
            (destination / "intermediate").symlink_to(outside, target_is_directory=True)
            swapped = True
        return cast(int, original_open(path, flags, *args, **kwargs))

    monkeypatch.setattr(module.os, "open", racing_open)
    with pytest.raises(module.BackupError, match=r"^recovery_directory_changed$"):
        module._safe_extract(archive_path, destination)
    module._clean_failed_restore(destination, preserve_root=False)

    assert swapped
    assert not (outside / "payload").exists()
    assert not (detached / "payload").exists()
    assert not destination.exists()


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
    encrypted.chmod(0o640)
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


def test_pg_verify_only_retention_never_prunes_without_dependency_watermark(
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
        (root / "index.json").chmod(0o640)
        encrypted_manifest = root / "recovery-manifest.json.age"
        encrypted_manifest.write_bytes(b"synthetic-manifest")
        encrypted_manifest.chmod(0o640)
        manifest_sha = module._sha256(encrypted_manifest)
        index_value = json.loads((root / "index.json").read_text())
        index_value["manifest_ciphertext_sha256"] = manifest_sha
        (root / "index.json").write_text(json.dumps(index_value), encoding="utf-8")
        (root / "index.json").chmod(0o640)
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
        (module.VERIFICATION_ROOT / f"{backup_id}.json").chmod(0o640)
    hold_id = ids[-1]
    (module.BASE_ROOT / hold_id / "HOLD").write_text("operator_hold\n")
    (module.BASE_ROOT / hold_id / "HOLD").chmod(0o640)
    # Neither an unauthenticated claim nor an ambiguous dependency hint grants
    # deletion authority; the production catalog contract does not yet exist.
    for name in ("PITR-VERIFIED.json", "DEPENDENCIES.json", "RESTORE-POINTS.json"):
        marker = module.BASE_ROOT / ids[0] / name
        marker.write_text("{}\n")
        marker.chmod(0o640)
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
    assert retained == set(ids)
    retained_weeks = {
        datetime.strptime(name[:15], "%Y%m%dT%H%M%S").isocalendar()[:2] for name in retained
    }
    assert len(retained_weeks) >= 5
    assert hold_id in retained
    assert (module.WAL_ROOT / "00000001000000000000000E").exists()
    assert (module.WAL_ROOT / "000000010000000000000010").exists()
    assert (module.WAL_ROOT / "000000020000000000000001").exists()
    status = json.loads((module.STATUS_ROOT / "latest-retention.json").read_text())
    assert status["result"] == "no_prune_dependency_watermark_absent"


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
    assert "eight-daily/five-weekly policy is an activation target" in prose
    assert "deletes nothing" in prose
    assert "no_prune_dependency_watermark_absent" in prose
    assert "private age identity" in prose
    assert "do not enable the verification timer on the routine node" in prose.lower()
    assert "does not start PostgreSQL" in prose
    assert "Stop immediately" in readme


def test_helper_readme_and_units_share_exact_storage_ownership_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    ownership_calls: dict[Path, tuple[str, str, int]] = {}

    def record(path: Path, *, owner: str, group: str, mode: int) -> None:
        ownership_calls[path] = (owner, group, mode)

    monkeypatch.setattr(module, "_require_owned", record)
    monkeypatch.setattr(module.os, "access", lambda _path, _mode: True)
    module._ensure_store()

    assert ownership_calls == {
        module.BACKUP_MOUNT: ("root", "kivra-backup", 0o750),
        module.STORE: ("memory-backup", "kivra-backup", 0o2750),
        module.BASE_ROOT: ("memory-backup", "kivra-backup", 0o2750),
        module.WAL_ROOT: ("memory-backup", "kivra-backup", 0o2770),
        module.STATUS_ROOT: ("memory-backup", "kivra-backup", 0o2770),
        module.VERIFICATION_ROOT: ("memory-recovery", "kivra-backup", 0o2750),
        module.STAGING_ROOT: ("memory-backup", "kivra-backup", 0o2770),
    }

    readme = " ".join((BACKUP_ROOT / "README.md").read_text().split())
    assert "backup mount as `root:kivra-backup` mode `0750`" in readme
    assert "store and `base` as `memory-backup:kivra-backup` mode `2750`" in readme
    assert "`wal`, `status`, and `.staging` as `memory-backup:kivra-backup` mode `2770`" in readme
    assert "`verification` as `memory-recovery:kivra-backup` mode `2750`" in readme
    assert (
        "staging mount is a distinct, local controlled filesystem owned by "
        "`memory-backup:memory-backup` mode `0700`" in readme
    )
    assert "recovery mount as `root:memory-recovery` mode `0770`" in readme

    base = (SYSTEMD / "kivra-memory-base-backup.service").read_text()
    verify = (SYSTEMD / "kivra-memory-backup-verify.service").read_text()
    retention = (SYSTEMD / "kivra-memory-backup-retention.service").read_text()
    assert "User=memory-backup\nGroup=kivra-backup" in base
    assert "User=memory-backup\nGroup=kivra-backup" in retention
    assert "User=memory-recovery\nGroup=memory-recovery" in verify
    assert "SupplementaryGroups=kivra-backup" in verify
    assert "/kivra-memory-postgres/verification" in verify


def test_helper_readme_share_exact_credential_and_metadata_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load()
    ownership_calls: dict[Path, tuple[str, str, int]] = {}

    def record(path: Path, *, owner: str, group: str, mode: int) -> None:
        ownership_calls[path] = (owner, group, mode)

    values = {
        module.RECIPIENT_FILE: "age1" + "q" * 58,
        module.RELEASE_FILE: "a" * 40,
        module.CONFIG_DIGEST_FILE: "b" * 64,
    }
    monkeypatch.setattr(module, "_require_owned", record)
    monkeypatch.setattr(module, "_require_regular_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_require_executable", lambda _path: None)
    monkeypatch.setattr(
        module,
        "_read_small_text",
        lambda path, **_kwargs: values[path],
    )

    module._validate_recipient()
    module._validate_identity()
    assert module._deployment_metadata() == ("a" * 40, "b" * 64)
    assert ownership_calls == {
        module.RECIPIENT_FILE: ("root", "kivra-backup", 0o640),
        module.IDENTITY_FILE: ("memory-recovery", "memory-recovery", 0o600),
        module.RELEASE_FILE: ("root", "root", 0o644),
        module.CONFIG_DIGEST_FILE: ("root", "root", 0o644),
    }

    readme = " ".join((BACKUP_ROOT / "README.md").read_text().split())
    assert "public recipient as `root:kivra-backup` mode `0640`" in readme
    assert "`REVISION` and `recovery-configuration.sha256` as `root:root` mode `0644`" in readme
    assert "`memory-recovery` identity as mode `0600`" in readme
