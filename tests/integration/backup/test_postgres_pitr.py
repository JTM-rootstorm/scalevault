"""Real PostgreSQL 17, WAL, age, and isolated PITR durability acceptance."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any, Never

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/memory-node/scripts/kivra-memory-postgres-backup"


def _unavailable(reason: str) -> Never:
    if os.environ.get("SCALEVAULT_REQUIRE_BACKUP_TESTS") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def _binary(name: str) -> Path:
    bindir = os.environ.get("SCALEVAULT_TEST_PG_BINDIR")
    found = str(Path(bindir) / name) if bindir else shutil.which(name)
    if found is None or not os.access(found, os.X_OK):
        _unavailable(f"backup durability binary {name!r} is unavailable")
    return Path(found)


def _load() -> Any:
    specification = importlib.util.spec_from_loader(
        "postgres_backup_integration", SourceFileLoader("postgres_backup_integration", str(SCRIPT))
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _run(arguments: list[str], *, timeout: int = 120) -> str:
    completed = subprocess.run(
        arguments, check=False, capture_output=True, text=True, timeout=timeout
    )
    if completed.returncode != 0:
        raise RuntimeError(f"backup durability dependency failed: {Path(arguments[0]).name}")
    return completed.stdout.strip()


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _psql(psql: Path, socket_dir: Path, port: int, sql: str) -> str:
    return _run(
        [
            str(psql),
            f"--host={socket_dir}",
            f"--port={port}",
            "--username=postgres",
            "--dbname=postgres",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set=ON_ERROR_STOP=1",
            f"--command={sql}",
        ]
    )


@pytest.mark.database
def test_encrypted_base_backup_and_named_restore_point_pitr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recover A and B but not C through a verified encrypted physical chain."""

    if os.environ.get("SCALEVAULT_REQUIRE_BACKUP_TESTS") != "1":
        pytest.skip("set SCALEVAULT_REQUIRE_BACKUP_TESTS=1 for the durable PITR gate")
    initdb = _binary("initdb")
    pg_ctl = _binary("pg_ctl")
    psql = _binary("psql")
    age_path = shutil.which("age")
    age_keygen_path = shutil.which("age-keygen")
    if age_path is None or age_keygen_path is None:
        _unavailable("age and age-keygen are required for the encrypted PITR gate")
    age = Path(age_path)
    age_keygen = Path(age_keygen_path)
    version = _run([str(initdb), "--version"])
    if not re.search(r"PostgreSQL\) 17(?:\.|$)", version):
        _unavailable("the encrypted PITR gate requires PostgreSQL 17 exactly")

    module = _load()
    data = tmp_path / "source-data"
    socket_dir = tmp_path / "source-socket"
    backup_mount = tmp_path / "backup-mount"
    recovery_mount = tmp_path / "recovery-mount"
    plaintext_staging_mount = tmp_path / "plaintext-staging-mount"
    for path in (socket_dir, backup_mount, recovery_mount, plaintext_staging_mount):
        path.mkdir(mode=0o700)
    source_port = _port()
    installed_helper = tmp_path / "kivra-memory-postgres-backup"
    _run(
        [
            str(initdb),
            f"--pgdata={data}",
            "--username=postgres",
            "--auth-local=trust",
            "--no-locale",
        ]
    )
    with (data / "postgresql.conf").open("a", encoding="utf-8") as config:
        config.write(
            "\n".join(
                (
                    "listen_addresses = ''",
                    f"port = {source_port}",
                    f"unix_socket_directories = '{socket_dir}'",
                    "fsync = on",
                    "full_page_writes = on",
                    "synchronous_commit = on",
                    "wal_level = replica",
                    "archive_mode = on",
                    "archive_timeout = '1s'",
                    f"archive_command = '{installed_helper} archive-wal {data}/%p %f'",
                    "log_statement = 'none'",
                    "",
                )
            )
        )
    source_running = False
    restored_running = False
    restored = recovery_mount / "pitr-drill"
    try:
        identity = tmp_path / "identity.txt"
        _run([str(age_keygen), "-o", str(identity)])
        identity.chmod(0o600)
        recipient = tmp_path / "recipient.txt"
        recipient.write_text(_run([str(age_keygen), "-y", str(identity)]) + "\n", encoding="ascii")
        release = tmp_path / "REVISION"
        release.write_text("a" * 40 + "\n", encoding="ascii")
        config_digest = tmp_path / "configuration.sha256"
        config_digest.write_text("b" * 64 + "\n", encoding="ascii")

        module.PG_BINDIR = initdb.parent
        module.PG_DATA = data
        module.PG_WAL = data / "pg_wal"
        module.PG_SOCKET = socket_dir
        module.PG_PORT = source_port
        module.PG_DATABASE = "postgres"
        module.BACKUP_MOUNT = backup_mount
        module.PLAINTEXT_STAGING_MOUNT = plaintext_staging_mount
        module.STORE = backup_mount / "kivra-memory-postgres"
        module.BASE_ROOT = module.STORE / "base"
        module.WAL_ROOT = module.STORE / "wal"
        module.STATUS_ROOT = module.STORE / "status"
        module.VERIFICATION_ROOT = module.STORE / "verification"
        module.STAGING_ROOT = module.STORE / ".staging"
        module.RECOVERY_MOUNT = recovery_mount
        module.RECIPIENT_FILE = recipient
        module.IDENTITY_FILE = identity
        module.RELEASE_FILE = release
        module.CONFIG_DIGEST_FILE = config_digest
        module.AGE = age
        module.HELPER_PATH = installed_helper
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
        monkeypatch.setattr(module, "_require_fd_owned", lambda *args, **kwargs: None)
        original_ismount = module.os.path.ismount
        monkeypatch.setattr(
            module.os.path,
            "ismount",
            lambda path: (
                Path(path) in {backup_mount, recovery_mount, plaintext_staging_mount}
                or original_ismount(path)
            ),
        )

        installed_helper.write_text(
            "#!/usr/bin/python3\n"
            "import importlib.util\n"
            "from importlib.machinery import SourceFileLoader\n"
            f"script = {str(SCRIPT)!r}\n"
            "loader = SourceFileLoader('backup_installed', script)\n"
            "spec = importlib.util.spec_from_loader('backup_installed', loader)\n"
            "assert spec is not None and spec.loader is not None\n"
            "helper = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(helper)\n"
            f"helper.PG_BINDIR = helper.Path({str(initdb.parent)!r})\n"
            f"helper.PG_DATA = helper.Path({str(data)!r})\n"
            "helper.PG_WAL = helper.PG_DATA / 'pg_wal'\n"
            f"helper.PG_SOCKET = helper.Path({str(socket_dir)!r})\n"
            f"helper.PG_PORT = {source_port}\n"
            "helper.PG_DATABASE = 'postgres'\n"
            f"helper.BACKUP_MOUNT = helper.Path({str(backup_mount)!r})\n"
            f"helper.PLAINTEXT_STAGING_MOUNT = helper.Path({str(plaintext_staging_mount)!r})\n"
            "helper.STORE = helper.BACKUP_MOUNT / 'kivra-memory-postgres'\n"
            "helper.BASE_ROOT = helper.STORE / 'base'\n"
            "helper.WAL_ROOT = helper.STORE / 'wal'\n"
            "helper.STATUS_ROOT = helper.STORE / 'status'\n"
            "helper.VERIFICATION_ROOT = helper.STORE / 'verification'\n"
            "helper.STAGING_ROOT = helper.STORE / '.staging'\n"
            f"helper.RECOVERY_MOUNT = helper.Path({str(recovery_mount)!r})\n"
            f"helper.RECIPIENT_FILE = helper.Path({str(recipient)!r})\n"
            f"helper.IDENTITY_FILE = helper.Path({str(identity)!r})\n"
            f"helper.RELEASE_FILE = helper.Path({str(release)!r})\n"
            f"helper.CONFIG_DIGEST_FILE = helper.Path({str(config_digest)!r})\n"
            f"helper.AGE = helper.Path({str(age)!r})\n"
            f"helper.HELPER_PATH = helper.Path({str(installed_helper)!r})\n"
            "helper._require_owned = lambda *args, **kwargs: None\n"
            "helper._require_fd_owned = lambda *args, **kwargs: None\n"
            "mounts = {helper.BACKUP_MOUNT, helper.PLAINTEXT_STAGING_MOUNT, "
            "helper.RECOVERY_MOUNT}\n"
            "helper.os.path.ismount = lambda path: helper.Path(path) in mounts\n"
            "raise SystemExit(helper.main())\n",
            encoding="utf-8",
        )
        installed_helper.chmod(0o755)

        _run(
            [str(pg_ctl), f"--pgdata={data}", f"--log={tmp_path / 'source.log'}", "--wait", "start"]
        )
        source_running = True
        _psql(psql, socket_dir, source_port, "CREATE ROLE memory_backup LOGIN REPLICATION")
        _psql(
            psql, socket_dir, source_port, "CREATE TABLE alembic_version(version_num text NOT NULL)"
        )
        _psql(psql, socket_dir, source_port, "INSERT INTO alembic_version VALUES ('000000000010')")
        _psql(psql, socket_dir, source_port, "GRANT SELECT ON alembic_version TO memory_backup")
        _psql(psql, socket_dir, source_port, "CREATE TABLE pitr_probe(marker integer PRIMARY KEY)")
        _psql(psql, socket_dir, source_port, "INSERT INTO pitr_probe VALUES (1)")

        module.base_backup()
        backup_id = json.loads((module.STATUS_ROOT / "latest-base.json").read_text())["object_id"]
        _psql(psql, socket_dir, source_port, "INSERT INTO pitr_probe VALUES (2)")
        _psql(psql, socket_dir, source_port, "SELECT pg_create_restore_point('after_b')")
        _psql(psql, socket_dir, source_port, "INSERT INTO pitr_probe VALUES (3)")
        _psql(psql, socket_dir, source_port, "SELECT pg_switch_wal()")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not list(module.WAL_ROOT.iterdir()):
            time.sleep(0.1)
        assert list(module.WAL_ROOT.iterdir()), "no encrypted WAL object was published"
        _run([str(pg_ctl), f"--pgdata={data}", "--wait", "--mode=fast", "stop"])
        source_running = False

        wal_object = next(path for path in module.WAL_ROOT.iterdir() if len(path.name) == 24)
        negative_root = recovery_mount / "negative" / "pg_wal"
        negative_root.mkdir(parents=True, mode=0o700)
        for member_name in ("recovery-manifest.json.age", "segment.age"):
            member = wal_object / member_name
            original = member.read_bytes()
            member.write_bytes(original + b"corrupt")
            member.chmod(0o640)
            completed = subprocess.run(
                [
                    str(installed_helper),
                    "restore-wal",
                    wal_object.name,
                    str(negative_root / wal_object.name),
                ],
                check=False,
                capture_output=True,
                timeout=30,
            )
            assert completed.returncode != 0
            assert not (negative_root / wal_object.name).exists()
            member.write_bytes(original)
            member.chmod(0o640)

        module.prepare_restore(backup_id, str(restored), "name", "after_b")
        recovery_settings = (restored / "postgresql.auto.conf").read_text()
        assert f"restore_command = '{installed_helper} restore-wal %f " in recovery_settings
        restored_socket = tmp_path / "restored-socket"
        restored_socket.mkdir(mode=0o700)
        restored_port = _port()
        _run(
            [
                str(pg_ctl),
                f"--pgdata={restored}",
                f"--log={tmp_path / 'restored.log'}",
                "--wait",
                "--timeout=60",
                "-o",
                f"-c listen_addresses='' -c unix_socket_directories='{restored_socket}' "
                f"-c port={restored_port} -c archive_mode=off",
                "start",
            ],
            timeout=90,
        )
        restored_running = True
        markers = _psql(
            psql, restored_socket, restored_port, "SELECT marker FROM pitr_probe ORDER BY marker"
        )
        assert markers.splitlines() == ["1", "2"]
        assert _psql(psql, restored_socket, restored_port, "SELECT pg_is_in_recovery()") == "t"
    finally:
        if restored_running:
            subprocess.run(
                [str(pg_ctl), f"--pgdata={restored}", "--wait", "--mode=immediate", "stop"],
                check=False,
                capture_output=True,
                timeout=30,
            )
        if source_running:
            subprocess.run(
                [str(pg_ctl), f"--pgdata={data}", "--wait", "--mode=immediate", "stop"],
                check=False,
                capture_output=True,
                timeout=30,
            )
