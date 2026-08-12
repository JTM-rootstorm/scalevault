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
    archived = tmp_path / "postgres-archive"
    backup_mount = tmp_path / "backup-mount"
    recovery_mount = tmp_path / "recovery-mount"
    plaintext_staging_mount = tmp_path / "plaintext-staging-mount"
    for path in (socket_dir, archived, backup_mount, recovery_mount, plaintext_staging_mount):
        path.mkdir(mode=0o700)
    source_port = _port()
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
                    f"archive_command = 'test ! -f {archived}/%f && cp %p {archived}/%f'",
                    "log_statement = 'none'",
                    "",
                )
            )
        )
    source_running = False
    restored_running = False
    restored = recovery_mount / "pitr-drill"
    try:
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
        original_ismount = module.os.path.ismount
        monkeypatch.setattr(
            module.os.path,
            "ismount",
            lambda path: (
                Path(path) in {backup_mount, recovery_mount, plaintext_staging_mount}
                or original_ismount(path)
            ),
        )

        module.base_backup()
        backup_id = json.loads((module.STATUS_ROOT / "latest-base.json").read_text())["object_id"]
        _psql(psql, socket_dir, source_port, "INSERT INTO pitr_probe VALUES (2)")
        _psql(psql, socket_dir, source_port, "SELECT pg_create_restore_point('after_b')")
        _psql(psql, socket_dir, source_port, "INSERT INTO pitr_probe VALUES (3)")
        _psql(psql, socket_dir, source_port, "SELECT pg_switch_wal()")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not list(archived.glob("[0-9A-F]" * 24)):
            time.sleep(0.1)
        for archived_wal in sorted(archived.iterdir()):
            source_wal = module.PG_WAL / archived_wal.name
            if module.WAL_RE.fullmatch(archived_wal.name) and source_wal.is_file():
                module.archive_wal(str(source_wal), archived_wal.name)
        assert list(module.WAL_ROOT.iterdir()), "no encrypted WAL object was published"
        _run([str(pg_ctl), f"--pgdata={data}", "--wait", "--mode=fast", "stop"])
        source_running = False

        module.prepare_restore(backup_id, str(restored), "name", "after_b")
        restore_wrapper = tmp_path / "restore-wal"
        restore_wrapper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            f'exec {age} --decrypt -i {identity} -o "$2" '
            f'{module.WAL_ROOT}/"$1"/segment.age\n',
            encoding="utf-8",
        )
        restore_wrapper.chmod(0o700)
        with (restored / "postgresql.auto.conf").open("a", encoding="utf-8") as config:
            config.write(f"restore_command = '{restore_wrapper} %f %p'\n")
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
