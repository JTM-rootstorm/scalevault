from __future__ import annotations

import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Never

import pytest


def _database_unavailable(reason: str) -> Never:
    if os.environ.get("SCALEVAULT_REQUIRE_DATABASE_TESTS") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def _postgresql_binary(name: str) -> str:
    bindir = os.environ.get("SCALEVAULT_TEST_PG_BINDIR")
    candidate = str(Path(bindir) / name) if bindir else shutil.which(name)
    if candidate is None or not os.access(candidate, os.X_OK):
        _database_unavailable(
            f"PostgreSQL test binary {name!r} is unavailable; install PostgreSQL 17+ "
            "or set SCALEVAULT_TEST_PG_BINDIR"
        )
    return candidate


def _available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run(command: list[str], *, timeout: int = 120) -> None:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part)
        raise RuntimeError(f"PostgreSQL test command failed ({command[0]}):\n{output}")


def _require_supported_postgresql(initdb: str) -> None:
    completed = subprocess.run(
        [initdb, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    match = re.search(r"PostgreSQL\)\s+(\d+)", completed.stdout)
    if completed.returncode != 0 or match is None:
        raise RuntimeError("could not determine the selected PostgreSQL version")
    if int(match.group(1)) < 17:
        _database_unavailable("ScaleVault integration tests require PostgreSQL 17 or newer")


def _stop_after_failed_start(pg_ctl: str, data_directory: Path) -> None:
    with suppress(subprocess.TimeoutExpired):
        subprocess.run(
            [
                pg_ctl,
                "--pgdata",
                str(data_directory),
                "--wait",
                "--timeout",
                "15",
                "--mode",
                "immediate",
                "stop",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )


class PostgreSQLTestServer:
    """An isolated PostgreSQL cluster whose credentials never enter command arguments."""

    def __init__(self, *, pg_ctl: str, data_directory: Path, database_url: str) -> None:
        self._pg_ctl = pg_ctl
        self._data_directory = data_directory
        self.database_url = database_url
        self._running = True

    def __repr__(self) -> str:
        return f"PostgreSQLTestServer(running={self._running!r})"

    def stop(self) -> None:
        if not self._running:
            return
        _run(
            [
                self._pg_ctl,
                "--pgdata",
                str(self._data_directory),
                "--wait",
                "--timeout",
                "15",
                "--mode",
                "immediate",
                "stop",
            ]
        )
        self._running = False


@pytest.fixture
def postgresql_server() -> Iterator[PostgreSQLTestServer]:
    """Start a password-protected, run-scoped PostgreSQL 17+ test cluster."""

    initdb = _postgresql_binary("initdb")
    pg_ctl = _postgresql_binary("pg_ctl")
    _require_supported_postgresql(initdb)
    username = "scalevault_test"
    password = secrets.token_urlsafe(32)
    port = _available_loopback_port()

    with tempfile.TemporaryDirectory(prefix="scalevault-postgres-") as temporary_directory:
        root = Path(temporary_directory)
        data_directory = root / "data"
        password_file = root / "password"
        log_file = root / "postgres.log"
        password_file.write_text(password, encoding="utf-8")
        password_file.chmod(0o600)

        _run(
            [
                initdb,
                "--pgdata",
                str(data_directory),
                "--username",
                username,
                "--pwfile",
                str(password_file),
                "--auth-host",
                "scram-sha-256",
                "--auth-local",
                "trust",
                "--encoding",
                "UTF8",
                "--no-locale",
                "--no-sync",
            ]
        )
        password_file.unlink()

        with (data_directory / "postgresql.conf").open("a", encoding="utf-8") as config:
            config.write(
                "\n".join(
                    (
                        "listen_addresses = '127.0.0.1'",
                        f"port = {port}",
                        "unix_socket_directories = ''",
                        "fsync = off",
                        "synchronous_commit = off",
                        "full_page_writes = off",
                        "log_connections = off",
                        "log_disconnections = off",
                        "log_statement = 'none'",
                        "",
                    )
                )
            )

        try:
            _run(
                [
                    pg_ctl,
                    "--pgdata",
                    str(data_directory),
                    "--log",
                    str(log_file),
                    "--wait",
                    "--timeout",
                    "15",
                    "start",
                ]
            )
        except BaseException:
            _stop_after_failed_start(pg_ctl, data_directory)
            raise
        server = PostgreSQLTestServer(
            pg_ctl=pg_ctl,
            data_directory=data_directory,
            database_url=(f"postgresql://{username}:{password}@127.0.0.1:{port}/postgres"),
        )
        try:
            yield server
        finally:
            server.stop()
