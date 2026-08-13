from __future__ import annotations

import os
from pathlib import Path

import pytest
from kivra_memory.observability import report_main

TENANT = "01970000-0000-7000-8000-000000000001"


def _protected_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _credential(monkeypatch: pytest.MonkeyPatch, path: Path, value: str) -> None:
    directory = _protected_directory(path)
    credential = directory / report_main.DATABASE_CREDENTIAL_NAME
    credential.write_text(value)
    credential.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))


def test_operator_report_cli_rejects_non_root_before_database_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as raised:
        report_main.main(["--tenant-id", TENANT, "--output", str(tmp_path / "report.json")])
    assert raised.value.code == 77
    assert capsys.readouterr().err == "ScaleVault operator report requires root\n"


def test_database_url_comes_only_from_fixed_systemd_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        "SCALEVAULT_DATABASE_URL",
        "postgresql://attacker@remote.invalid/private",
    )
    with pytest.raises(ValueError, match="database_credential_invalid"):
        report_main._database_url_from_systemd_credential()

    _credential(
        monkeypatch,
        tmp_path / "credentials",
        "postgresql+psycopg://kivra_memory_operator_report_login:secret@127.0.0.1/kivra_memory",
    )
    assert "kivra_memory_operator_report_login" in (
        report_main._database_url_from_systemd_credential()
    )


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://kivra_memory_api@database.invalid/kivra_memory",
        "postgresql+psycopg://kivra_memory_owner@127.0.0.1/kivra_memory",
        "postgresql+psycopg://kivra_memory_api@127.0.0.1/other_database",
        "postgresql+psycopg://kivra_memory_api@127.0.0.1/kivra_memory?hostaddr=10.0.0.1",
        "sqlite:///tmp/kivra-memory.db",
    ],
)
def test_database_boundary_rejects_other_roles_and_remote_coordinates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, database_url: str
) -> None:
    _credential(monkeypatch, tmp_path / "credentials", database_url)
    with pytest.raises(ValueError, match="database_credential_invalid"):
        report_main._database_url_from_systemd_credential()


def test_report_output_is_atomic_mode_0600_and_never_overwrites(tmp_path: Path) -> None:
    protected = _protected_directory(tmp_path / "protected")
    destination = protected / "report.json"
    report_main._publish_report(destination, b'{"safe":"aggregate"}\n')
    assert destination.read_bytes() == b'{"safe":"aggregate"}\n'
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.stat().st_nlink == 1
    with pytest.raises(ValueError, match="output_failed"):
        report_main._publish_report(destination, b'{"replacement":true}\n')
    assert destination.read_bytes() == b'{"safe":"aggregate"}\n'
    assert not tuple(protected.glob(".operator-report-*.tmp"))


def test_report_output_rejects_symlink_and_unprotected_parent(tmp_path: Path) -> None:
    protected = _protected_directory(tmp_path / "protected")
    target = protected / "target"
    target.write_text("sentinel")
    destination = protected / "report.json"
    destination.symlink_to(target)
    with pytest.raises(ValueError, match="output_failed"):
        report_main._publish_report(destination, b"{}\n")
    assert target.read_text() == "sentinel"

    destination.unlink()
    protected.chmod(0o750)
    with pytest.raises(ValueError, match="output_failed"):
        report_main._publish_report(destination, b"{}\n")
    assert not destination.exists()


def test_report_output_cleans_reservation_after_publish_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    protected = _protected_directory(tmp_path / "protected")
    destination = protected / "report.json"

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(ValueError, match="output_failed"):
        report_main._publish_report(destination, b"{}\n")
    assert not destination.exists()
    assert not tuple(protected.iterdir())


def test_successful_cli_writes_only_to_protected_destination(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.json"
    published: list[tuple[Path, bytes]] = []

    async def render(_arguments: object, _database_url: str) -> bytes:
        return b'{"safe":"aggregate"}\n'

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        report_main,
        "_database_url_from_systemd_credential",
        lambda: "postgresql+psycopg://kivra_memory_operator_report_login@127.0.0.1/kivra_memory",
    )
    monkeypatch.setattr(report_main, "_render", render)
    monkeypatch.setattr(
        report_main, "_publish_report", lambda path, body: published.append((path, body))
    )

    report_main.main(["--tenant-id", TENANT, "--output", str(destination)])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert published == [(destination, b'{"safe":"aggregate"}\n')]
