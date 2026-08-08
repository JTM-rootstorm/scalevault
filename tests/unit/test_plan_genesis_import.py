"""Tests for the local-only zero-write Genesis planner CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from stat import S_IMODE
from types import SimpleNamespace

import pytest
from kivra_memory.application.genesis_plan import GenesisPlanError, GenesisPlanReport

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts import plan_genesis_import as cli  # noqa: E402


def test_exclusive_plan_output_is_mode_0600_and_refuses_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "genesis-plan.json"
    content = b'{"safe":"metadata-only"}\n'

    cli._write_exclusive(destination, content)

    assert destination.read_bytes() == content
    assert S_IMODE(destination.stat().st_mode) == 0o600
    with pytest.raises(GenesisPlanError, match="plan_output_failed"):
        cli._write_exclusive(destination, b'{"overwrite":true}\n')
    assert destination.read_bytes() == content


def test_exclusive_plan_output_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"retained")
    destination = tmp_path / "genesis-plan.json"
    destination.symlink_to(target)

    with pytest.raises(GenesisPlanError, match="plan_output_failed"):
        cli._write_exclusive(destination, b'{"unsafe":true}\n')

    assert target.read_bytes() == b"retained"
    assert destination.is_symlink()


def test_expected_manifest_reader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b'{"safe":"aggregate"}\n')
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)

    with pytest.raises(GenesisPlanError, match="invalid_expected_manifest"):
        cli._read_expected(linked)


def test_cli_plan_writes_only_report_and_safe_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "source.git"
    repository.mkdir()
    destination = tmp_path / "plan.json"
    report = SimpleNamespace(canonical_bytes=b'{"safe":"aggregate"}')
    manifest = SimpleNamespace(digest="a" * 64)
    fake_plan = SimpleNamespace(report=report, manifest=manifest)
    monkeypatch.setattr(cli, "LocalGitObjectReader", lambda _path: object())
    monkeypatch.setattr(cli, "plan_genesis_import", lambda _reader: fake_plan)

    status = cli.main(
        ["plan", "--repository", str(repository), "--output", str(destination)]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert destination.read_bytes() == report.canonical_bytes + b"\n"
    assert captured.err == ""
    assert captured.out == '{"digest":"' + "a" * 64 + '","ok":true,"verified":false}\n'


def test_cli_verify_recomputes_and_compares_expected_safe_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "source.git"
    repository.mkdir()
    expected_path = tmp_path / "expected.json"
    expected_value = {"safe": "aggregate"}
    expected_bytes = b'{"safe":"aggregate"}'
    expected_path.write_bytes(expected_bytes + b"\n")
    # Patch the strict loader in this CLI test; planner tests exercise its full schema.
    expected = GenesisPlanReport(value=expected_value, canonical_bytes=expected_bytes)
    verified: list[GenesisPlanReport] = []
    fake_plan = SimpleNamespace(
        report=expected,
        manifest=SimpleNamespace(digest="b" * 64),
        verify_report=verified.append,
    )
    monkeypatch.setattr(cli, "LocalGitObjectReader", lambda _path: object())
    monkeypatch.setattr(cli, "plan_genesis_import", lambda _reader: fake_plan)
    monkeypatch.setattr(cli, "_read_expected", lambda _path: expected)

    status = cli.main(
        [
            "verify-plan",
            "--repository",
            str(repository),
            "--expected-manifest",
            str(expected_path),
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert verified == [expected]
    assert captured.err == ""
    assert captured.out == '{"digest":"' + "b" * 64 + '","ok":true,"verified":true}\n'


def test_cli_exposes_no_apply_subcommand() -> None:
    with pytest.raises(SystemExit):
        cli._parser().parse_args(["apply"])
