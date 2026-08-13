from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from kivra_memory.security import operational_canary

CANARY = b"SYNTHETIC_OPERATIONAL_CANARY"


def _protected_reader(path: Path, **_options: object) -> bytes:
    return path.read_bytes()


def test_operational_scan_reports_only_bounded_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    clean = tmp_path / "clean.capture"
    matching = tmp_path / "matching.capture"
    clean.write_bytes(b"fixed content-free diagnostic")
    matching.write_bytes(base64.urlsafe_b64encode(CANARY).rstrip(b"="))
    artifact_list = tmp_path / "artifacts"
    artifact_list.write_text(f"{clean}\n{matching}\n")
    canary_file = tmp_path / "canaries"
    canary_file.write_bytes(CANARY + b"\n")
    monkeypatch.setattr(operational_canary, "read_protected_file", _protected_reader)

    exit_code = operational_canary.main(
        ["--artifact-list", str(artifact_list), "--canary-file", str(canary_file)]
    )

    output = capsys.readouterr()
    result = json.loads(output.out)
    assert exit_code == 1
    assert result == {
        "ok": False,
        "result": "match",
        "counts": {
            "bytes_scanned": len(clean.read_bytes()) + len(matching.read_bytes()),
            "inputs_scanned": 2,
            "matches": 1,
        },
    }
    assert CANARY.decode() not in output.out + output.err
    assert str(clean) not in output.out + output.err


def test_operational_scan_clean_and_incomplete_are_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clean = tmp_path / "clean.capture"
    clean.write_bytes(b"clean")
    monkeypatch.setattr(operational_canary, "read_protected_file", _protected_reader)

    result = operational_canary.scan_operational_captures([clean], [CANARY])
    incomplete = operational_canary.scan_operational_captures([], [CANARY])

    assert result.ok and result.result == "clean" and result.matches == 0
    assert not incomplete.ok and incomplete.result == "incomplete"


def test_operational_cli_rejects_duplicate_or_relative_capture_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact_list = tmp_path / "artifacts"
    artifact_list.write_text("relative.capture\nrelative.capture\n")
    canary_file = tmp_path / "canaries"
    canary_file.write_bytes(CANARY + b"\n")
    monkeypatch.setattr(operational_canary, "read_protected_file", _protected_reader)

    exit_code = operational_canary.main(
        ["--artifact-list", str(artifact_list), "--canary-file", str(canary_file)]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "result": "incomplete",
        "counts": {"bytes_scanned": 0, "inputs_scanned": 0, "matches": 0},
    }


def test_operational_cli_sanitizes_internal_reader_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = tmp_path / "capture"
    capture.write_bytes(b"clean")
    artifact_list = tmp_path / "artifacts"
    artifact_list.write_text(f"{capture}\n")
    canary_file = tmp_path / "canaries"
    canary_file.write_bytes(CANARY + b"\n")

    def failing_reader(path: Path, **_options: object) -> bytes:
        if path == capture:
            raise RuntimeError(f"{CANARY.decode()}:{capture}")
        return path.read_bytes()

    monkeypatch.setattr(operational_canary, "read_protected_file", failing_reader)
    exit_code = operational_canary.main(
        ["--artifact-list", str(artifact_list), "--canary-file", str(canary_file)]
    )

    output = capsys.readouterr()
    assert exit_code == 1
    assert json.loads(output.out)["result"] == "incomplete"
    assert CANARY.decode() not in output.out + output.err
    assert str(capture) not in output.out + output.err
