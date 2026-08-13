from __future__ import annotations

from pathlib import Path

import pytest
from kivra_memory.observability import report_main, report_runner

TENANT = "01970000-0000-7000-8000-000000000001"


def _credential(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str) -> None:
    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    credential = directory / report_runner.TENANT_CREDENTIAL_NAME
    credential.write_text(value)
    credential.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))


def test_systemd_runner_binds_tenant_credential_to_fixed_output_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _credential(monkeypatch, tmp_path, TENANT)
    invocations: list[list[str]] = []
    monkeypatch.setattr(report_main, "main", lambda argv: invocations.append(argv))

    report_runner.main(["--report-id", "daily-20260812t120000z"])

    assert invocations == [
        [
            "--tenant-id",
            TENANT,
            "--output",
            "/var/lib/kivra-memory/operator-reports/daily-20260812t120000z.json",
        ]
    ]


@pytest.mark.parametrize(
    "report_id",
    ["../escape", "contains.dot", "UPPERCASE", "slash/name", "a" * 65],
)
def test_systemd_runner_rejects_unsafe_report_ids(report_id: str) -> None:
    with pytest.raises(SystemExit) as raised:
        report_runner.main(["--report-id", report_id])
    assert raised.value.code == 2


@pytest.mark.parametrize(
    "tenant",
    [
        "not-a-uuid",
        "01970000-0000-4000-8000-000000000001",
        "01970000-0000-7000-8000-000000000001\n",
    ],
)
def test_systemd_runner_rejects_invalid_tenant_credential(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    tenant: str,
) -> None:
    _credential(monkeypatch, tmp_path, tenant)
    with pytest.raises(SystemExit) as raised:
        report_runner.main(["--report-id", "daily"])
    assert raised.value.code == 1
    assert capsys.readouterr().err == "ScaleVault operator report failed\n"
