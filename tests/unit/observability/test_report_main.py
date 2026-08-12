from __future__ import annotations

import pytest
from kivra_memory.observability import report_main


def test_operator_report_cli_rejects_non_root_before_database_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(report_main.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as raised:
        report_main.main(["--tenant-id", "01970000-0000-7000-8000-000000000001"])
    assert raised.value.code == 77
    assert capsys.readouterr().err == "ScaleVault operator report requires root\n"


@pytest.mark.asyncio
async def test_operator_report_cli_rejects_missing_database_url_without_echo() -> None:
    arguments = report_main._parser().parse_args(  # pyright: ignore[reportPrivateUsage]
        ["--tenant-id", "01970000-0000-7000-8000-000000000001"]
    )
    with pytest.raises(ValueError, match="database_url_unavailable"):
        await report_main._run(arguments, {})  # pyright: ignore[reportPrivateUsage]
