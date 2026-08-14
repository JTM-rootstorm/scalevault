from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from kivra_memory.observability import retention_caps


def _manifest() -> dict[str, object]:
    return {
        "surfaces": {
            name: {"maximum_age_days": maximum_days, "maximum_bytes": 1024}
            for name, maximum_days in retention_caps.SURFACE_MAXIMUM_DAYS.items()
        },
        "version": 1,
    }


def test_retention_cap_manifest_covers_each_surface_separately() -> None:
    result = retention_caps.validate_retention_cap_manifest(_manifest())
    assert result["ok"] is True
    assert result["result"] == "retention_cap_manifest_valid"
    assert result["counts"] == {"surfaces": 7}
    assert len(result["config_sha256"]) == 64


@pytest.mark.parametrize(
    "change",
    (
        lambda value: value["surfaces"].pop("postgresql_logs"),
        lambda value: value["surfaces"]["prometheus_history"].update(maximum_age_days=31),
        lambda value: value["surfaces"]["tunnel_json"].update(maximum_bytes=0),
    ),
)
def test_retention_cap_manifest_rejects_missing_or_unbounded_surface(
    change: Callable[[dict[str, object]], object],
) -> None:
    value = _manifest()
    change(value)
    with pytest.raises(ValueError, match="retention_cap_manifest_invalid"):
        retention_caps.validate_retention_cap_manifest(value)


def test_retention_cap_cli_is_content_free_and_requires_protected_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "private-location.json"
    manifest.write_text(json.dumps(_manifest()))
    captured: dict[str, object] = {}

    def reader(path: Path, **options: object) -> bytes:
        captured["path"] = path
        captured.update(options)
        return path.read_bytes()

    monkeypatch.setattr(retention_caps, "read_protected_file", reader)
    assert retention_caps.main(["--manifest", str(manifest)]) == 0

    output = capsys.readouterr()
    assert json.loads(output.out)["result"] == "retention_cap_manifest_valid"
    assert str(manifest) not in output.out + output.err
    assert captured["required_owner_uid"] == 0
    assert captured["allowed_modes"] == frozenset({0o600})


def test_repository_example_requires_operator_selected_nonzero_caps() -> None:
    root = Path(__file__).resolve().parents[3]
    example = json.loads(
        (root / "deploy/memory-node/operations/retention-caps.json.example").read_text()
    )
    with pytest.raises(ValueError, match="retention_cap_manifest_invalid"):
        retention_caps.validate_retention_cap_manifest(example)
