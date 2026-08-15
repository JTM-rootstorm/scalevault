from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/memory-node/scripts/kivra-memory-operational-metrics-publish"
SYSTEMD = ROOT / "deploy/memory-node/systemd"


def _load() -> ModuleType:
    specification = importlib.util.spec_from_loader(
        "operational_metrics_publish",
        SourceFileLoader("operational_metrics_publish", str(SCRIPT)),
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _configure(module: ModuleType, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_status = root / "latest-base.json"
    archive_status = root / "archive_status"
    output = root / "output"
    memory_capacity = root / "memory-capacity"
    monitoring_capacity = root / "monitoring-capacity"
    archive_status.mkdir()
    output.mkdir(mode=0o750)
    output.chmod(0o750)
    for path in (memory_capacity, monitoring_capacity):
        path.mkdir()
    base_status.write_text(
        json.dumps({"object_id": "20260813T120000Z-0123456789abcdef", "result": "ok"})
    )
    base_status.chmod(0o640)
    counter_values = {
        "base_backup": {
            "base_backup_failure": 0,
            "base_backup_success": 1,
            "version": 1,
        },
        "backup_verification": {
            "backup_verification_failure": 0,
            "backup_verification_success": 1,
            "version": 1,
        },
        "wal_archive": {
            "version": 1,
            "wal_archive_failure_command": 0,
            "wal_archive_failure_storage": 0,
            "wal_archive_failure_timeout": 0,
            "wal_archive_failure_unavailable": 0,
            "wal_archive_success": 1,
        },
    }
    counter_paths = {name: root / f"counter-{name}.json" for name in counter_values}
    for name, path in counter_paths.items():
        path.write_text(json.dumps(counter_values[name]))
        path.chmod(0o640)
    module.__dict__.update(
        {
            "BASE_STATUS": base_status,
            "COUNTER_STATUS": counter_paths,
            "PG_ARCHIVE_STATUS": archive_status,
            "OUTPUT_ROOT": output,
            "OUTPUT_PATH": output / "status.json",
            "MEMORY_CAPACITY_ROOT": memory_capacity,
            "MONITORING_CAPACITY_ROOT": monitoring_capacity,
        }
    )
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "_output_ids", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(module, "_backup_status_ids", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(
        module,
        "_counter_status_ids",
        lambda: {name: (os.getuid(), os.getgid()) for name in counter_paths},
    )


def test_publisher_emits_only_fixed_content_free_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    ready = module.PG_ARCHIVE_STATUS / ("0" * 24 + ".ready")
    ready.touch()
    os.utime(ready, (1_786_622_460, 1_786_622_460))
    monkeypatch.setattr(module, "_now_unixtime", lambda: 1_786_622_500)

    assert module.main() == 0

    output = capsys.readouterr()
    status = json.loads(module.OUTPUT_PATH.read_text())
    assert output.out == "operational_metrics_published\n"
    assert output.err == ""
    assert set(status) == {
        "generated_at_unixtime",
        "latest_base_unixtime",
        "result_counters",
        "storage_free_bytes",
        "storage_free_ratio",
        "version",
        "wal_oldest_ready_unixtime",
    }
    assert status["version"] == 1
    assert status["wal_oldest_ready_unixtime"] == 1_786_622_460
    assert status["result_counters"]["wal_archive_success"] == 1
    assert set(status["storage_free_bytes"]) == {"backup", "database", "monitoring", "wal"}
    assert status["storage_free_bytes"]["backup"] == status["storage_free_bytes"]["database"]
    assert status["storage_free_bytes"]["database"] == status["storage_free_bytes"]["wal"]
    assert status["storage_free_ratio"]["backup"] == status["storage_free_ratio"]["database"]
    assert status["storage_free_ratio"]["database"] == status["storage_free_ratio"]["wal"]
    assert module.OUTPUT_PATH.stat().st_mode & 0o777 == 0o640
    assert str(tmp_path) not in output.out + output.err + module.OUTPUT_PATH.read_text()


def test_publisher_fails_closed_without_replacing_last_good_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    module.OUTPUT_PATH.write_text("last-good")
    module.OUTPUT_PATH.chmod(0o640)
    module.BASE_STATUS.write_text("PRIVATE_CANARY")
    module.BASE_STATUS.chmod(0o640)

    assert module.main() == 1

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "operational_metrics_input_invalid\n"
    assert "PRIVATE_CANARY" not in output.err
    assert module.OUTPUT_PATH.read_text() == "last-good"


def test_publisher_rejects_latest_base_with_wrong_owner_or_group(tmp_path: Path) -> None:
    module = _load()
    status = tmp_path / "latest-base.json"
    status.write_text('{"object_id":"20260813T120000Z-0123456789abcdef","result":"ok"}')
    status.chmod(0o640)

    with pytest.raises(module.PublishError, match="operational_metrics_input_invalid"):
        module._read_regular(
            status,
            maximum_bytes=4096,
            mode=0o640,
            required_ids=(os.getuid() + 1, os.getgid()),
        )
    with pytest.raises(module.PublishError, match="operational_metrics_input_invalid"):
        module._read_regular(
            status,
            maximum_bytes=4096,
            mode=0o640,
            required_ids=(os.getuid(), os.getgid() + 1),
        )


def test_publisher_rejects_existing_counter_with_wrong_producer_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    expected = {name: (os.getuid(), os.getgid()) for name in module.COUNTER_STATUS}
    expected["wal_archive"] = (os.getuid() + 1, os.getgid())
    monkeypatch.setattr(module, "_counter_status_ids", lambda: expected)

    with pytest.raises(module.PublishError, match="operational_metrics_input_invalid"):
        module._counters()


def test_publisher_without_first_base_is_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    module.BASE_STATUS.unlink()

    assert module.main() == 1

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "operational_metrics_input_unavailable\n"
    assert not module.OUTPUT_PATH.exists()


def test_missing_never_emitted_counters_publish_as_zero_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    for path in module.COUNTER_STATUS.values():
        path.unlink()

    assert module.main() == 0

    status = json.loads(module.OUTPUT_PATH.read_text())
    assert status["result_counters"] == {
        "base_backup_failure": 0,
        "base_backup_success": 0,
        "backup_verification_failure": 0,
        "backup_verification_success": 0,
        "wal_archive_failure_command": 0,
        "wal_archive_failure_storage": 0,
        "wal_archive_failure_timeout": 0,
        "wal_archive_failure_unavailable": 0,
        "wal_archive_success": 0,
    }


def test_storage_preserves_fixed_labels_from_one_shared_memory_capacity_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load()
    _configure(module, tmp_path, monkeypatch)
    memory_values = os.statvfs(module.MEMORY_CAPACITY_ROOT)
    monitoring_values = os.statvfs(module.MONITORING_CAPACITY_ROOT)
    calls: list[Path] = []

    def statvfs(path: Path) -> os.statvfs_result:
        calls.append(Path(path))
        if Path(path) == module.MEMORY_CAPACITY_ROOT:
            return memory_values
        if Path(path) == module.MONITORING_CAPACITY_ROOT:
            return monitoring_values
        raise AssertionError(f"unexpected capacity source: {path}")

    monkeypatch.setattr(module.os, "statvfs", statvfs)

    free_bytes, free_ratios = module._storage()

    assert calls == [module.MEMORY_CAPACITY_ROOT, module.MONITORING_CAPACITY_ROOT]
    assert free_bytes["backup"] == free_bytes["database"] == free_bytes["wal"]
    assert free_ratios["backup"] == free_ratios["database"] == free_ratios["wal"]


def test_operational_metrics_units_keep_backup_store_out_of_exporter() -> None:
    publisher = (SYSTEMD / "kivra-memory-operational-metrics.service").read_text()
    timer = (SYSTEMD / "kivra-memory-operational-metrics.timer").read_text()
    exporter = (SYSTEMD / "kivra-memory-metrics-exporter.service").read_text()
    assert "User=root\nGroup=memory-metrics" in publisher
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in publisher
    assert "RestrictAddressFamilies=AF_UNIX" in publisher
    assert "ReadWritePaths=/run/kivra-memory-metrics" in publisher
    assert "RuntimeDirectoryMode=0750" in publisher
    assert "RequiresMountsFor=/mnt/memory\n" in publisher
    assert "ConditionPathIsMountPoint=/mnt/memory\n" in publisher
    assert "/mnt/memory-backup" not in publisher
    assert publisher.count("ReadOnlyPaths=-/mnt/memory/kivra-memory/backups/postgresql-pitr") == 3
    assert "OnUnitActiveSec=30s" in timer
    assert "ReadOnlyPaths=-/run/kivra-memory-metrics/status.json" in exporter
    assert "/mnt/memory-backup" not in exporter
    assert "Group=kivra-backup" not in exporter
