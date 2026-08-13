"""Deterministic release preparation and content-free installed-audit contracts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "deploy" / "memory-node" / "scripts"
PREPARE = SCRIPTS / "kivra-memory-release-prepare"
AUDIT = SCRIPTS / "kivra-memory-installed-audit"
BACKUP = SCRIPTS / "kivra-memory-postgres-backup"
POSTGRESQL_EXAMPLE = ROOT / "deploy" / "memory-node" / "backup" / "postgresql.conf.example"
REVISION = "a" * 40
MIGRATION = "0011_observability_aggregates"
ENTRY_POINTS = (
    "kivra-memory-api",
    "kivra-memory-archive-recovery",
    "kivra-memory-archive-exporter",
    "kivra-memory-codex-ingress",
    "kivra-memory-credential-admin",
    "kivra-memory-diagnose",
    "kivra-memory-destruction-broker",
    "kivra-memory-github-ingress",
    "kivra-memory-lifecycle-worker",
    "kivra-memory-metrics-exporter",
    "kivra-memory-operator-report",
    "kivra-memory-operator-report-run",
    "kivra-memory-scan-operational-canaries",
    "kivra-memory-scan-public-artifact",
    "kivra-memory-sealed-restore-reconcile",
    "kivra-memory-sealed-worker",
    "kivra-memory-worker",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _release(tmp_path: Path, *, owner_read_only: bool = False) -> tuple[Path, Path, Path]:
    releases = tmp_path / "releases"
    archives = tmp_path / "archives"
    release = releases / REVISION
    release.mkdir(parents=True)
    archive = archives / f"{REVISION}.tar"
    archive.parent.mkdir()
    archive.write_bytes(b"deterministic source archive")
    digest = _sha256(archive)
    (release / "REVISION").write_text(f"{REVISION}\n", encoding="ascii")
    (release / "SOURCE_ARCHIVE.sha256").write_text(f"{digest}\n", encoding="ascii")
    (release / "EXPECTED_MIGRATION").write_text(f"{MIGRATION}\n", encoding="ascii")
    manifest = {
        "deployment_script_sha256": {},
        "expected_migration": MIGRATION,
        "executable_sha256": {},
        "revision": REVISION,
        "source_archive_sha256": digest,
        "version": 1,
    }
    (release / "RELEASE_MANIFEST.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    if owner_read_only:
        archive.chmod(0o444)
        for path in release.iterdir():
            path.chmod(0o444)
        release.chmod(0o555)
    return release, releases, archives


def test_release_scripts_are_executable_and_content_free() -> None:
    assert os.access(PREPARE, os.X_OK)
    assert os.access(AUDIT, os.X_OK)
    audit = AUDIT.read_text(encoding="utf-8")
    assert (
        "read_bytes()"
        not in audit.split("def _credential_metadata", 1)[1].split("def _release", 1)[0]
    )
    assert "stderr=subprocess.DEVNULL" in audit
    assert "SELECT version_num FROM alembic_version" in audit


def test_pointer_plan_is_bounded_and_apply_is_atomic(tmp_path: Path) -> None:
    release, _, _ = _release(tmp_path, owner_read_only=True)
    pointer = tmp_path / "app"
    plan = tmp_path / "pointer-plan.json"

    planned = subprocess.run(
        [
            PREPARE,
            "plan-pointer",
            "--release",
            release,
            "--pointer",
            pointer,
            "--expected-current",
            "absent",
            "--plan-file",
            plan,
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert planned.returncode == 0, planned.stderr
    assert planned.stdout == f"release_pointer_plan_ready\nrevision={REVISION}\n"
    assert plan.stat().st_mode & 0o777 == 0o600
    plan_body = json.loads(plan.read_text(encoding="utf-8"))
    assert plan_body["release"] == str(release)
    assert plan_body["pointer"] == str(pointer)
    assert plan_body["expected_current"] == "absent"

    applied = subprocess.run(
        [PREPARE, "apply-pointer", "--plan-file", plan],
        text=True,
        capture_output=True,
        check=False,
    )

    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == f"release_pointer_applied\nrevision={REVISION}\n"
    assert pointer.is_symlink()
    assert os.readlink(pointer) == str(release)


def test_pointer_apply_rejects_changed_current_pointer(tmp_path: Path) -> None:
    release, releases, _ = _release(tmp_path, owner_read_only=True)
    prior = releases / ("b" * 40)
    prior.mkdir(mode=0o555)
    other = releases / ("c" * 40)
    other.mkdir(mode=0o555)
    pointer = tmp_path / "app"
    pointer.symlink_to(prior)
    plan = tmp_path / "pointer-plan.json"
    planned = subprocess.run(
        [
            PREPARE,
            "plan-pointer",
            "--release",
            release,
            "--pointer",
            pointer,
            "--expected-current",
            str(prior),
            "--plan-file",
            plan,
        ],
        capture_output=True,
        check=False,
    )
    assert planned.returncode == 0
    pointer.unlink()
    pointer.symlink_to(other)

    applied = subprocess.run(
        [PREPARE, "apply-pointer", "--plan-file", plan],
        text=True,
        capture_output=True,
        check=False,
    )

    assert applied.returncode != 0
    assert applied.stdout == ""
    assert applied.stderr == "release_pointer_changed\n"
    assert os.readlink(pointer) == str(other)


def test_prepare_rejects_tracked_drift_before_writing(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "release-test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Release Test"], cwd=repository, check=True)
    tracked = repository / "tracked"
    tracked.write_text("tracked\n", encoding="utf-8")
    deployment_scripts = repository / "deploy" / "memory-node" / "scripts"
    deployment_scripts.mkdir(parents=True)
    deployment_script = deployment_scripts / "kivra-memory-example"
    deployment_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked", "deploy"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repository, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    tracked.write_text("dirty\n", encoding="utf-8")

    result = subprocess.run(
        [
            PREPARE,
            "prepare",
            "--repository",
            repository,
            "--revision",
            revision,
            "--releases-root",
            tmp_path / "releases",
            "--archives-root",
            tmp_path / "archives",
            "--uv",
            "/bin/true",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr == "repository_dirty\n"
    assert not (tmp_path / "releases").exists()
    assert not (tmp_path / "archives").exists()


def test_prepare_preserves_untracked_operator_inputs(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "release-test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Release Test"], cwd=repository, check=True)
    tracked = repository / "tracked"
    tracked.write_text("tracked\n", encoding="utf-8")
    deployment_scripts = repository / "deploy" / "memory-node" / "scripts"
    deployment_scripts.mkdir(parents=True)
    deployment_script = deployment_scripts / "kivra-memory-example"
    deployment_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked", "deploy"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repository, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    untracked = repository / "operator-plan.md"
    untracked.write_text("preserve me\n", encoding="utf-8")

    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        "#!/usr/bin/python3\n"
        "import pathlib, sys\n"
        "project = pathlib.Path(sys.argv[sys.argv.index('--project') + 1])\n"
        f"names = {ENTRY_POINTS!r}\n"
        "binary = project / '.venv' / 'bin'\n"
        "binary.mkdir(parents=True)\n"
        "for name in names:\n"
        "    target = binary / name\n"
        "    target.write_bytes(b'#!/bin/sh\\nexit 0\\n')\n"
        "    target.chmod(0o755)\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    result = subprocess.run(
        [
            PREPARE,
            "prepare",
            "--repository",
            repository,
            "--revision",
            revision,
            "--releases-root",
            tmp_path / "releases",
            "--archives-root",
            tmp_path / "archives",
            "--uv",
            fake_uv,
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert untracked.read_text(encoding="utf-8") == "preserve me\n"


def test_prepare_produces_repeatable_archives_and_read_only_releases(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "release-test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Release Test"], cwd=repository, check=True)
    tracked = repository / "tracked"
    tracked.write_text("tracked\n", encoding="utf-8")
    deployment_scripts = repository / "deploy" / "memory-node" / "scripts"
    deployment_scripts.mkdir(parents=True)
    deployment_script = deployment_scripts / "kivra-memory-example"
    deployment_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked", "deploy"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repository, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        "#!/usr/bin/python3\n"
        "import pathlib, sys\n"
        "project = pathlib.Path(sys.argv[sys.argv.index('--project') + 1])\n"
        f"names = {ENTRY_POINTS!r}\n"
        "binary = project / '.venv' / 'bin'\n"
        "binary.mkdir(parents=True)\n"
        "for name in names:\n"
        "    target = binary / name\n"
        "    target.write_bytes(b'#!/bin/sh\\nexit 0\\n')\n"
        "    target.chmod(0o755)\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    archive_digests: list[str] = []

    for index in (1, 2):
        releases = tmp_path / f"releases-{index}"
        archives = tmp_path / f"archives-{index}"
        result = subprocess.run(
            [
                PREPARE,
                "prepare",
                "--repository",
                repository,
                "--revision",
                revision,
                "--releases-root",
                releases,
                "--archives-root",
                archives,
                "--uv",
                fake_uv,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        archive = archives / f"{revision}.tar"
        release = releases / revision
        archive_digests.append(_sha256(archive))
        assert result.stdout == (
            "release_prepared\n"
            f"revision={revision}\n"
            f"source_archive_sha256={archive_digests[-1]}\n"
            f"migration_head={MIGRATION}\n"
        )
        assert archive.stat().st_mode & 0o777 == 0o444
        assert release.stat().st_mode & 0o222 == 0
        assert all(path.stat().st_mode & 0o222 == 0 for path in release.rglob("*"))
        manifest = json.loads((release / "RELEASE_MANIFEST.json").read_text())
        assert manifest["revision"] == revision
        assert manifest["source_archive_sha256"] == archive_digests[-1]
        assert set(manifest["executable_sha256"]) == set(ENTRY_POINTS)
        assert set(manifest["deployment_script_sha256"]) == {"kivra-memory-example"}

    assert archive_digests[0] == archive_digests[1]


def test_backup_helper_uses_the_canonical_mounted_postgresql_path() -> None:
    helper = BACKUP.read_text(encoding="utf-8")
    postgresql = POSTGRESQL_EXAMPLE.read_text(encoding="utf-8")
    canonical = "/mnt/memory/kivra-memory/postgresql/17/main"

    assert f'PG_DATA = Path("{canonical}")' in helper
    assert 'PG_WAL = PG_DATA / "pg_wal"' in helper
    assert f"archive-wal {canonical}/%p %f" in postgresql
    assert "/var/lib/postgresql/17/main" not in postgresql
