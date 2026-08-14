"""Deterministic release preparation and content-free installed-audit contracts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType

import pytest

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
    "kivra-memory-retention-cap-check",
    "kivra-memory-scan-operational-canaries",
    "kivra-memory-scan-public-artifact",
    "kivra-memory-sealed-restore-reconcile",
    "kivra-memory-sealed-worker",
    "kivra-memory-worker",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fixture_drop_ins(repository: Path) -> None:
    drop_ins = {
        "client-auth/kivra-memory-api.service.d/30-client-token-auth.conf": "client\n",
        "sealed-content/kivra-memory-api.service.d/20-sealed-content.conf": "api\n",
        "sealed-content/kivra-memory-codex-ingress.service.d/20-sealed-content.conf": ("ingress\n"),
    }
    root = repository / "deploy" / "memory-node" / "systemd"
    for relative, content in drop_ins.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


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
        "systemd_drop_in_sha256": {},
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


def _load_audit() -> ModuleType:
    loader = SourceFileLoader("installed_audit", str(AUDIT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def _drop_in_fixture(
    tmp_path: Path,
) -> tuple[ModuleType, Path, Path, dict[str, str], str]:
    module = _load_audit()
    source = tmp_path / "source-systemd"
    installed = tmp_path / "installed-systemd"
    entries = {
        "client-auth/kivra-memory-api.service.d/30-client-token-auth.conf": "client\n",
        "sealed-content/kivra-memory-api.service.d/20-sealed-content.conf": "api\n",
        "sealed-content/kivra-memory-codex-ingress.service.d/20-sealed-content.conf": ("ingress\n"),
    }
    for relative, content in entries.items():
        source_path = source / relative
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(content, encoding="utf-8")
        _, target_directory, filename = Path(relative).parts
        installed_path = installed / target_directory / filename
        installed_path.parent.mkdir(parents=True, exist_ok=True)
        installed_path.write_text(content, encoding="utf-8")
        installed_path.chmod(0o644)
    reviewed_local = installed / "kivra-memory-codex-ingress.service.d" / "10-network-policy.conf"
    reviewed_local.write_text("reviewed local network policy\n", encoding="utf-8")
    reviewed_local.chmod(0o644)
    manifest = {relative: module._sha256(source / relative) for relative in entries}
    return module, source, installed, manifest, module._sha256(reviewed_local)


def test_installed_audit_inventories_exact_security_drop_ins(tmp_path: Path) -> None:
    module, source, installed, manifest, reviewed_digest = _drop_in_fixture(tmp_path)

    result = module._installed_systemd_drop_ins(
        source,
        installed,
        manifest,
        reviewed_digest,
        required_uid=os.geteuid(),
    )

    assert result == {
        **manifest,
        (
            "reviewed-local/kivra-memory-codex-ingress.service.d/10-network-policy.conf"
        ): reviewed_digest,
    }


def test_installed_audit_requires_disabled_sealed_drop_ins_absent(tmp_path: Path) -> None:
    module, source, installed, manifest, reviewed_digest = _drop_in_fixture(tmp_path)
    for target in (
        installed / "kivra-memory-api.service.d" / "20-sealed-content.conf",
        installed / "kivra-memory-codex-ingress.service.d" / "20-sealed-content.conf",
    ):
        target.unlink()

    result = module._installed_systemd_drop_ins(
        source,
        installed,
        manifest,
        reviewed_digest,
        enabled_profiles=frozenset({"client-auth"}),
        required_uid=os.geteuid(),
    )

    assert result == {
        "client-auth/kivra-memory-api.service.d/30-client-token-auth.conf": manifest[
            "client-auth/kivra-memory-api.service.d/30-client-token-auth.conf"
        ],
        (
            "reviewed-local/kivra-memory-codex-ingress.service.d/10-network-policy.conf"
        ): reviewed_digest,
    }


def test_installed_audit_rejects_sealed_drop_ins_when_profile_disabled(
    tmp_path: Path,
) -> None:
    module, source, installed, manifest, reviewed_digest = _drop_in_fixture(tmp_path)

    with pytest.raises(module.AuditError, match=r"^installed_systemd_drop_in_set_mismatch$"):
        module._installed_systemd_drop_ins(
            source,
            installed,
            manifest,
            reviewed_digest,
            enabled_profiles=frozenset({"client-auth"}),
            required_uid=os.geteuid(),
        )


def test_installed_audit_sealed_profile_requires_explicit_flag() -> None:
    module = _load_audit()

    disabled = module._parser().parse_args(["--codex-network-policy-sha256", "a" * 64])
    enabled = module._parser().parse_args(
        ["--codex-network-policy-sha256", "a" * 64, "--sealed-content-enabled"]
    )

    assert disabled.sealed_content_enabled is False
    assert enabled.sealed_content_enabled is True


@pytest.mark.parametrize(
    ("nasty", "expected"),
    (
        ("missing", "installed_systemd_drop_in_missing"),
        ("extra", "installed_systemd_drop_in_set_mismatch"),
        ("digest", "installed_systemd_drop_in_mismatch"),
        ("writable", "installed_systemd_drop_in_invalid"),
        ("owner", "installed_systemd_drop_in_invalid"),
        ("local-missing", "reviewed_local_drop_in_missing"),
        ("local-drift", "reviewed_local_drop_in_mismatch"),
        ("local-digest-invalid", "reviewed_local_drop_in_digest_invalid"),
    ),
)
def test_installed_audit_rejects_security_drop_in_drift(
    tmp_path: Path, nasty: str, expected: str
) -> None:
    module, source, installed, manifest, reviewed_digest = _drop_in_fixture(tmp_path)
    target = installed / "kivra-memory-api.service.d" / "30-client-token-auth.conf"
    reviewed_local = installed / "kivra-memory-codex-ingress.service.d" / "10-network-policy.conf"
    required_uid = os.geteuid()
    if nasty == "missing":
        target.unlink()
    elif nasty == "extra":
        (reviewed_local.parent / "99-unreviewed.conf").write_text("extra\n", encoding="utf-8")
    elif nasty == "digest":
        target.write_text("changed\n", encoding="utf-8")
    elif nasty == "writable":
        target.chmod(0o664)
    elif nasty == "local-missing":
        reviewed_local.unlink()
    elif nasty == "local-drift":
        reviewed_local.write_text("unreviewed drift\n", encoding="utf-8")
    elif nasty == "local-digest-invalid":
        reviewed_digest = "not-a-sha256"
    else:
        required_uid += 1

    with pytest.raises(module.AuditError, match=f"^{expected}$"):
        module._installed_systemd_drop_ins(
            source,
            installed,
            manifest,
            reviewed_digest,
            required_uid=required_uid,
        )


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
    _write_fixture_drop_ins(repository)
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
    _write_fixture_drop_ins(repository)
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
        assert set(manifest["systemd_drop_in_sha256"]) == {
            "client-auth/kivra-memory-api.service.d/30-client-token-auth.conf",
            "sealed-content/kivra-memory-api.service.d/20-sealed-content.conf",
            "sealed-content/kivra-memory-codex-ingress.service.d/20-sealed-content.conf",
        }

    assert archive_digests[0] == archive_digests[1]


def test_backup_helper_uses_the_canonical_mounted_postgresql_path() -> None:
    helper = BACKUP.read_text(encoding="utf-8")
    postgresql = POSTGRESQL_EXAMPLE.read_text(encoding="utf-8")
    canonical = "/mnt/memory/kivra-memory/postgresql/17/main"

    assert f'PG_DATA = Path("{canonical}")' in helper
    assert 'PG_WAL = PG_DATA / "pg_wal"' in helper
    assert f"archive-wal {canonical}/%p %f" in postgresql
    assert "/var/lib/postgresql/17/main" not in postgresql
