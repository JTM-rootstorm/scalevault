"""Real CLI acceptance for encrypted full-history archive object recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from kivra_memory import __version__
from kivra_memory.archive.adapters import ArchivePayload, DeterministicArchiveBuilder
from kivra_memory.archive.bundle import ArchiveBundleError, EncryptedArchiveBundle
from kivra_memory.archive.git import GitCommitSigner, GitSigningConfig
from kivra_memory.storage.readiness import EXPECTED_ALEMBIC_HEAD
from kivra_memory.tools.archive_recovery import ArchiveRecoverySettings

from tests.integration.archive.test_continuation import _run, _tree
from tests.integration.database.test_archive_restore_acceptance import (
    _branch_event,
    _snapshot_source,
)

_ROOT = Path(__file__).resolve().parents[3]


def _cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    executable = Path(sys.executable).with_name("kivra-memory-archive-recovery")
    environment = {"LC_ALL": "C", "LANG": "C"}
    command = (
        (str(executable), *arguments)
        if executable.is_file()
        else (
            sys.executable,
            "-c",
            "from kivra_memory.tools.archive_recovery import main; main()",
            *arguments,
        )
    )
    if not executable.is_file():
        python_path = os.environ.get("PYTHONPATH")
        if not python_path:
            pytest.skip("archive recovery source path is unavailable")
        environment["PYTHONPATH"] = python_path
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        shell=False,
        env=environment,
        timeout=120,
    )


def _age_identity(path: Path) -> str:
    _run("/usr/bin/age-keygen", "-o", str(path))
    path.chmod(0o600)
    return _run("/usr/bin/age-keygen", "-y", str(path)).decode("ascii").strip()


@pytest.fixture
def encrypted_gate_root(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / "encrypted-object-gate"
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cli_creates_and_restores_encrypted_signed_archive_object(
    encrypted_gate_root: Path,
) -> None:
    if shutil.which("age") is None or shutil.which("age-keygen") is None:
        pytest.skip("age and age-keygen are required")
    tmp_path = encrypted_gate_root
    tmp_path.chmod(0o700)
    source_repository = tmp_path / "source.git"
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    _run("/usr/bin/git", "init", "--bare", "--initial-branch=main", str(source_repository))

    signing_key = tmp_path / "archive-signing-key"
    _run(
        "/usr/bin/ssh-keygen",
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        str(signing_key),
    )
    public_fields = signing_key.with_suffix(".pub").read_text().split()
    exact_public_key = tmp_path / "archive-signing-key.public"
    exact_public_key.write_text(f"{public_fields[0]} {public_fields[1]}\n")
    allowed_signers = tmp_path / "allowed-signers"
    allowed_signers.write_text(f"archive@scalevault {public_fields[0]} {public_fields[1]}\n")
    fingerprint = (
        _run("/usr/bin/ssh-keygen", "-E", "sha256", "-lf", str(exact_public_key))
        .decode("ascii")
        .split()[1]
    )

    source = _snapshot_source(_branch_event())
    built = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version=__version__,
    ).build(source)
    assert isinstance(built.payload, ArchivePayload)
    tree = _tree(source_repository, dict(built.payload.files), tmp_path / "source.index")
    signer = GitCommitSigner(
        GitSigningConfig(
            repository=source_repository,
            signing_key=signing_key,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        )
    )
    head = signer.sign_commit(
        tree_sha=tree,
        parent_sha=None,
        message=built.commit_message,
        timestamp=source.export_timestamp,
    )
    _run(
        "/usr/bin/git",
        "-C",
        str(source_repository),
        "update-ref",
        "refs/heads/main",
        head,
    )

    config = tmp_path / "recovery.json"
    config.write_text(
        json.dumps(
            {
                "archive_target_id": "encrypted-object-gate",
                "repository": str(source_repository),
                "branch_name": "main",
                "expected_head": head,
                "expected_manifest_sha256": built.manifest_sha256.hex(),
                "expected_high_water_sequence": 1,
                "expected_application_version": __version__,
                "expected_alembic_revision": EXPECTED_ALEMBIC_HEAD,
                "signer_epochs": [
                    {
                        "epoch_id": "gate-epoch-1",
                        "first_event_sequence": 1,
                        "last_event_sequence": None,
                        "allowed_signers_file": str(allowed_signers),
                        "public_key_file": str(exact_public_key),
                        "public_key_fingerprint": fingerprint,
                        "signer_principal": "archive@scalevault",
                        "author_name": "ScaleVault Archive",
                        "author_email": "archive@scalevault.invalid",
                        "transition_record_id": None,
                        "compromised_last_commit": None,
                        "compromised_last_event_sequence": None,
                    }
                ],
                "transition_evidence": [],
            },
            sort_keys=True,
        )
    )

    identity = tmp_path / "age-identity"
    recipient = _age_identity(identity)
    encrypted = tmp_path / "archive.bundle.age"
    created = _cli(
        "--config",
        str(config),
        "bundle-create",
        "--destination",
        str(encrypted),
        "--scratch-directory",
        str(scratch),
        "--recipient",
        recipient,
    )
    assert created.returncode == 0, created.stderr.decode("utf-8", errors="replace")
    creation = json.loads(created.stdout)
    ciphertext_sha256 = hashlib.sha256(encrypted.read_bytes()).hexdigest()
    assert creation == {
        "ciphertext_sha256": ciphertext_sha256,
        "ciphertext_size": encrypted.stat().st_size,
        "head": head,
        "ok": True,
    }
    assert not tuple(scratch.iterdir())

    restored = tmp_path / "restored"
    materialized = _cli(
        "--config",
        str(config),
        "bundle-materialize",
        "--encrypted-bundle",
        str(encrypted),
        "--expected-ciphertext-sha256",
        ciphertext_sha256,
        "--identity-file",
        str(identity),
        "--output-repository",
        str(restored),
        "--scratch-directory",
        str(scratch),
    )
    if materialized.returncode != 0:
        diagnostic_output = tmp_path / "diagnostic-output"
        settings = ArchiveRecoverySettings.load(config)
        try:
            EncryptedArchiveBundle().materialize(
                encrypted_bundle=encrypted,
                expected_ciphertext_sha256=ciphertext_sha256,
                identity_file=identity,
                output_repository=diagnostic_output,
                scratch_directory=scratch,
                branch_name="main",
                expected_head=head,
                signer_epochs_for_repository=settings.epochs_for,
            )
        except ArchiveBundleError as error:
            pytest.fail(f"materialize failed at content-free stage: {error}")
    assert materialized.returncode == 0, materialized.stderr.decode("utf-8", errors="replace")
    assert json.loads(materialized.stdout)["head"] == head
    assert _run("/usr/bin/git", "-C", str(restored), "rev-parse", "refs/heads/main") == (
        head + "\n"
    ).encode("ascii")
    source_closure = _run(
        "/usr/bin/git", "-C", str(source_repository), "rev-list", "--objects", head
    )
    restored_closure = _run("/usr/bin/git", "-C", str(restored), "rev-list", "--objects", head)
    assert restored_closure == source_closure
    assert not tuple(scratch.iterdir())

    wrong_identity = tmp_path / "wrong-age-identity"
    _age_identity(wrong_identity)
    wrong_output = tmp_path / "wrong-key-output"
    wrong_key = _cli(
        "--config",
        str(config),
        "bundle-materialize",
        "--encrypted-bundle",
        str(encrypted),
        "--expected-ciphertext-sha256",
        ciphertext_sha256,
        "--identity-file",
        str(wrong_identity),
        "--output-repository",
        str(wrong_output),
        "--scratch-directory",
        str(scratch),
    )
    assert wrong_key.returncode == 2
    assert wrong_key.stderr == b"ScaleVault archive recovery failed safely\n"
    assert not wrong_output.exists()

    corrupted = tmp_path / "archive.corrupt.bundle.age"
    ciphertext = bytearray(encrypted.read_bytes())
    ciphertext[len(ciphertext) // 2] ^= 1
    corrupted.write_bytes(ciphertext)
    corrupt_output = tmp_path / "corrupt-output"
    corrupt = _cli(
        "--config",
        str(config),
        "bundle-materialize",
        "--encrypted-bundle",
        str(corrupted),
        "--expected-ciphertext-sha256",
        ciphertext_sha256,
        "--identity-file",
        str(identity),
        "--output-repository",
        str(corrupt_output),
        "--scratch-directory",
        str(scratch),
    )
    assert corrupt.returncode == 2
    assert corrupt.stderr == b"ScaleVault archive recovery failed safely\n"
    assert not corrupt_output.exists()
    assert not tuple(scratch.iterdir())
    assert not tuple(path for path in tmp_path.rglob("*.bundle") if path.is_file())
    assert not any(
        b"AGE-SECRET-KEY-" in path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and path not in {identity, wrong_identity}
    )
