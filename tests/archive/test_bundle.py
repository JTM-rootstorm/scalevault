"""Encrypted secondary archive bundle safety tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from kivra_memory.archive import bundle as bundle_module
from kivra_memory.archive.bundle import (
    ArchiveBundleError,
    BundleToolConfig,
    EncryptedArchiveBundle,
    _publish_new_file,
)
from kivra_memory.archive.git import ProcessResult
from kivra_memory.archive.recovery import GitRecoverySource


def test_bundle_paths_fail_closed_before_tool_execution(tmp_path: Path) -> None:
    runner_called = False

    class Runner:
        def run(self, *args: object, **kwargs: object) -> object:
            nonlocal runner_called
            runner_called = True
            raise AssertionError

    bundle = EncryptedArchiveBundle(
        BundleToolConfig(age_executable=Path("/usr/bin/age")),
        runner=Runner(),  # type: ignore[arg-type]
    )
    with pytest.raises(ArchiveBundleError, match="recipient"):
        bundle.create(
            source=None,  # type: ignore[arg-type]
            destination=tmp_path / "archive.age",
            scratch_directory=tmp_path,
            recipient="not-a-recipient",
            signer_epochs=(),
        )
    assert not runner_called

    (tmp_path / "archive.age").write_bytes(b"existing")
    with pytest.raises(ArchiveBundleError, match="already exists"):
        bundle.create(
            source=None,  # type: ignore[arg-type]
            destination=tmp_path / "archive.age",
            scratch_directory=tmp_path,
            recipient="age1" + "q" * 58,
            signer_epochs=(),
        )
    assert not runner_called


def test_materialize_requires_separately_protected_identity(tmp_path: Path) -> None:
    encrypted = tmp_path / "archive.age"
    encrypted.write_bytes(b"ciphertext")
    identity = tmp_path / "identity"
    identity.write_bytes(b"AGE-SECRET-KEY-test")
    identity.chmod(0o644)
    bundle = EncryptedArchiveBundle()

    with pytest.raises(ArchiveBundleError, match="identity is unsafe"):
        bundle.materialize(
            encrypted_bundle=encrypted,
            expected_ciphertext_sha256=(
                "305531dcc50ebca31cf1d5b31e9fc76ed51f66b3b6dd5a030c6539ae6532f979"
            ),
            identity_file=identity,
            output_repository=tmp_path / "restored",
            scratch_directory=tmp_path,
            branch_name="main",
            expected_head="a" * 40,
            signer_epochs=(),
        )


def test_bundle_creation_pins_exact_object_when_source_branch_advances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repository = tmp_path / "source.git"
    source_repository.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    destination_directory = tmp_path / "destination"
    destination_directory.mkdir()
    expected_head = "a" * 40
    advanced_head = "b" * 40

    def advance_branch(reader: object) -> tuple[object, ...]:
        del reader
        (source_repository / "branch-head").write_text(advanced_head)
        return ()

    monkeypatch.setattr(
        "kivra_memory.archive.bundle.ReadOnlyGitArchive.read",
        advance_branch,
    )
    monkeypatch.setattr(bundle_module, "verify_signed_archive_epochs", lambda *_args: None)

    class RaceRunner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(
            self,
            arguments: tuple[str, ...],
            *,
            stdin: bytes,
            environment: dict[str, str],
            timeout_seconds: int,
            stdout_limit_bytes: int = 8 * 1024 * 1024,
            stderr_limit_bytes: int = 256 * 1024,
        ) -> ProcessResult:
            del stdin, timeout_seconds, stdout_limit_bytes, stderr_limit_bytes
            assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
            assert environment["GIT_NO_LAZY_FETCH"] == "1"
            self.calls.append(arguments)
            if "init" in arguments and "--bare" in arguments:
                Path(arguments[-1]).mkdir()
            if "fetch" in arguments:
                assert arguments[-1] == expected_head
                assert arguments[-2] == str(source_repository)
            if "rev-parse" in arguments:
                return ProcessResult(0, f"{expected_head}\n".encode())
            if "create" in arguments and "bundle" in arguments:
                Path(arguments[-2]).write_bytes(b"bundle")
            if "list-heads" in arguments:
                return ProcessResult(0, f"{expected_head} refs/heads/main\n".encode())
            if "--encrypt" in arguments:
                output = Path(arguments[arguments.index("--output") + 1])
                output.write_bytes(b"ciphertext")
            return ProcessResult(0)

    runner = RaceRunner()
    result = EncryptedArchiveBundle(runner=runner).create(
        source=GitRecoverySource(source_repository, "main", expected_head),
        destination=destination_directory / "archive.bundle.age",
        scratch_directory=scratch,
        recipient="age1" + "q" * 58,
        signer_epochs=(),
    )

    assert result.source_head == expected_head
    assert (source_repository / "branch-head").read_text() == advanced_head
    create_call = next(call for call in runner.calls if "create" in call and "bundle" in call)
    assert str(source_repository) not in create_call


def test_atomic_publish_rejects_source_growth_without_final_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "ciphertext"
    source.write_bytes(b"sealed")
    destination = tmp_path / "published"
    expected = hashlib.sha256(b"sealed").hexdigest()
    original_read = os.read
    mutated = False

    def growing_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            with source.open("ab") as stream:
                stream.write(b"growth")
        return chunk

    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(ArchiveBundleError, match="changed before publication"):
        _publish_new_file(
            source,
            destination,
            expected_sha256=expected,
            expected_size=len(b"sealed"),
        )
    assert not destination.exists()
    assert not tuple(tmp_path.glob(".published.*.tmp"))
