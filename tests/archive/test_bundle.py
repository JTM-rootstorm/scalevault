"""Encrypted secondary archive bundle safety tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from kivra_memory.archive.bundle import (
    ArchiveBundleError,
    BundleToolConfig,
    EncryptedArchiveBundle,
)


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
