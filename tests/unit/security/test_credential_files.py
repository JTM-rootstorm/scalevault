"""Tests for the common protected credential reader."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from kivra_memory.security.credential_files import (
    read_protected_file,
    read_protected_text,
    read_systemd_credential_text,
)


def _credential(tmp_path: Path, value: bytes = b"secret-value") -> Path:
    path = tmp_path / "credential"
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def test_reader_holds_validated_descriptor_across_path_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _credential(tmp_path, b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"attacker")
    replacement.chmod(0o600)
    real_read = os.read
    replaced = False

    def replace_path_after_open(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        if not replaced and size > 1:
            path.unlink()
            replacement.rename(path)
            replaced = True
        return real_read(descriptor, size)

    monkeypatch.setattr(os, "read", replace_path_after_open)

    with pytest.raises(ValueError):
        read_protected_file(
            path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=os.geteuid()
        )


def test_reader_rejects_content_change_while_descriptor_is_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _credential(tmp_path, b"original")
    real_read = os.read
    changed = False

    def change_open_file(descriptor: int, size: int) -> bytes:
        nonlocal changed
        value = real_read(descriptor, size)
        if not changed and size > 1:
            with path.open("r+b") as writer:
                writer.write(b"changed!")
            changed = True
        return value

    monkeypatch.setattr(os, "read", change_open_file)

    with pytest.raises(ValueError):
        read_protected_file(
            path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=os.geteuid()
        )


@pytest.mark.parametrize("mode", [0o000, 0o440, 0o640, 0o604])
def test_reader_rejects_wrong_mode(tmp_path: Path, mode: int) -> None:
    path = _credential(tmp_path)
    path.chmod(mode)

    with pytest.raises(ValueError):
        read_protected_file(path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=None)


def test_reader_rejects_wrong_owner(tmp_path: Path) -> None:
    path = _credential(tmp_path)

    with pytest.raises(ValueError):
        read_protected_file(
            path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=os.geteuid() + 1
        )


def test_reader_rejects_symlink_hardlink_and_symlinked_parent(tmp_path: Path) -> None:
    path = _credential(tmp_path)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(path)
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    hardlink = tmp_path / "hardlink"
    hardlink.hardlink_to(path)

    for candidate in (symlink, parent_link / path.name, path):
        with pytest.raises(ValueError):
            read_protected_file(
                candidate, minimum_bytes=1, maximum_bytes=32, required_owner_uid=None
            )


@pytest.mark.parametrize("value", [b"", b"x" * 33])
def test_reader_rejects_empty_or_oversized_file(tmp_path: Path, value: bytes) -> None:
    path = _credential(tmp_path, value)

    with pytest.raises(ValueError):
        read_protected_file(path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=None)


@pytest.mark.parametrize("value", [b"has\x00nul", b"has\ttab", b"has\nline", b"trailing "])
def test_text_reader_rejects_controls_and_surrounding_whitespace(
    tmp_path: Path, value: bytes
) -> None:
    path = _credential(tmp_path, value)

    with pytest.raises(ValueError):
        read_protected_text(path, minimum_bytes=1, maximum_bytes=32, required_owner_uid=None)


def test_systemd_reader_uses_only_fixed_name_below_credential_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _credential(tmp_path, b"local-database-url")
    path.rename(tmp_path / "database-url")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

    assert (
        read_systemd_credential_text("database-url", minimum_bytes=1, maximum_bytes=64)
        == "local-database-url"
    )
    with pytest.raises(ValueError):
        read_systemd_credential_text("../database-url", minimum_bytes=1, maximum_bytes=64)
