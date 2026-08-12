"""Fail-closed readers for protected local credential files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def read_protected_file(
    path: Path,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    required_owner_uid: int | None,
    required_group_gid: int | None = None,
    allowed_modes: frozenset[int] = frozenset({0o400, 0o600}),
) -> bytes:
    """Read one bounded regular file through a stable descriptor.

    Every path component is opened relative to its already-open parent with
    ``O_NOFOLLOW``. The returned bytes therefore come from the object that was
    validated, even if an attacker concurrently replaces a pathname.
    """

    selected = Path(path)
    if (
        not selected.is_absolute()
        or selected == Path("/")
        or any(part in {"", ".", ".."} for part in selected.parts[1:])
        or minimum_bytes < 0
        or maximum_bytes < minimum_bytes
    ):
        raise ValueError

    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = -1
    try:
        for component in selected.parts[1:-1]:
            try:
                next_directory_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            except OSError as error:
                if isinstance(error, FileNotFoundError):
                    raise
                raise ValueError from None
            os.close(directory_fd)
            directory_fd = next_directory_fd
        try:
            descriptor = os.open(
                selected.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        except OSError as error:
            if isinstance(error, FileNotFoundError):
                raise
            raise ValueError from None
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or stat.S_IMODE(initial.st_mode) not in allowed_modes
            or (required_owner_uid is not None and initial.st_uid != required_owner_uid)
            or (required_group_gid is not None and initial.st_gid != required_group_gid)
            or not minimum_bytes <= initial.st_size <= maximum_bytes
        ):
            raise ValueError
        raw = os.read(descriptor, maximum_bytes + 1)
        if os.read(descriptor, 1):
            raise ValueError
        final = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(initial, field, None) != getattr(final, field, None) for field in stable_fields
        ):
            raise ValueError
        if len(raw) != initial.st_size:
            raise ValueError
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def read_protected_text(
    path: Path,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    required_owner_uid: int | None,
    required_group_gid: int | None = None,
    allowed_modes: frozenset[int] = frozenset({0o400, 0o600}),
) -> str:
    """Read one UTF-8 credential with no whitespace or control characters."""

    raw = read_protected_file(
        path,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        required_owner_uid=required_owner_uid,
        required_group_gid=required_group_gid,
        allowed_modes=allowed_modes,
    )
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError from None
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError
    return value


def read_systemd_credential(
    name: str,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    text: bool = False,
) -> bytes | str:
    """Read one credential from systemd's service-scoped credential directory."""

    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if (
        not directory
        or not name
        or "/" in name
        or name in {".", ".."}
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in name)
    ):
        raise ValueError
    path = Path(directory) / name
    reader = read_protected_text if text else read_protected_file
    return reader(
        path,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        required_owner_uid=os.geteuid(),
    )


def read_systemd_credential_text(
    name: str,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
) -> str:
    """Read one bounded text credential from the service credential directory."""

    value = read_systemd_credential(
        name,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        text=True,
    )
    if not isinstance(value, str):
        raise ValueError
    return value


__all__ = [
    "read_protected_file",
    "read_protected_text",
    "read_systemd_credential",
    "read_systemd_credential_text",
]
