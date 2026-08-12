"""Protected configuration and one-time secret artifact handling for credential admin."""

from __future__ import annotations

import errno
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final
from urllib.parse import unquote

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy.engine import make_url

from kivra_memory.admin.credentials import (
    TOKEN_PEPPER_MAXIMUM_BYTES,
    TOKEN_PEPPER_MINIMUM_BYTES,
    CredentialAdminError,
)
from kivra_memory.auth import BearerTokenCodec
from kivra_memory.domain.canonical_json import parse_json_strict
from kivra_memory.security.credential_files import read_protected_file

DEFAULT_ADMIN_CONFIG_PATH: Final = Path("/etc/kivra-memory/credential-admin.json")
_CONFIG_MAXIMUM_BYTES: Final = 8_192
_DATABASE_URL_MAXIMUM_BYTES: Final = 4_096
_KEY_ID_PATTERN: Final = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_LOCAL_DATABASE_HOSTS: Final = {
    "localhost",
    "127.0.0.1",
    "::1",
    "/run/postgresql",
    "/var/run/postgresql",
}


@dataclass(frozen=True, slots=True)
class CredentialAdminSettings:
    """Validated protected-file configuration with redacted secret-bearing fields."""

    database_url: str = field(repr=False)
    token_pepper: bytes = field(repr=False)
    secret_hash_key_id: str

    @classmethod
    def from_file(cls, path: Path) -> CredentialAdminSettings:
        """Read config and pepper without following links or accepting ambient secrets."""

        try:
            config_raw = _read_protected_file(
                path,
                minimum_bytes=2,
                maximum_bytes=_CONFIG_MAXIMUM_BYTES,
            )
            parsed = parse_json_strict(config_raw)
            if not isinstance(parsed, dict) or set(parsed) != {
                "database_url_file",
                "secret_hash_key_id",
                "token_pepper_file",
            }:
                raise ValueError
            database_path = _absolute_path(parsed["database_url_file"])
            pepper_path = _absolute_path(parsed["token_pepper_file"])
            key_id = parsed["secret_hash_key_id"]
            if not isinstance(key_id, str) or _KEY_ID_PATTERN.fullmatch(key_id) is None:
                raise ValueError
            database_raw = _read_protected_file(
                database_path,
                minimum_bytes=1,
                maximum_bytes=_DATABASE_URL_MAXIMUM_BYTES,
            )
            database_url = database_raw.decode("utf-8")
            if database_url.endswith("\n"):
                database_url = database_url[:-1]
            if "\n" in database_url or "\r" in database_url:
                raise ValueError
            _require_local_admin_database(database_url)
            token_pepper = _read_protected_file(
                pepper_path,
                minimum_bytes=TOKEN_PEPPER_MINIMUM_BYTES,
                maximum_bytes=TOKEN_PEPPER_MAXIMUM_BYTES,
            )
            return cls(
                database_url=database_url,
                token_pepper=token_pepper,
                secret_hash_key_id=key_id,
            )
        except Exception:
            raise CredentialAdminError("credential_admin_configuration_invalid") from None


def write_one_time_secret(path: Path, token: str) -> None:
    """Publish one mode-0600 token file atomically without replacing any path."""

    _write_one_time_secret(path, token, authorization=False)


def _write_one_time_secret(path: Path, value: str, *, authorization: bool) -> None:
    """Publish one validated secret artifact without replacing any path."""

    temporary_name: str | None = None
    descriptor = -1
    directory_fd = -1
    destination_reserved = False
    try:
        destination = Path(path)
        if not destination.is_absolute() or ".." in destination.parts or not destination.name:
            raise ValueError
        parent = destination.parent
        if parent.resolve(strict=True) != parent:
            raise ValueError
        parent_lstat = parent.lstat()
        if stat.S_ISLNK(parent_lstat.st_mode):
            raise ValueError
        directory_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or stat.S_IMODE(directory_stat.st_mode) & 0o077
        ):
            raise ValueError
        payload = value.encode("ascii") + b"\n"
        if not 64 <= len(payload) <= 256 or any(
            byte < (0x20 if authorization else 0x21) or byte > 0x7E for byte in payload[:-1]
        ):
            raise ValueError
        if authorization and (not value.startswith("Bearer ") or " " in value[7:]):
            raise ValueError
        descriptor = os.open(
            destination.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o000,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o000)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        destination_reserved = True
        os.fsync(directory_fd)
        temporary_name = f".credential-{os.urandom(16).hex()}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None
        destination_reserved = False
        os.fsync(directory_fd)
    except Exception:
        raise CredentialAdminError("credential_secret_output_failed") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)
            if destination_reserved:
                with suppress(FileNotFoundError):
                    os.unlink(destination.name, dir_fd=directory_fd)
            os.close(directory_fd)


def load_or_create_authorization(path: Path, proposed: str) -> str:
    """Load an exact protected Authorization artifact or create it once."""

    try:
        BearerTokenCodec.parse_authorization(proposed)
        try:
            raw = _read_protected_file(path, minimum_bytes=71, maximum_bytes=263)
        except FileNotFoundError:
            try:
                _write_one_time_secret(path, proposed, authorization=True)
            except CredentialAdminError:
                # A concurrent duplicate-safe invocation may have won O_EXCL.
                raw = _read_protected_file(path, minimum_bytes=71, maximum_bytes=263)
            else:
                raw = _read_protected_file(path, minimum_bytes=71, maximum_bytes=263)
        authorization = raw.decode("ascii")
        if not authorization.endswith("\n"):
            raise ValueError
        authorization = authorization[:-1]
        if "\n" in authorization or "\r" in authorization:
            raise ValueError
        BearerTokenCodec.parse_authorization(authorization)
        return authorization
    except Exception:
        raise CredentialAdminError("credential_secret_output_failed") from None


def _read_protected_file(path: Path, *, minimum_bytes: int, maximum_bytes: int) -> bytes:
    return read_protected_file(
        path,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        required_owner_uid=os.geteuid(),
        allowed_modes=frozenset({0o600}),
    )


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    return path


def _require_local_admin_database(value: str) -> None:
    try:
        parsed = TypeAdapter(PostgresDsn).validate_python(value)
        url = make_url(value)
        query_parameters = {name for name, _value in parsed.query_params()}
        if (
            url.username != "kivra_memory_credential_admin"
            or parsed.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}
            or query_parameters & {"host", "hostaddr", "service", "servicefile"}
            or any(
                host["host"] is None
                or unquote(str(host["host"])).removeprefix("[").removesuffix("]")
                not in _LOCAL_DATABASE_HOSTS
                for host in parsed.hosts()
            )
        ):
            raise ValueError
    except (ValidationError, ValueError):
        raise ValueError from None


__all__ = [
    "DEFAULT_ADMIN_CONFIG_PATH",
    "CredentialAdminSettings",
    "write_one_time_secret",
]
