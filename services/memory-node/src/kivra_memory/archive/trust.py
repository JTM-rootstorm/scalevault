"""External signer-epoch transition records and detached SSH verification."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from kivra_memory.archive.git import (
    GitSigningError,
    ProcessRunner,
    SubprocessRunner,
)
from kivra_memory.archive.verification import ArchiveSignerEpoch, VerifiedArchive
from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict

TRANSITION_NAMESPACE = "scalevault-archive-transition-v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_SIGNATURE_STATUS = re.compile(
    rb'Good "scalevault-archive-transition-v1" signature for '
    rb"([A-Za-z0-9][A-Za-z0-9_.@+\-]{0,127}) with "
    rb"[A-Z0-9][A-Z0-9_-]{0,31} key (SHA256:[A-Za-z0-9+/]{43})"
)


class ArchiveTrustError(ValueError):
    """Content-free failure in external archive signer trust evidence."""


@dataclass(frozen=True, slots=True)
class ArchivePublicKey:
    """Exact root-controlled SSH public key identity for one signer epoch."""

    path: Path
    fingerprint: str

    @classmethod
    def load(cls, path: Path, *, expected_fingerprint: str) -> ArchivePublicKey:
        if _FINGERPRINT.fullmatch(expected_fingerprint) is None:
            raise ArchiveTrustError("archive signer fingerprint is invalid")
        document = _read_regular(path, maximum=16 * 1024)
        try:
            line = document.decode("ascii")
            if not line.endswith("\n") or line.count("\n") != 1:
                raise ValueError
            fields = line[:-1].split(" ")
            if len(fields) != 2 or not fields[0].startswith("ssh-"):
                raise ValueError
            wire = base64.b64decode(fields[1], validate=True)
            declared_size = int.from_bytes(wire[:4], "big")
            wire_type = wire[4 : 4 + declared_size].decode("ascii")
            if wire_type != fields[0] or 4 + declared_size >= len(wire):
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            raise ArchiveTrustError("archive signer public key is invalid") from None
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip(
            "="
        )
        if actual != expected_fingerprint:
            raise ArchiveTrustError("archive signer public key fingerprint does not match")
        return cls(path=path, fingerprint=actual)


@dataclass(frozen=True, slots=True)
class ArchiveSignerTransition:
    """Canonical external trust record covered by old and new detached signatures."""

    transition_id: str
    archive_target_id: str
    previous_epoch_id: str
    next_epoch_id: str
    previous_key_fingerprint: str
    next_key_fingerprint: str
    last_old_head: str
    last_old_event_sequence: int
    first_new_event_sequence: int
    format: str = TRANSITION_NAMESPACE

    def __post_init__(self) -> None:
        for value in (
            self.transition_id,
            self.archive_target_id,
            self.previous_epoch_id,
            self.next_epoch_id,
        ):
            if _IDENTIFIER.fullmatch(value) is None:
                raise ArchiveTrustError("archive transition identity is invalid")
        if self.previous_epoch_id == self.next_epoch_id:
            raise ArchiveTrustError("archive transition epochs must be distinct")
        if self.format != TRANSITION_NAMESPACE:
            raise ArchiveTrustError("archive transition format is unsupported")
        if (
            _FINGERPRINT.fullmatch(self.previous_key_fingerprint) is None
            or _FINGERPRINT.fullmatch(self.next_key_fingerprint) is None
        ):
            raise ArchiveTrustError("archive transition fingerprint is invalid")
        if self.previous_key_fingerprint == self.next_key_fingerprint:
            raise ArchiveTrustError("archive transition must change signer key")
        if _OBJECT_ID.fullmatch(self.last_old_head) is None:
            raise ArchiveTrustError("archive transition head is invalid")
        if (
            isinstance(self.last_old_event_sequence, bool)
            or self.last_old_event_sequence < 1
            or isinstance(self.first_new_event_sequence, bool)
            or self.first_new_event_sequence != self.last_old_event_sequence + 1
        ):
            raise ArchiveTrustError("archive transition event boundary is invalid")

    @property
    def value(self) -> dict[str, object]:
        return {
            "archive_target_id": self.archive_target_id,
            "first_new_event_sequence": self.first_new_event_sequence,
            "format": self.format,
            "last_old_event_sequence": self.last_old_event_sequence,
            "last_old_head": self.last_old_head,
            "next_epoch_id": self.next_epoch_id,
            "next_key_fingerprint": self.next_key_fingerprint,
            "previous_epoch_id": self.previous_epoch_id,
            "previous_key_fingerprint": self.previous_key_fingerprint,
            "transition_id": self.transition_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.value)

    @classmethod
    def parse(cls, document: bytes) -> ArchiveSignerTransition:
        try:
            value = parse_json_strict(document)
        except ValueError:
            raise ArchiveTrustError("archive transition record is invalid") from None
        expected = {
            "archive_target_id",
            "first_new_event_sequence",
            "format",
            "last_old_event_sequence",
            "last_old_head",
            "next_epoch_id",
            "next_key_fingerprint",
            "previous_epoch_id",
            "previous_key_fingerprint",
            "transition_id",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ArchiveTrustError("archive transition record is invalid")
        try:
            record = cls(**value)  # type: ignore[arg-type]
        except (TypeError, ArchiveTrustError):
            raise ArchiveTrustError("archive transition record is invalid") from None
        if record.canonical_bytes != document:
            raise ArchiveTrustError("archive transition record is not canonical")
        return record


@dataclass(frozen=True, slots=True)
class ArchiveTransitionEvidence:
    record_file: Path
    previous_signature_file: Path
    next_signature_file: Path


class DetachedTransitionVerifier:
    """Verify exact transition bytes using public allowed-signers material only."""

    def __init__(
        self,
        *,
        ssh_keygen_executable: Path = Path("/usr/bin/ssh-keygen"),
        runner: ProcessRunner | None = None,
    ) -> None:
        if not ssh_keygen_executable.is_absolute():
            raise ValueError("transition verifier executable must be absolute")
        self._ssh_keygen = ssh_keygen_executable
        self._runner = runner or SubprocessRunner()

    def verify(
        self,
        *,
        record: ArchiveSignerTransition,
        signature_file: Path,
        allowed_signers_file: Path,
        signer_principal: str,
        expected_fingerprint: str,
    ) -> None:
        _read_regular(signature_file, maximum=64 * 1024)
        _read_regular(allowed_signers_file, maximum=1024 * 1024)
        try:
            result = self._runner.run(
                (
                    str(self._ssh_keygen),
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_signers_file),
                    "-I",
                    signer_principal,
                    "-n",
                    TRANSITION_NAMESPACE,
                    "-s",
                    str(signature_file),
                ),
                stdin=record.canonical_bytes,
                environment={"LC_ALL": "C", "LANG": "C"},
                timeout_seconds=30,
                stdout_limit_bytes=64 * 1024,
                stderr_limit_bytes=64 * 1024,
            )
        except GitSigningError:
            raise ArchiveTrustError("archive transition signature verification failed") from None
        if result.returncode != 0:
            raise ArchiveTrustError("archive transition signature verification failed")
        identities = {
            (match.group(1).decode("ascii"), match.group(2).decode("ascii"))
            for line in (*result.stdout.splitlines(), *result.stderr.splitlines())
            if (match := _SIGNATURE_STATUS.fullmatch(line)) is not None
        }
        if identities != {(signer_principal, expected_fingerprint)}:
            raise ArchiveTrustError("archive transition signer identity does not match")


class TransitionSignatureVerifier(Protocol):
    """Public-key-only detached transition verification seam."""

    def verify(
        self,
        *,
        record: ArchiveSignerTransition,
        signature_file: Path,
        allowed_signers_file: Path,
        signer_principal: str,
        expected_fingerprint: str,
    ) -> None: ...


def verify_transition_evidence(
    archive: VerifiedArchive,
    epochs: Sequence[ArchiveSignerEpoch],
    evidence: Sequence[ArchiveTransitionEvidence],
    *,
    archive_target_id: str,
    allowed_signers: Mapping[str, Path],
    signer_principals: Mapping[str, str],
    public_keys: Mapping[str, ArchivePublicKey],
    verifier: TransitionSignatureVerifier | None = None,
) -> tuple[ArchiveSignerTransition, ...]:
    """Verify every adjacent epoch boundary and both detached signatures."""

    policy = tuple(epochs)
    records = tuple(evidence)
    if len({epoch.epoch_id for epoch in policy}) != len(policy):
        raise ArchiveTrustError("archive signer epoch identities are duplicated")
    for index, epoch in enumerate(policy):
        if epoch.public_key_fingerprint is None:
            raise ArchiveTrustError("archive signer epoch fingerprint is missing")
        if (index == 0 and epoch.transition_record_id is not None) or (
            index > 0 and epoch.transition_record_id is None
        ):
            raise ArchiveTrustError("archive signer transition identity is missing")
        if index > 0 and policy[index - 1].public_key_fingerprint == epoch.public_key_fingerprint:
            raise ArchiveTrustError("archive signer transition must change key fingerprint")
    if len(records) != max(0, len(policy) - 1):
        raise ArchiveTrustError("archive transition evidence count does not match epochs")
    commits_by_end = {
        commit.batch.manifest.last_event_sequence: commit for commit in archive.commits
    }
    transition_verifier = verifier or DetachedTransitionVerifier()
    verified: list[ArchiveSignerTransition] = []
    for index, item in enumerate(records):
        previous = policy[index]
        following = policy[index + 1]
        record = ArchiveSignerTransition.parse(_read_regular(item.record_file, maximum=64 * 1024))
        boundary = commits_by_end.get(record.last_old_event_sequence)
        if (
            record.archive_target_id != archive_target_id
            or record.previous_epoch_id != previous.epoch_id
            or record.next_epoch_id != following.epoch_id
            or record.transition_id != following.transition_record_id
            or record.previous_key_fingerprint != previous.public_key_fingerprint
            or record.next_key_fingerprint != following.public_key_fingerprint
            or previous.last_event_sequence != record.last_old_event_sequence
            or following.first_event_sequence != record.first_new_event_sequence
            or boundary is None
            or boundary.git.commit_sha != record.last_old_head
        ):
            raise ArchiveTrustError("archive transition record does not match epoch boundary")
        for epoch, signature in (
            (previous, item.previous_signature_file),
            (following, item.next_signature_file),
        ):
            try:
                allowed = allowed_signers[epoch.epoch_id]
                principal = signer_principals[epoch.epoch_id]
                key = public_keys[epoch.epoch_id]
            except KeyError:
                raise ArchiveTrustError("archive transition signer trust is missing") from None
            if key.fingerprint != epoch.public_key_fingerprint:
                raise ArchiveTrustError("archive transition public key binding does not match")
            transition_verifier.verify(
                record=record,
                signature_file=signature,
                allowed_signers_file=allowed,
                signer_principal=principal,
                expected_fingerprint=key.fingerprint,
            )
        verified.append(record)
    return tuple(verified)


def _read_regular(path: Path, *, maximum: int) -> bytes:
    if not path.is_absolute():
        raise ArchiveTrustError("archive trust path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise ArchiveTrustError("archive trust file is unavailable") from None
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size < 1
            or details.st_size > maximum
        ):
            raise ArchiveTrustError("archive trust file is unsafe")
        document = os.read(descriptor, details.st_size + 1)
        final = os.fstat(descriptor)
        if (
            len(document) != details.st_size
            or final.st_dev != details.st_dev
            or final.st_ino != details.st_ino
            or final.st_size != details.st_size
            or final.st_mtime_ns != details.st_mtime_ns
            or final.st_ctime_ns != details.st_ctime_ns
        ):
            raise ArchiveTrustError("archive trust file changed while reading")
        return document
    finally:
        os.close(descriptor)
