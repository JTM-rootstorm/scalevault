"""Signer transition trust and safe continuation proof tests."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from kivra_memory.archive.continuation import (
    ArchiveContinuationError,
    ContinuationCheckpointPlan,
    prove_one_normal_append,
    reconstruct_new_target_checkpoint,
    require_exact_archive_equality,
)
from kivra_memory.archive.git import VerifiedGitCommit
from kivra_memory.archive.trust import (
    ArchivePublicKey,
    ArchiveSignerTransition,
    ArchiveTransitionEvidence,
    ArchiveTrustError,
    verify_transition_evidence,
)
from kivra_memory.archive.verification import (
    ArchiveSignerEpoch,
    VerifiedArchive,
    VerifiedArchiveBatch,
    VerifiedArchiveCommit,
)

from .test_manifest import SCHEMA_BYTES, SCHEMA_PATH, event_path, manifest

OLD_FINGERPRINT = "SHA256:" + "A" * 43
NEW_FINGERPRINT = "SHA256:" + "B" * 43


class NeverCommitVerifier:
    def verify_archive_commit(self, *args: object, **kwargs: object) -> VerifiedGitCommit:
        del args, kwargs
        raise AssertionError("pre-verified archive must not call commit verifier")


class RecordingTransitionVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def verify(
        self,
        *,
        record: ArchiveSignerTransition,
        signature_file: Path,
        allowed_signers_file: Path,
        signer_principal: str,
        expected_fingerprint: str,
    ) -> None:
        del record, signature_file, allowed_signers_file
        self.calls.append((signer_principal, expected_fingerprint))


class RecordingReconstructor:
    def __init__(self) -> None:
        self.plans: list[ContinuationCheckpointPlan] = []

    async def reconstruct_checkpoint(self, plan: ContinuationCheckpointPlan) -> None:
        self.plans.append(plan)


def _verified_archive(length: int) -> VerifiedArchive:
    commits: list[VerifiedArchiveCommit] = []
    previous_commit: str | None = None
    previous_manifest: str | None = None
    for sequence in range(1, length + 1):
        item = manifest(sequence, sequence, previous_manifest)
        commit_sha = f"{sequence:040x}"
        files = {
            SCHEMA_PATH: SCHEMA_BYTES,
            event_path(sequence): b"{}",
        }
        batch = VerifiedArchiveBatch(
            manifest=item,
            manifest_bytes=item.canonical_bytes,
            manifest_sha256=item.sha256,
            files=files,
            events=(),
            snapshot=None,
        )
        commits.append(
            VerifiedArchiveCommit(
                git=VerifiedGitCommit(commit_sha, f"{sequence + 100:040x}", previous_commit),
                batch=batch,
            )
        )
        previous_commit = commit_sha
        previous_manifest = item.sha256
    return VerifiedArchive(tuple(commits))


def test_public_key_load_binds_exact_fingerprint_and_rejects_comments(tmp_path: Path) -> None:
    key_type = b"ssh-ed25519"
    wire = len(key_type).to_bytes(4, "big") + key_type + b"x" * 32
    encoded = base64.b64encode(wire).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode(
        "ascii"
    ).rstrip("=")
    public_key = tmp_path / "archive.pub"
    public_key.write_text(f"ssh-ed25519 {encoded}\n")

    assert (
        ArchivePublicKey.load(public_key, expected_fingerprint=fingerprint).fingerprint
        == fingerprint
    )
    with pytest.raises(ArchiveTrustError, match="fingerprint"):
        ArchivePublicKey.load(public_key, expected_fingerprint=NEW_FINGERPRINT)
    public_key.write_text(f"ssh-ed25519 {encoded} comment\n")
    with pytest.raises(ArchiveTrustError, match="public key"):
        ArchivePublicKey.load(public_key, expected_fingerprint=fingerprint)


def test_transition_record_requires_canonical_dual_signed_exact_boundary(tmp_path: Path) -> None:
    archive = _verified_archive(2)
    old = ArchiveSignerEpoch(
        1,
        1,
        NeverCommitVerifier(),
        epoch_id="old",
        public_key_fingerprint=OLD_FINGERPRINT,
    )
    new = ArchiveSignerEpoch(
        2,
        None,
        NeverCommitVerifier(),
        epoch_id="new",
        public_key_fingerprint=NEW_FINGERPRINT,
        transition_record_id="old-to-new",
    )
    record = ArchiveSignerTransition(
        transition_id="old-to-new",
        archive_target_id="archive-primary",
        previous_epoch_id="old",
        next_epoch_id="new",
        previous_key_fingerprint=OLD_FINGERPRINT,
        next_key_fingerprint=NEW_FINGERPRINT,
        last_old_head=archive.commits[0].git.commit_sha,
        last_old_event_sequence=1,
        first_new_event_sequence=2,
    )
    record_file = tmp_path / "transition.json"
    record_file.write_bytes(record.canonical_bytes)
    previous_signature = tmp_path / "old.sig"
    next_signature = tmp_path / "new.sig"
    previous_signature.write_bytes(b"signature")
    next_signature.write_bytes(b"signature")
    transition_verifier = RecordingTransitionVerifier()

    assert verify_transition_evidence(
        archive,
        (old, new),
        (ArchiveTransitionEvidence(record_file, previous_signature, next_signature),),
        archive_target_id="archive-primary",
        allowed_signers={"old": tmp_path / "old.allowed", "new": tmp_path / "new.allowed"},
        signer_principals={"old": "old@archive", "new": "new@archive"},
        public_keys={
            "old": ArchivePublicKey(tmp_path / "old.pub", OLD_FINGERPRINT),
            "new": ArchivePublicKey(tmp_path / "new.pub", NEW_FINGERPRINT),
        },
        verifier=transition_verifier,
    ) == (record,)
    assert transition_verifier.calls == [
        ("old@archive", OLD_FINGERPRINT),
        ("new@archive", NEW_FINGERPRINT),
    ]

    record_file.write_bytes(b" " + record.canonical_bytes)
    with pytest.raises(ArchiveTrustError, match="not canonical"):
        ArchiveSignerTransition.parse(record_file.read_bytes())


@pytest.mark.asyncio
async def test_exact_copy_reconstructs_only_final_checkpoint_and_proves_one_append() -> None:
    source = _verified_archive(1)
    copied = _verified_archive(1)
    reconstructor = RecordingReconstructor()

    plan = await reconstruct_new_target_checkpoint(
        source,
        copied,
        archive_target_id="new-immutable-target",
        reconstructor=reconstructor,
    )

    assert reconstructor.plans == [plan]
    assert plan.git_commit_sha == source.commits[-1].git.commit_sha
    assert plan.manifest_sha256 == source.commits[-1].batch.manifest_sha256
    assert plan.source_high_water_sequence == 1
    prove_one_normal_append(copied, _verified_archive(2))


def test_copy_and_append_proofs_reject_mutation_merge_and_duplicate_range() -> None:
    before = _verified_archive(1)
    mutated_commit = before.commits[0]
    mutated = VerifiedArchive(
        (
            VerifiedArchiveCommit(
                git=VerifiedGitCommit(
                    mutated_commit.git.commit_sha,
                    "f" * 40,
                    mutated_commit.git.parent_sha,
                ),
                batch=mutated_commit.batch,
            ),
        )
    )
    with pytest.raises(ArchiveContinuationError, match="does not match"):
        require_exact_archive_equality(before, mutated)

    with pytest.raises(ArchiveContinuationError, match="exactly one"):
        prove_one_normal_append(before, before)
