from __future__ import annotations

import base64
import hashlib
import json
import os
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

import kivra_memory.security.leakage_scanner as leakage_scanner
import pytest
from kivra_memory.security.leakage_scanner import (
    CandidateFile,
    LeakageReason,
    LeakageScannerPolicy,
    main,
    scan_candidate_files,
    scan_candidate_tree,
)

PRIVATE_CANARY = "SYNTHETIC-private-canary-7f3d9b"


def candidate(path: str, value: object) -> CandidateFile:
    return CandidateFile(path, json.dumps(value, ensure_ascii=False).encode())


def test_clean_synthetic_candidate_passes_with_only_content_free_result() -> None:
    files = [
        candidate("records/one.json", {"summary": "A deliberately public synthetic record"}),
        CandidateFile("README.md", b"# Synthetic public fixture\n"),
    ]

    first = scan_candidate_files(files, canaries=[PRIVATE_CANARY])
    reordered = scan_candidate_files(reversed(files), canaries=[PRIVATE_CANARY])

    assert first.ok is True
    assert first.counts == {}
    assert first.artifact_sha256 == reordered.artifact_sha256
    rendered = json.dumps(first.as_dict())
    assert set(first.as_dict()) == {"ok", "artifact_sha256", "counts"}
    assert PRIVATE_CANARY not in rendered
    assert "records/one.json" not in rendered


@pytest.mark.parametrize(
    ("encoded", "reason"),
    [
        (PRIVATE_CANARY.encode(), LeakageReason.CANARY_RAW),
        (base64.b64encode(PRIVATE_CANARY.encode()), LeakageReason.CANARY_BASE64),
        (PRIVATE_CANARY.encode().hex().upper().encode(), LeakageReason.CANARY_HEX),
        (
            hashlib.sha256(PRIVATE_CANARY.encode()).hexdigest().encode(),
            LeakageReason.CANARY_DIGEST,
        ),
    ],
)
def test_detects_raw_and_encoded_canary_forms(encoded: bytes, reason: LeakageReason) -> None:
    result = scan_candidate_files(
        [CandidateFile("candidate.txt", b"prefix " + encoded + b" suffix")],
        canaries=[PRIVATE_CANARY],
    )

    assert result.ok is False
    assert result.counts[reason.value] == 1
    assert PRIVATE_CANARY not in json.dumps(result.as_dict())


def test_detects_unicode_normalization_without_echoing_the_canary() -> None:
    canary = "private-caf\N{LATIN SMALL LETTER E WITH ACUTE}-canary"
    decomposed = unicodedata.normalize("NFD", canary)
    assert decomposed.encode() != canary.encode()

    result = scan_candidate_files(
        [candidate("candidate.json", {"summary": decomposed})],
        canaries=[canary],
    )

    assert result.counts == {LeakageReason.CANARY_NORMALIZED.value: 1}
    assert canary not in json.dumps(result.as_dict())


def test_detects_nfkc_compatibility_normalization() -> None:
    canary = "private-ASCII-canary"
    compatibility_form = "private-\uff21\uff33\uff23\uff29\uff29-canary"

    result = scan_candidate_files(
        [candidate("candidate.json", {"summary": compatibility_form})],
        canaries=[canary],
    )

    assert result.counts == {LeakageReason.CANARY_NORMALIZED.value: 1}


def test_detects_urlsafe_unpadded_base64_for_binary_canary() -> None:
    canary = b"\xfb\xffsynthetic-private"
    encoded = base64.urlsafe_b64encode(canary).rstrip(b"=")

    result = scan_candidate_files(
        [CandidateFile("candidate.txt", encoded)],
        canaries=[canary],
    )

    assert result.counts == {LeakageReason.CANARY_BASE64.value: 1}


@pytest.mark.parametrize("normalization", ["NFC", "NFKC"])
@pytest.mark.parametrize(
    "representation",
    [
        "base64_standard_padded",
        "base64_standard_unpadded",
        "base64_urlsafe_padded",
        "base64_urlsafe_unpadded",
        "hex_lower",
        "hex_upper",
        "digest_lower",
        "digest_upper",
    ],
)
def test_encoded_forms_include_each_unicode_normalization(
    normalization: Literal["NFC", "NFKC"], representation: str
) -> None:
    canary = "private-cafe\N{COMBINING ACUTE ACCENT}-\uff21-canary"
    normalized = unicodedata.normalize(normalization, canary).encode()
    assert normalized != canary.encode()
    if representation == "base64_standard_padded":
        encoded = base64.b64encode(normalized)
        reason = LeakageReason.CANARY_BASE64
    elif representation == "base64_standard_unpadded":
        encoded = base64.b64encode(normalized).rstrip(b"=")
        reason = LeakageReason.CANARY_BASE64
    elif representation == "base64_urlsafe_padded":
        encoded = base64.urlsafe_b64encode(normalized)
        reason = LeakageReason.CANARY_BASE64
    elif representation == "base64_urlsafe_unpadded":
        encoded = base64.urlsafe_b64encode(normalized).rstrip(b"=")
        reason = LeakageReason.CANARY_BASE64
    elif representation == "hex_lower":
        encoded = normalized.hex().encode()
        reason = LeakageReason.CANARY_HEX
    elif representation == "hex_upper":
        encoded = normalized.hex().upper().encode()
        reason = LeakageReason.CANARY_HEX
    elif representation == "digest_lower":
        encoded = hashlib.sha256(normalized).hexdigest().encode()
        reason = LeakageReason.CANARY_DIGEST
    else:
        encoded = hashlib.sha256(normalized).hexdigest().upper().encode()
        reason = LeakageReason.CANARY_DIGEST

    result = scan_candidate_files(
        [CandidateFile("candidate.txt", encoded)],
        canaries=[canary],
    )

    assert result.counts == {reason.value: 1}


def test_json_escaping_does_not_hide_normalized_canary_text() -> None:
    canary = "private-caf\N{LATIN SMALL LETTER E WITH ACUTE}-canary"
    escaped = json.dumps({"summary": canary}, ensure_ascii=True).encode()
    assert canary.encode() not in escaped

    result = scan_candidate_files(
        [CandidateFile("candidate.json", escaped)],
        canaries=[canary],
    )

    assert result.counts == {LeakageReason.CANARY_RAW.value: 1}


def test_canaries_are_found_in_every_synthetic_private_content_class() -> None:
    files = [
        candidate("statement.json", {"statement": PRIVATE_CANARY}),
        candidate("reason.json", {"reason": PRIVATE_CANARY}),
        candidate("metadata.json", {"metadata": {"note": PRIVATE_CANARY}}),
        candidate("alias.json", {"aliases": [PRIVATE_CANARY]}),
        candidate("subject.json", {"subject_identifier": PRIVATE_CANARY}),
        candidate("collision.json", {"public": "same", "private": PRIVATE_CANARY}),
    ]

    result = scan_candidate_files(files, canaries=[PRIVATE_CANARY])

    assert result.counts[LeakageReason.CANARY_RAW.value] == len(files)


@pytest.mark.parametrize(
    "field",
    [
        # Sealed envelope/AAD and provider/destruction material.
        "ciphertext",
        "sealedCiphertext",
        "authentication-tag",
        "authentication_tag",
        "nonce",
        "aad",
        "aad_sha256",
        "content_key_id",
        "content_key_reference",
        "providerName",
        "provider_key_reference",
        "destruction_receipt",
        "destruction_receipt_sha256",
        # Canonical content, evidence, and content-bearing metadata.
        "statement",
        "memoryStatement",
        "reason_to_remember",
        "reason",
        "rationale",
        "resolution_rationale",
        "interpretationLimits",
        "metadata",
        "evidence_text",
        "evidence_summary",
        "excerpt",
        # Private source, transcript, manifest, and event linkage.
        "private_source_reference",
        "source_ref",
        "transcript",
        "transcript-reference",
        "private_manifest_linkage",
        "manifest_sha256",
        "previous_manifest_sha256",
        "source_high_water_sequence",
        "event_id",
        "causationEventId",
        # Private identities/installations and credentials.
        "tenant_id",
        "actorId",
        "client-id",
        "credential_id",
        "ingressId",
        "deployment_id",
        "host_identifier",
        "repositoryExternalId",
        "installation_id",
        "githubInstallationIdentifier",
        "publicationApprovedByActorId",
        "authorization",
        "secret_verifier",
    ],
)
def test_rejects_forbidden_structured_fields_at_any_depth(field: str) -> None:
    result = scan_candidate_files(
        [candidate("candidate.json", {"safe": [{field: "synthetic-value"}]})],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts == {LeakageReason.FORBIDDEN_FIELD.value: 1}


def test_forbidden_field_alias_normalization_is_unicode_and_separator_insensitive() -> None:
    fullwidth_alias = (
        "\uff33\uff25\uff21\uff2c\uff25\uff24-"
        "\uff23\uff29\uff30\uff28\uff25\uff32\uff34\uff25\uff38\uff34"
    )
    result = scan_candidate_files(
        [candidate("candidate.json", {fullwidth_alias: "synthetic"})],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts == {LeakageReason.FORBIDDEN_FIELD.value: 1}


def test_unicode_forbidden_alias_is_also_detected_in_text_key_syntax() -> None:
    fullwidth_alias = (
        "\uff33\uff25\uff21\uff2c\uff25\uff24-"
        "\uff23\uff29\uff30\uff28\uff25\uff32\uff34\uff25\uff38\uff34"
    )
    document = f"{fullwidth_alias}: synthetic\n".encode()

    result = scan_candidate_files(
        [CandidateFile("candidate.txt", document)],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts == {LeakageReason.FORBIDDEN_FIELD.value: 1}


@pytest.mark.parametrize(
    "payload",
    [
        b"Authorization: Bearer synthetic_bearer_value_that_is_long_enough",
        b"Basic c3ludGhldGljOnByaXZhdGU=",
        (
            b"svb1.019c0000-0000-7000-8000-000000000001."
            b"019c0000-0000-7000-8000-000000000002." + b"A" * 43
        ),
        b"hmac-sha256-v1:" + b"B" * 43,
        b'{"access_token":"synthetic-secret-value"}',
        b"TOKEN=synthetic_secret_value_12345",
        b"postgresql://operator:synthetic-password@database.invalid/vault",
        b"https://operator:synthetic-password@service.invalid/private",
        b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
        b"github_pat_0123456789abcdefghijklmnop",
        b"glpat-0123456789abcdefghijklmnop",
        b"AKIA0123456789ABCDEF",
    ],
)
def test_rejects_credential_and_authorization_grammar(payload: bytes) -> None:
    result = scan_candidate_files(
        [CandidateFile("candidate.txt", payload)], canaries=[PRIVATE_CANARY]
    )

    assert result.counts[LeakageReason.CREDENTIAL_GRAMMAR.value] == 1


def test_rejects_invalid_duplicate_and_unknown_paths() -> None:
    files = [
        CandidateFile("../escape.json", b"{}"),
        CandidateFile("same.json", b"{}"),
        CandidateFile("same.json", b"{}"),
        CandidateFile("binary.exe", b"synthetic"),
        CandidateFile("upper.JSON", b"{}"),
        CandidateFile("cafe\N{COMBINING ACUTE ACCENT}.json", b"{}"),
    ]

    result = scan_candidate_files(files, canaries=[PRIVATE_CANARY])

    assert result.counts[LeakageReason.PATH_INVALID.value] == 2
    assert result.counts[LeakageReason.DUPLICATE_PATH.value] == 1
    assert result.counts[LeakageReason.FILE_TYPE_FORBIDDEN.value] == 2


def test_materialized_map_rejects_link_or_special_provenance() -> None:
    result = scan_candidate_files(
        [
            CandidateFile("link.txt", b"", source_kind="link"),
            CandidateFile("special.txt", b"", source_kind="special"),
        ],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts == {LeakageReason.LINK_OR_SPECIAL_FILE.value: 2}


@pytest.mark.parametrize(
    "path",
    [
        "/absolute.json",
        "records//duplicate-separator.json",
        "records/./dot.json",
        "a/../escape.json",
        "a" * 241 + ".txt",
        "/".join(["nested"] * 17) + ".txt",
    ],
)
def test_candidate_paths_obey_canonical_posix_depth_and_byte_bounds(path: str) -> None:
    result = scan_candidate_files(
        [CandidateFile(path, b"{}")],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts[LeakageReason.PATH_INVALID.value] == 1


def test_rejects_malformed_text_json_and_resource_overruns() -> None:
    malformed = scan_candidate_files(
        [
            CandidateFile("bad.json", b'{"x":1,"x":2}'),
            CandidateFile("control.json", b'{"safe":"\\u0000"}'),
            CandidateFile("bad.txt", b"\xff\x00"),
        ],
        canaries=[PRIVATE_CANARY],
    )
    policy = LeakageScannerPolicy(maximum_files=1, maximum_file_bytes=8, maximum_tree_bytes=4)
    overrun = scan_candidate_files(
        [CandidateFile("large.txt", b"more than eight bytes")],
        canaries=[PRIVATE_CANARY],
        policy=policy,
    )

    assert malformed.counts[LeakageReason.MALFORMED_ENCODING.value] >= 3
    assert overrun.counts[LeakageReason.TREE_TOO_LARGE.value] >= 1
    assert overrun.counts[LeakageReason.FILE_TOO_LARGE.value] == 1


def test_invalid_canary_inputs_fail_closed() -> None:
    result = scan_candidate_files(
        [CandidateFile("candidate.json", b"{}")],
        canaries=[b"short", PRIVATE_CANARY, PRIVATE_CANARY],
    )

    assert result.ok is False
    assert result.counts == {LeakageReason.CANARY_INPUT_INVALID.value: 2}

    missing = scan_candidate_files([CandidateFile("candidate.json", b"{}")], canaries=[])
    assert missing.counts == {LeakageReason.CANARY_INPUT_INVALID.value: 1}
    assert result.artifact_sha256 == missing.artifact_sha256


@pytest.mark.parametrize(
    "canaries",
    [[], [PRIVATE_CANARY, PRIVATE_CANARY], [b"short"]],
)
def test_tree_wrapper_preserves_incomplete_canary_input_digest(
    tmp_path: Path, canaries: list[str | bytes]
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "clean.txt").write_text("clean synthetic candidate")

    pure = scan_candidate_files(
        [CandidateFile("clean.txt", b"clean synthetic candidate")], canaries=canaries
    )
    wrapped = scan_candidate_tree(root, canaries=canaries)

    assert wrapped.counts[LeakageReason.CANARY_INPUT_INVALID.value] >= 1
    assert wrapped.artifact_sha256 == pure.artifact_sha256


def test_file_iterable_is_consumed_only_through_the_fixed_bound() -> None:
    consumed = 0
    policy = LeakageScannerPolicy(maximum_files=2)

    def files() -> Iterator[CandidateFile]:
        nonlocal consumed
        while True:
            consumed += 1
            yield CandidateFile(f"candidate-{consumed}.txt", b"clean")

    result = scan_candidate_files(files(), canaries=[PRIVATE_CANARY], policy=policy)

    assert consumed == 3
    assert result.counts == {LeakageReason.TREE_TOO_LARGE.value: 1}

    another_overflow = scan_candidate_files(
        [
            CandidateFile("different-one.txt", b"different"),
            CandidateFile("different-two.txt", b"different"),
            CandidateFile("different-three.txt", b"different"),
        ],
        canaries=[PRIVATE_CANARY],
        policy=policy,
    )
    assert result.artifact_sha256 == another_overflow.artifact_sha256


def test_complete_rejected_artifact_still_has_its_exact_distinguishing_digest() -> None:
    first = scan_candidate_files(
        [CandidateFile("forbidden.bin", b"first")], canaries=[PRIVATE_CANARY]
    )
    second = scan_candidate_files(
        [CandidateFile("forbidden.bin", b"second")], canaries=[PRIVATE_CANARY]
    )

    assert first.counts == second.counts == {LeakageReason.FILE_TYPE_FORBIDDEN.value: 1}
    assert first.artifact_sha256 != second.artifact_sha256


def test_internal_iteration_failure_is_sanitized() -> None:
    private_exception = f"exception contains {PRIVATE_CANARY}"

    def broken_files() -> Iterator[CandidateFile]:
        raise RuntimeError(private_exception)
        yield CandidateFile("never.json", b"{}")

    result = scan_candidate_files(broken_files(), canaries=[PRIVATE_CANARY])

    assert result.counts == {LeakageReason.INTERNAL_ERROR.value: 1}
    assert PRIVATE_CANARY not in json.dumps(result.as_dict())


def test_tree_adapter_rejects_symbolic_and_hard_links(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    regular = root / "regular.txt"
    regular.write_text("synthetic clean text")
    (root / "symbolic.txt").symlink_to(regular)
    os.link(regular, root / "hard.txt")

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])

    assert result.ok is False
    assert result.counts[LeakageReason.LINK_OR_SPECIAL_FILE.value] == 3


def test_tree_adapter_rejects_special_files_without_reading_them(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    os.mkfifo(root / "named-pipe.txt")

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])

    assert result.counts == {LeakageReason.LINK_OR_SPECIAL_FILE.value: 1}


def test_tree_adapter_scans_nested_regular_files_without_path_races(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    nested = root / "records"
    nested.mkdir(parents=True)
    (nested / "one.json").write_text(json.dumps({"summary": PRIVATE_CANARY}))

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    pure = scan_candidate_files(
        [candidate("records/one.json", {"summary": PRIVATE_CANARY})],
        canaries=[PRIVATE_CANARY],
    )

    assert result.counts == {LeakageReason.CANARY_RAW.value: 1}
    assert result.artifact_sha256 == pure.artifact_sha256


def test_tree_adapter_rejects_a_symbolic_root(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(root, target_is_directory=True)

    result = scan_candidate_tree(linked_root, canaries=[PRIVATE_CANARY])

    assert result.counts == {LeakageReason.LINK_OR_SPECIAL_FILE.value: 1}


def test_tree_adapter_rejects_concurrent_name_insertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "clean.txt").write_text("clean synthetic candidate")
    original = leakage_scanner._directory_names
    calls = 0

    def changing_names(directory_descriptor: int, *, maximum_entries: int) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 2:
            (root / "inserted.txt").write_text("concurrent synthetic insertion")
        return original(directory_descriptor, maximum_entries=maximum_entries)

    monkeypatch.setattr(leakage_scanner, "_directory_names", changing_names)
    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])

    assert result.counts[LeakageReason.LINK_OR_SPECIAL_FILE.value] >= 1
    assert result.artifact_sha256 == incomplete.artifact_sha256


def test_tree_adapter_rejects_directory_metadata_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "clean.txt").write_text("clean synthetic candidate")
    monkeypatch.setattr(leakage_scanner, "_stable_directory_metadata", lambda _a, _b: False)

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])

    assert result.counts[LeakageReason.LINK_OR_SPECIAL_FILE.value] >= 1
    assert result.artifact_sha256 == incomplete.artifact_sha256


def test_tree_adapter_rejects_root_path_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "clean.txt").write_text("clean synthetic candidate")
    original = leakage_scanner._directory_names
    calls = 0

    def substitute_root(directory_descriptor: int, *, maximum_entries: int) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 2:
            root.rename(tmp_path / "moved-candidate")
            root.mkdir()
        return original(directory_descriptor, maximum_entries=maximum_entries)

    monkeypatch.setattr(leakage_scanner, "_directory_names", substitute_root)
    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])

    assert result.counts[LeakageReason.LINK_OR_SPECIAL_FILE.value] >= 1
    assert result.artifact_sha256 == incomplete.artifact_sha256


def test_tree_adapter_rejects_nested_mount_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    nested = root / "mounted"
    nested.mkdir(parents=True)
    mount = ("100", "1", "0:1", "/", str(root))
    nested_mount = ("101", "100", "0:2", "/", str(nested))
    monkeypatch.setattr(
        leakage_scanner,
        "_mountinfo_snapshot",
        lambda: (mount, nested_mount),
    )

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])

    assert result.counts == {LeakageReason.LINK_OR_SPECIAL_FILE.value: 1}
    assert result.artifact_sha256 == incomplete.artifact_sha256


def test_tree_adapter_rejects_mount_table_change_during_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "clean.txt").write_text("clean synthetic candidate")
    first = (("100", "1", "0:1", "/", str(root)),)
    second = (*first, ("101", "1", "0:2", "/", "/unrelated"))
    snapshots = iter((first, second))
    monkeypatch.setattr(leakage_scanner, "_mountinfo_snapshot", lambda: next(snapshots))

    result = scan_candidate_tree(root, canaries=[PRIVATE_CANARY])
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])

    assert result.counts[LeakageReason.LINK_OR_SPECIAL_FILE.value] == 1
    assert result.artifact_sha256 == incomplete.artifact_sha256


def test_cli_requires_protected_canary_input_and_emits_no_sensitive_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "candidate.json").write_text(json.dumps({"summary": PRIVATE_CANARY}))
    canary_file = tmp_path / "canaries"
    canary_file.write_text(PRIVATE_CANARY + "\n")
    canary_file.chmod(0o600)
    monkeypatch.setattr(
        leakage_scanner,
        "_read_protected_canaries",
        lambda _path, _policy: (PRIVATE_CANARY.encode(),),
    )

    exit_code = main(["--candidate-root", str(root), "--canary-file", str(canary_file)])

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert exit_code == 1
    assert report["counts"] == {LeakageReason.CANARY_RAW.value: 1}
    assert PRIVATE_CANARY not in output.out
    assert str(root) not in output.out
    assert output.err == ""


def test_canary_reader_requires_root_owner_exact_0600_and_reuses_hardened_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_reader(path: Path, **options: object) -> bytes:
        captured["path"] = path
        captured.update(options)
        return PRIVATE_CANARY.encode() + b"\n"

    monkeypatch.setattr(leakage_scanner, "read_protected_file", fake_reader)
    canaries = leakage_scanner._read_protected_canaries(
        tmp_path / "canaries", LeakageScannerPolicy()
    )

    assert canaries == (PRIVATE_CANARY.encode(),)
    assert captured["required_owner_uid"] == 0
    assert captured["allowed_modes"] == frozenset({0o600})
    assert captured["minimum_bytes"] == 0


def test_canary_reader_rejects_non_root_owned_file(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("test requires a non-root process owner")
    canary_file = tmp_path / "canaries"
    canary_file.write_text(PRIVATE_CANARY + "\n")
    canary_file.chmod(0o600)

    with pytest.raises(ValueError):
        leakage_scanner._read_protected_canaries(canary_file, LeakageScannerPolicy())


def test_cli_reports_missing_canary_file_as_incomplete_invalid_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()

    exit_code = main(["--candidate-root", str(root), "--canary-file", str(tmp_path / "missing")])

    report = json.loads(capsys.readouterr().out)
    incomplete = scan_candidate_files([CandidateFile("ignored.txt", b"ignored")], canaries=[])
    assert exit_code == 1
    assert report["counts"] == {LeakageReason.CANARY_INPUT_INVALID.value: 1}
    assert report["artifact_sha256"] == incomplete.artifact_sha256


def test_cli_fails_closed_on_weak_canary_file_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    canary_file = tmp_path / "canaries"
    canary_file.write_text(PRIVATE_CANARY + "\n")
    canary_file.chmod(0o644)

    exit_code = main(["--candidate-root", str(root), "--canary-file", str(canary_file)])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["counts"] == {LeakageReason.CANARY_INPUT_INVALID.value: 1}


@pytest.mark.parametrize("content", ["", "\n", f"{PRIVATE_CANARY}\n\nsecond-private-canary\n"])
def test_cli_fails_closed_on_empty_canary_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    canary_file = tmp_path / "canaries"
    canary_file.write_text(content)
    canary_file.chmod(0o600)

    exit_code = main(["--candidate-root", str(root), "--canary-file", str(canary_file)])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["counts"] == {LeakageReason.CANARY_INPUT_INVALID.value: 1}


def test_cli_fails_closed_on_hard_linked_canary_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    canary_file = tmp_path / "canaries"
    canary_file.write_text(PRIVATE_CANARY + "\n")
    canary_file.chmod(0o600)
    os.link(canary_file, tmp_path / "canaries-copy")

    exit_code = main(["--candidate-root", str(root), "--canary-file", str(canary_file)])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["counts"] == {LeakageReason.CANARY_INPUT_INVALID.value: 1}
