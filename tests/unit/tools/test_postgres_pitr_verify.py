"""Content-free PostgreSQL PITR verifier contracts."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import EventOperation, MemoryVisibility
from kivra_memory.domain.events import (
    BranchCreatedPayload,
    BranchState,
    MemoryEvent,
    event_hash_fields,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.models import Branch, Memory
from kivra_memory.storage.projector import ProjectionRows
from kivra_memory.tools import postgres_pitr_verify as module
from kivra_memory.tools.postgres_pitr_verify import (
    ApplicationSnapshot,
    PitrConfigurationError,
    PitrManifest,
    ServerSnapshot,
)

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64
_F = "f" * 64
_ZERO = "0" * 64
_RPO_REFERENCE = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
_STARTED = datetime(2026, 8, 15, 12, 5, tzinfo=UTC)
_FINISHED = datetime(2026, 8, 15, 12, 10, tzinfo=UTC)


def _manifest_document(tmp_path: Path) -> dict[str, object]:
    target_value = "after_b"
    return {
        "version": 1,
        "system_identifier_sha256": _A,
        "timeline_id": 2,
        "recovery_target": {
            "kind": "name",
            "value": target_value,
            "sha256": module._target_sha256("name", target_value),
        },
        "migration_revision": "0011_observability_aggregates",
        "compatibility": {
            "component": "memory_node",
            "contract_version": 11,
            "minimum_reader_revision": "0011_observability_aggregates",
            "minimum_writer_revision": "0011_observability_aggregates",
        },
        "extension_versions": {
            "citext": "1.6",
            "pg_trgm": "1.6",
            "pgcrypto": "1.3",
            "vector": "0.8.0",
        },
        "event_count": 2,
        "event_prefix_sha256": _B,
        "projection": {
            "counts": {
                "branches": 1,
                "memories": 1,
                "evidence": 0,
                "links": 0,
                "conflicts": 0,
                "conflict_members": 0,
            },
            "sha256": _C,
        },
        "markers": {
            "a": {"sequence": 1, "command_sha256": _A},
            "b": {"sequence": 2, "command_sha256": _B},
            "c": {"sequence": 3, "command_sha256": _C},
        },
        "synthetic": {
            "tenant_id": str(new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=901)),
            "memory_id": str(new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=902)),
            "drill_generation": "phase-2-generation",
            "correlation_sha256": _D,
        },
        "embedding_requeue": {"count": 1, "sha256": _E},
        "provider_attachment_paths": [str(tmp_path / "provider-control")],
        "destruction_ledger": {
            "root": str(tmp_path / "ledger"),
            "anchor_path": str(tmp_path / "anchor" / "current.json"),
            "accepted_entry_count": 1,
            "accepted_aggregate_sha256": _ZERO,
        },
        "drill_started_at": "2026-08-15T12:05:00.000000Z",
        "rpo_reference_at": "2026-08-15T12:00:00.000000Z",
    }


def _manifest(tmp_path: Path) -> PitrManifest:
    return PitrManifest.model_validate(_manifest_document(tmp_path))


def _event(*, sequence: int = 1) -> MemoryEvent:
    """Create one valid immutable envelope for digest-binding tests."""

    def uid(value: int) -> UUID:
        return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)

    created_at = datetime(2026, 8, 15, 12, 1, tzinfo=UTC)
    tenant_id = uid(1)
    lineage_id = uid(2)
    branch_id = uid(3)
    actor_id = uid(4)
    client_id = uid(5)
    transport_binding_id = uid(6)
    payload = BranchCreatedPayload(
        branch=BranchState(
            branch_id=branch_id,
            tenant_id=tenant_id,
            lineage_id=lineage_id,
            name="synthetic",
            visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
            created_at=created_at,
        )
    )
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=EventOperation.BRANCH_CREATED,
        payload=payload,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        memory_id=None,
        expected_revision=None,
        causation_event_id=None,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=uid(100 + sequence),
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=transport_binding_id,
        session_id=None,
        ingress_id=None,
        operation=EventOperation.BRANCH_CREATED,
        memory_id=None,
        expected_revision=None,
        causation_event_id=None,
        correlation_id=uid(7),
        idempotency_key=f"synthetic:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


def _branch_projection() -> Branch:
    def uid(value: int) -> UUID:
        return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)

    created_at = datetime(2026, 8, 15, 12, 1, tzinfo=UTC)
    return Branch(
        branch_id=uid(1),
        tenant_id=uid(2),
        lineage_id=uid(3),
        parent_branch_id=None,
        fork_event_sequence=None,
        name="synthetic",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=created_at,
        sealed_at=None,
    )


def _projection_digest(*, branch: Branch) -> str:
    rows = ProjectionRows((branch,), (), (), (), (), ())
    return module._projection_summary(rows, sequence=1)[1]


def _add_unknown(value: dict[str, object]) -> None:
    value["unexpected"] = True


def _break_target_digest(value: dict[str, object]) -> None:
    cast(dict[str, object], value["recovery_target"])["sha256"] = _A


def _break_marker_order(value: dict[str, object]) -> None:
    markers = cast(dict[str, object], value["markers"])
    cast(dict[str, object], markers["c"])["sequence"] = 2


def _break_migration(value: dict[str, object]) -> None:
    value["migration_revision"] = "0010_ingress_provider_heads"


def _break_timing_order(value: dict[str, object]) -> None:
    value["drill_started_at"] = "2026-08-15T11:59:59.000000Z"


def _server(manifest: PitrManifest) -> ServerSnapshot:
    return ServerSnapshot(
        server_version_num=170006,
        system_identifier_sha256=manifest.system_identifier_sha256,
        timeline_id=manifest.timeline_id,
        in_recovery=True,
        replay_paused=True,
        transaction_read_only=True,
        listen_addresses="",
        socket_connection=True,
        archive_mode="off",
        recovery_target_action="pause",
        recovery_target_value=manifest.recovery_target.value,
        recovery_target_sha256=manifest.recovery_target.sha256,
        replay_timestamp=_RPO_REFERENCE - timedelta(seconds=60),
    )


def _application(manifest: PitrManifest) -> ApplicationSnapshot:
    return ApplicationSnapshot(
        migration_revision=manifest.migration_revision,
        compatibility=(
            manifest.compatibility.contract_version,
            manifest.compatibility.minimum_reader_revision,
            manifest.compatibility.minimum_writer_revision,
        ),
        extension_versions=manifest.extension_versions,
        event_count=manifest.event_count,
        event_prefix_sha256=manifest.event_prefix_sha256,
        projection_counts=manifest.projection.counts.model_dump(),
        projection_sha256=manifest.projection.sha256,
        rebuilt_projection_counts=manifest.projection.counts.model_dump(),
        rebuilt_projection_sha256=manifest.projection.sha256,
        marker_a_present=True,
        marker_b_present=True,
        marker_c_absent=True,
        synthetic_correlation_sha256=manifest.synthetic.correlation_sha256,
        embedding_requeue_count=manifest.embedding_requeue.count,
        embedding_requeue_sha256=manifest.embedding_requeue.sha256,
    )


def _verify(
    manifest: PitrManifest,
    *,
    server: ServerSnapshot | None = None,
    application: ApplicationSnapshot | None = None,
    destruction_verified: bool = True,
    attachments_absent: bool = True,
    finished_at: datetime = _FINISHED,
) -> module.VerificationReport:
    return module.verify_snapshots(
        manifest,
        server or _server(manifest),
        application or _application(manifest),
        destruction_verified=destruction_verified,
        provider_attachments_absent=attachments_absent,
        finished_at=finished_at,
    )


def test_manifest_requires_protected_canonical_exact_document(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    document = _manifest_document(tmp_path)
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)

    loaded = PitrManifest.load(path)

    assert loaded.event_count == 2
    assert loaded.markers.c.sequence == 3

    path.write_text(json.dumps(document, indent=2))
    with pytest.raises(PitrConfigurationError, match="manifest_invalid"):
        PitrManifest.load(path)

    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o644)
    with pytest.raises(PitrConfigurationError, match="manifest_invalid"):
        PitrManifest.load(path)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_add_unknown, "manifest_invalid"),
        (_break_target_digest, "manifest_invalid"),
        (_break_marker_order, "manifest_invalid"),
        (_break_migration, "manifest_invalid"),
        (_break_timing_order, "manifest_invalid"),
    ],
)
def test_manifest_rejects_unknown_or_unbound_contracts(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
    expected: str,
) -> None:
    document = _manifest_document(tmp_path)
    mutate(document)
    path = tmp_path / "manifest.json"
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)
    with pytest.raises(PitrConfigurationError, match=expected):
        PitrManifest.load(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("payload_version", 2),
        ("event_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=200)),
        ("tenant_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=201)),
        ("lineage_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=202)),
        ("branch_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=203)),
        ("actor_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=204)),
        ("client_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=205)),
        (
            "transport_binding_id",
            new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=206),
        ),
        ("session_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=207)),
        ("ingress_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=208)),
        ("operation", EventOperation.LINKED),
        ("memory_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=209)),
        ("expected_revision", 2),
        (
            "causation_event_id",
            new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=210),
        ),
        ("correlation_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=211)),
        ("idempotency_key", "synthetic:changed"),
        ("policy_version", 2),
        ("normalization_version", 2),
        ("payload_sha256", _D),
        ("command_sha256", _E),
        ("created_at", datetime(2026, 8, 15, 12, 2, tzinfo=UTC)),
    ],
)
def test_event_prefix_binds_every_immutable_envelope_field(
    field: str,
    value: object,
) -> None:
    original = _event()
    changed = original.model_copy(update={field: value})

    assert module._event_prefix_sha256((changed,)) != module._event_prefix_sha256((original,))


def test_event_prefix_rejects_a_sequence_gap_before_digesting() -> None:
    with pytest.raises(module.PitrVerificationError):
        module._event_prefix_sha256((_event(sequence=2),))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("branch_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=301)),
        ("tenant_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=302)),
        ("lineage_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=303)),
        ("parent_branch_id", new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=304)),
        ("fork_event_sequence", 7),
        ("name", "changed"),
        ("visibility_ceiling", MemoryVisibility.RESTRICTED),
        ("created_at", datetime(2026, 8, 15, 12, 2, tzinfo=UTC)),
        ("sealed_at", datetime(2026, 8, 15, 12, 3, tzinfo=UTC)),
    ],
)
def test_projection_digest_binds_every_branch_canonical_field(
    field: str,
    value: object,
) -> None:
    original = _branch_projection()
    changed = _branch_projection()
    setattr(changed, field, value)

    assert _projection_digest(branch=changed) != _projection_digest(branch=original)


def test_projection_field_allowlist_covers_every_mapped_canonical_column() -> None:
    for model in module._PROJECTION_MODELS:
        mapped = {attribute.key for attribute in model.__mapper__.column_attrs}
        excluded = {"search_document"} if model is Memory else set()

        assert set(module._PROJECTION_FIELDS[model]) == mapped - excluded


def test_database_connection_file_is_protected_and_socket_only(tmp_path: Path) -> None:
    path = tmp_path / "database-url"
    path.write_text("postgresql://memory_recovery@%2Ftmp/private-socket/scalevault")
    path.chmod(0o600)

    assert "%2Ftmp" in module._read_database_url(path)

    path.write_text("postgresql://memory_recovery:secret@127.0.0.1/scalevault")
    with pytest.raises(PitrConfigurationError, match="database_connection_invalid"):
        module._read_database_url(path)
    path.write_text("postgresql://memory_recovery@%2Ftmp/private-socket/scalevault")
    path.chmod(0o644)
    with pytest.raises(PitrConfigurationError, match="database_connection_invalid"):
        module._read_database_url(path)


def test_passing_report_has_one_fixed_content_free_schema(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    report = _verify(manifest)
    rendered = json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":"))

    assert report.ok
    assert report.result_code == "verified"
    assert [check.name for check in report.checks] == list(module._CHECK_NAMES)
    assert {check.status for check in report.checks} == {"pass"}
    assert set(report.as_dict()) == {
        "schema_version",
        "ok",
        "result_code",
        "checks",
        "counts",
        "digests",
        "timings",
    }
    assert report.rpo_seconds == 60
    assert report.rto_seconds == 300
    assert str(manifest.synthetic.tenant_id) not in rendered
    assert str(manifest.synthetic.memory_id) not in rendered
    assert manifest.destruction_ledger.root not in rendered
    assert manifest.synthetic.drill_generation not in rendered


@pytest.mark.parametrize(
    ("server_changes", "failed_check"),
    [
        ({"server_version_num": 180000}, "database_runtime"),
        ({"system_identifier_sha256": _F}, "database_runtime"),
        ({"timeline_id": 3}, "database_runtime"),
        ({"in_recovery": False}, "recovery_isolation"),
        ({"replay_paused": False}, "recovery_isolation"),
        ({"transaction_read_only": False}, "recovery_isolation"),
        ({"listen_addresses": "127.0.0.1"}, "recovery_isolation"),
        ({"socket_connection": False}, "recovery_isolation"),
        ({"archive_mode": "on"}, "recovery_isolation"),
        ({"recovery_target_action": "promote"}, "recovery_isolation"),
        ({"recovery_target_value": "after_c"}, "recovery_target"),
    ],
)
def test_runtime_and_recovery_mismatches_fail_closed(
    tmp_path: Path,
    server_changes: dict[str, object],
    failed_check: str,
) -> None:
    manifest = _manifest(tmp_path)
    report = _verify(
        manifest,
        server=replace(_server(manifest), **cast(Any, server_changes)),
    )

    assert not report.ok
    assert report.result_code == "verification_failed"
    assert next(check for check in report.checks if check.name == failed_check).status == "fail"


@pytest.mark.parametrize(
    ("application_changes", "failed_check"),
    [
        ({"migration_revision": "0010_ingress_provider_heads"}, "compatibility"),
        ({"extension_versions": {"citext": "1.6"}}, "compatibility"),
        ({"event_count": 1}, "events"),
        ({"event_prefix_sha256": _F}, "events"),
        ({"projection_sha256": _F}, "projections"),
        ({"rebuilt_projection_sha256": _F}, "projections"),
        ({"rebuilt_projection_counts": {}}, "projections"),
        ({"marker_a_present": False}, "pitr_markers"),
        ({"marker_b_present": False}, "pitr_markers"),
        ({"marker_c_absent": False}, "pitr_markers"),
        ({"synthetic_correlation_sha256": _F}, "synthetic_correlation"),
        ({"embedding_requeue_count": 0}, "embedding_requeue"),
        ({"embedding_requeue_sha256": _A}, "embedding_requeue"),
    ],
)
def test_application_mismatches_fail_closed(
    tmp_path: Path,
    application_changes: dict[str, object],
    failed_check: str,
) -> None:
    manifest = _manifest(tmp_path)
    application = replace(_application(manifest), **cast(Any, application_changes))
    report = _verify(manifest, application=application)

    assert not report.ok
    assert next(check for check in report.checks if check.name == failed_check).status == "fail"


def test_external_authority_attachment_and_objective_failures_are_explicit(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)

    ledger = _verify(manifest, destruction_verified=False)
    attachment = _verify(manifest, attachments_absent=False)
    rpo = _verify(
        manifest,
        server=replace(
            _server(manifest),
            replay_timestamp=_RPO_REFERENCE - timedelta(seconds=901),
        ),
    )
    rto = _verify(manifest, finished_at=_STARTED + timedelta(seconds=14_401))

    assert next(check for check in ledger.checks if check.name == "destruction_authority").code == (
        "destruction_anchor_mismatch"
    )
    assert next(
        check for check in attachment.checks if check.name == "provider_attachment"
    ).code == ("provider_attachment_present")
    assert next(check for check in rpo.checks if check.name == "objectives").status == "fail"
    assert next(check for check in rto.checks if check.name == "objectives").status == "fail"


@pytest.mark.asyncio
async def test_destruction_anchor_is_checked_before_application_relations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    calls: list[str] = []

    class Probe:
        async def server_snapshot(self, received: PitrManifest) -> ServerSnapshot:
            assert received is manifest
            calls.append("server")
            return _server(manifest)

        async def application_snapshot(self, received: PitrManifest) -> ApplicationSnapshot:
            assert received is manifest
            calls.append("application")
            return _application(manifest)

    def ledger(received: PitrManifest) -> bool:
        assert received is manifest
        calls.append("ledger")
        return True

    monkeypatch.setattr(module, "_verify_destruction_authority", ledger)
    monkeypatch.setattr(module, "_provider_attachments_absent", lambda paths: True)
    report = await module.verify_pitr(
        manifest,
        cast(module.PostgresPitrProbe, Probe()),
        now=_FINISHED,
    )

    assert report.ok
    assert calls == ["server", "ledger", "application"]


@pytest.mark.asyncio
async def test_failed_destruction_anchor_prevents_application_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)

    class Probe:
        async def server_snapshot(self, received: PitrManifest) -> ServerSnapshot:
            return _server(received)

        async def application_snapshot(self, received: PitrManifest) -> ApplicationSnapshot:
            raise AssertionError("application relations must remain unread")

    monkeypatch.setattr(module, "_verify_destruction_authority", lambda received: False)
    monkeypatch.setattr(module, "_provider_attachments_absent", lambda paths: True)
    report = await module.verify_pitr(
        manifest,
        cast(module.PostgresPitrProbe, Probe()),
        now=_FINISHED,
    )

    assert not report.ok
    check = next(item for item in report.checks if item.name == "destruction_authority")
    assert (check.status, check.code) == ("fail", "destruction_anchor_mismatch")


def test_cli_argument_failure_emits_one_sanitized_json_and_fixed_exit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = module.main(())
    captured = capsys.readouterr()
    lines = captured.out.splitlines()

    assert exit_code == 2
    assert captured.err == ""
    assert len(lines) == 1
    report = json.loads(lines[0])
    assert report["result_code"] == "configuration_invalid"
    assert report["ok"] is False
    assert len(report["checks"]) == len(module._CHECK_NAMES)
    assert all(check["status"] == "not_run" for check in report["checks"])


def test_cli_sanitizes_unexpected_failures_without_raw_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(arguments: object) -> tuple[Path, Path]:
        del arguments
        raise RuntimeError("secret DSN and private path")

    monkeypatch.setattr(module, "_parse_arguments", fail)
    exit_code = module.main(("ignored", "ignored", "ignored", "ignored"))
    captured = capsys.readouterr()

    assert exit_code == 5
    assert captured.err == ""
    assert "secret DSN" not in captured.out
    assert "private path" not in captured.out
    assert json.loads(captured.out)["result_code"] == "internal_error"


def test_provider_attachment_check_never_traverses_or_removes_paths(tmp_path: Path) -> None:
    absent = tmp_path / "absent"
    present = tmp_path / "present"
    present.mkdir()

    assert module._provider_attachments_absent((str(absent),))
    assert not module._provider_attachments_absent((str(present),))
    assert present.is_dir()
