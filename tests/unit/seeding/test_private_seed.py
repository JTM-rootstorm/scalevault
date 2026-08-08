from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from kivra_memory.seeding.contracts import PrivateSeedBundle
from kivra_memory.seeding.private_seed import (
    PrivateSeedError,
    SeedApplyRequest,
    SeedApplyResult,
    apply_private_seed,
    load_private_seed_bundle,
    plan_private_seed,
)


def _record(
    *, key: str = "synthetic-anchor", statement: str = "Synthetic continuity anchor."
) -> dict[str, Any]:
    return {
        "record_key": key,
        "selector": {
            "tenant": "synthetic-tenant",
            "persona": "synthetic-persona",
            "lineage": "synthetic-lineage",
            "branch": "private-root",
            "subject_kind": "persona",
            "subject": "synthetic-persona",
        },
        "memory": {
            "category": "interaction_convention",
            "ontological_status": "interaction_convention",
            "scope": "persona",
            "visibility": "private_root",
            "statement": statement,
            "reason_to_remember": "Synthetic durable continuity fixture.",
            "interpretation_limits": ["This fixture describes no real person."],
            "confidence": 0.8,
            "salience": 0.7,
            "durability": 0.9,
            "sensitivity": 1,
        },
        "evidence": [
            {
                "source_ref": "synthetic://fixture/one",
                "source_sha256": "1" * 64,
            }
        ],
    }


def _bundle() -> dict[str, Any]:
    return {
        "contract_version": "scalevault-private-seed-v1",
        "bundle_key": "synthetic-private-seed",
        "records": [_record()],
    }


def _write_bundle(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_load_and_plan_are_deterministic_content_free_and_zero_write(tmp_path: Path) -> None:
    source = _write_bundle(tmp_path / "private.json", _bundle())
    original = source.read_bytes()

    bundle = load_private_seed_bundle(source)
    first = plan_private_seed(bundle)
    second = plan_private_seed(bundle)

    assert first == second
    assert first.record_count == 1
    assert source.read_bytes() == original
    rendered = first.model_dump_json()
    assert "Synthetic continuity anchor" not in rendered
    assert "synthetic-persona" not in rendered
    assert "synthetic://" not in rendered
    assert first.items[0].idempotency_key.startswith("private-seed-v1:")


def test_idempotency_identity_is_stable_when_record_content_changes(tmp_path: Path) -> None:
    first_value = _bundle()
    second_value = deepcopy(first_value)
    second_value["records"][0]["memory"]["statement"] = "Changed synthetic content."
    first = plan_private_seed(
        load_private_seed_bundle(_write_bundle(tmp_path / "first.json", first_value))
    )
    second = plan_private_seed(
        load_private_seed_bundle(_write_bundle(tmp_path / "second.json", second_value))
    )

    assert first.bundle_sha256 != second.bundle_sha256
    assert first.items[0].record_sha256 != second.items[0].record_sha256
    assert first.items[0].idempotency_key == second.items[0].idempotency_key


def test_validation_cli_prints_only_the_content_free_plan(tmp_path: Path) -> None:
    source = _write_bundle(tmp_path / "private.json", _bundle())
    repository = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [sys.executable, "scripts/validate_private_seed.py", str(source)],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert '"ok":true' in result.stdout
    assert "Synthetic continuity anchor" not in result.stdout
    assert "synthetic-persona" not in result.stdout
    assert "synthetic://fixture/one" not in result.stdout


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda value: value["records"][0]["memory"].__setitem__("visibility", "shareable"),
            "seed_bundle_schema_invalid",
        ),
        (
            lambda value: value["records"][0]["selector"].__setitem__(
                "tenant", "018f3d6a-4b7c-7abc-8def-0123456789ab"
            ),
            "seed_bundle_schema_invalid",
        ),
        (
            lambda value: value["records"][0]["memory"].__setitem__(
                "authority_class", "explicit_user_statement"
            ),
            "seed_bundle_schema_invalid",
        ),
        (
            lambda value: value["records"][0]["memory"].__setitem__(
                "statement", "password=synthetic-rejected-value"
            ),
            "secret_material_rejected",
        ),
        (
            lambda value: value["records"][0]["evidence"][0].__setitem__(
                "source_ref", "api_key=redacted-secret-value"
            ),
            "secret_material_rejected",
        ),
    ],
)
def test_loader_rejects_leakage_deploy_identifiers_trust_and_secrets(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None], code: str
) -> None:
    value = _bundle()
    mutate(value)
    source = _write_bundle(tmp_path / "private.json", value)

    with pytest.raises(PrivateSeedError, match=code):
        load_private_seed_bundle(source)


def test_loader_rejects_duplicate_json_names_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"contract_version":"a","contract_version":"b"}', encoding="utf-8")
    duplicate.chmod(0o600)
    with pytest.raises(PrivateSeedError, match="seed_bundle_schema_invalid"):
        load_private_seed_bundle(duplicate)

    target = _write_bundle(tmp_path / "target.json", _bundle())
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(PrivateSeedError, match="invalid_seed_bundle_path"):
        load_private_seed_bundle(linked)


def test_loader_requires_owner_only_mode_and_bounded_regular_file(tmp_path: Path) -> None:
    readable = _write_bundle(tmp_path / "readable.json", _bundle())
    readable.chmod(0o644)
    with pytest.raises(PrivateSeedError) as permissions:
        load_private_seed_bundle(readable)
    assert str(permissions.value) == "unsafe_seed_bundle_permissions"
    assert "readable.json" not in str(permissions.value)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * ((2 * 1024 * 1024) + 1))
    oversized.chmod(0o600)
    with pytest.raises(PrivateSeedError) as size:
        load_private_seed_bundle(oversized)
    assert str(size.value) == "invalid_seed_bundle_size"
    assert "x" not in str(size.value)

    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    with pytest.raises(PrivateSeedError) as regular:
        load_private_seed_bundle(directory)
    assert str(regular.value) in {
        "invalid_seed_bundle_path",
        "unsafe_seed_bundle_permissions",
    }


def test_loader_rejects_normalized_duplicate_memories(tmp_path: Path) -> None:
    value = _bundle()
    duplicate = deepcopy(value["records"][0])
    duplicate["record_key"] = "second-anchor"
    duplicate["memory"]["statement"] = "  SYNTHETIC   continuity anchor.  "
    value["records"].append(duplicate)

    with pytest.raises(PrivateSeedError, match="duplicate_seed_memory"):
        load_private_seed_bundle(_write_bundle(tmp_path / "private.json", value))


class _NominationService:
    def __init__(self) -> None:
        self.requests: list[SeedApplyRequest] = []

    async def nominate_private_seed(self, request: SeedApplyRequest) -> SeedApplyResult:
        self.requests.append(request)
        return SeedApplyResult(
            contract_version="scalevault-private-seed-result-v1",
            bundle_sha256=request.bundle_sha256,
            outcome="applied",
            nominated_count=len(request.nominations),
        )


class _UnsafeFailureService:
    async def nominate_private_seed(self, request: SeedApplyRequest) -> SeedApplyResult:
        raise RuntimeError(request.nominations[0].record.evidence[0].source_ref)


async def test_apply_requires_both_gates_and_uses_one_injected_service_call(tmp_path: Path) -> None:
    bundle = load_private_seed_bundle(_write_bundle(tmp_path / "private.json", _bundle()))
    plan = plan_private_seed(bundle)
    service = _NominationService()

    with pytest.raises(PrivateSeedError, match="seed_apply_not_approved"):
        await apply_private_seed(
            bundle,
            expected_digest=plan.bundle_sha256,
            approved=False,
            nomination_service=service,
        )
    with pytest.raises(PrivateSeedError, match="seed_bundle_digest_mismatch"):
        await apply_private_seed(
            bundle,
            expected_digest="0" * 64,
            approved=True,
            nomination_service=service,
        )
    assert service.requests == []

    result = await apply_private_seed(
        bundle,
        expected_digest=plan.bundle_sha256,
        approved=True,
        nomination_service=service,
    )
    assert result.outcome == "applied"
    assert len(service.requests) == 1
    request = service.requests[0]
    assert request.bundle_sha256 == plan.bundle_sha256
    assert request.nominations[0].record_sha256 == plan.items[0].record_sha256
    assert request.nominations[0].record.selector.tenant == "synthetic-tenant"
    assert not hasattr(request.nominations[0].record.memory, "authority_class")
    assert "source_ref" not in result.model_dump_json()
    assert "synthetic://fixture/one" not in result.model_dump_json()

    with pytest.raises(PrivateSeedError) as failure:
        await apply_private_seed(
            bundle,
            expected_digest=plan.bundle_sha256,
            approved=True,
            nomination_service=_UnsafeFailureService(),
        )
    assert str(failure.value) == "seed_nomination_failed"
    assert "synthetic://fixture/one" not in str(failure.value)


def test_generated_schema_is_closed_and_requires_symbolic_selectors() -> None:
    schema = PrivateSeedBundle.model_json_schema()
    assert schema["additionalProperties"] is False
    selector = schema["$defs"]["SymbolicSeedSelector"]
    assert selector["additionalProperties"] is False
    assert set(selector["required"]) == {
        "tenant",
        "persona",
        "lineage",
        "branch",
        "subject_kind",
        "subject",
    }
