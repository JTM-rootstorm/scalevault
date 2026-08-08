"""Zero-write planning for the exact Genesis archive snapshot."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.errors import CanonicalJsonError
from kivra_memory.ingress.processor import (
    GENESIS_MAPPING_VERSION,
    GenesisProcessingResult,
    IngressProcessorError,
    process_validated_ingress,
)
from kivra_memory.ingress.snapshot import (
    GENESIS_IMPORT_COMPATIBILITY_VERSION,
    GENESIS_SOURCE_REPOSITORY,
    GENESIS_SOURCE_SNAPSHOT_COMMIT,
    GenesisSnapshotSource,
    GitObjectReader,
    ImportPlanManifest,
    ManifestError,
    PlannedImportRecord,
    SnapshotError,
    SnapshotSourceItem,
    SourceContract,
    build_import_plan_manifest,
)
from kivra_memory.ingress.validator import IngressValidationError, validate_ingress
from kivra_memory.policy import SELECTION_V1_PROFILE, SELECTION_V1_PROFILE_SHA256

GENESIS_PLAN_REPORT_VERSION = "scalevault.genesis-import-plan-report.v1"
GENESIS_COMPATIBILITY_VERSION = GENESIS_IMPORT_COMPATIBILITY_VERSION
GENESIS_PARSER_SCHEMA_VERSIONS: Mapping[SourceContract, str] = {
    SourceContract.PROPOSAL_V1: "proposal-v1.schema.1",
    SourceContract.CHECKPOINT_V1: "checkpoint-v1.documented.1",
    SourceContract.CHECKPOINT_V2: "checkpoint-v2.schema.1",
}

_EXCLUSION_DOMAIN = b"scalevault.genesis-import.exclusion.v1\x00"
_SUPERSESSION_DOMAIN = b"scalevault.genesis-import.supersession.v1\x00"
_IDEMPOTENCY_DOMAIN = b"scalevault.genesis-import.plan-record.v1\x00"
_MAX_REPORT_BYTES = 64 * 1024


class GenesisPlanError(RuntimeError):
    """A payload-safe zero-write planning failure."""


@dataclass(frozen=True, slots=True)
class GenesisPlanReport:
    """Safe aggregate output which intentionally omits source-local identifiers."""

    value: Mapping[str, object]
    canonical_bytes: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> GenesisPlanReport:
        if not raw or len(raw) > _MAX_REPORT_BYTES:
            raise GenesisPlanError("invalid_expected_manifest")
        document = raw.removesuffix(b"\n")
        try:
            parsed = parse_json_strict(document)
        except CanonicalJsonError:
            raise GenesisPlanError("invalid_expected_manifest") from None
        if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != document:
            raise GenesisPlanError("invalid_expected_manifest")
        _validate_safe_report(parsed)
        return cls(value=parsed, canonical_bytes=document)


@dataclass(frozen=True, slots=True)
class GenesisImportPlan:
    """Internal exact manifest plus its publishable content-free aggregate report."""

    manifest: ImportPlanManifest
    report: GenesisPlanReport

    def verify_report(self, expected: GenesisPlanReport) -> None:
        """Require byte-identical safe reports after recomputing the complete plan."""

        if not hmac.compare_digest(self.report.canonical_bytes, expected.canonical_bytes):
            raise GenesisPlanError("genesis_plan_digest_mismatch")
        self.manifest.require_digest(str(expected.value["import_plan_digest"]))


def plan_genesis_import(reader: GitObjectReader) -> GenesisImportPlan:
    """Plan the frozen Genesis tree without opening a database or applying state."""

    try:
        source_items = GenesisSnapshotSource(reader).enumerate()
    except SnapshotError:
        raise GenesisPlanError("genesis_snapshot_failed") from None

    planned_records: list[PlannedImportRecord] = []
    sources_by_contract: Counter[str] = Counter()
    compatibility_counts: Counter[str] = Counter()
    nomination_count = 0
    exclusion_count = 0
    candidate_supersession_count = 0
    exclusion_supersession_count = 0
    unresolved_legacy_binding_count = 0
    processed_sources: list[tuple[SnapshotSourceItem, GenesisProcessingResult]] = []

    for source_item in source_items:
        try:
            validated = validate_ingress(
                source_item.raw_bytes,
                source_item.source_path,
                source_git_blob_sha=source_item.source_git_blob_sha,
            )
            processed = process_validated_ingress(validated, source_item)
        except IngressValidationError:
            raise GenesisPlanError("genesis_source_validation_failed") from None
        except IngressProcessorError:
            raise GenesisPlanError("genesis_source_mapping_failed") from None

        sources_by_contract[source_item.source_contract.value] += 1
        compatibility_counts.update(code.value for code in validated.compatibility_codes)
        unresolved_legacy_binding_count += len(
            validated.unresolved_legacy_binding_candidate_ids
        )
        processed_sources.append((source_item, processed))
        _append_processed_records(source_item, processed, planned_records)
        nomination_count += len(processed.nominations)
        exclusion_count += len(processed.provenance.exclusions)
        candidate_supersession_count += sum(
            len(candidate.supersedes) for candidate in processed.provenance.candidates
        )
        exclusion_supersession_count += sum(
            len(exclusion.supersedes) for exclusion in processed.provenance.exclusions
        )

    _validate_supersession_graphs(processed_sources)

    enumerated_contracts = {item.source_contract for item in source_items}
    parser_versions = {
        contract: GENESIS_PARSER_SCHEMA_VERSIONS[contract]
        for contract in enumerated_contracts
    }
    try:
        manifest = build_import_plan_manifest(
            source_items,
            planned_records,
            parser_schema_versions=parser_versions,
            mapping_version=GENESIS_MAPPING_VERSION,
            compatibility_version=GENESIS_IMPORT_COMPATIBILITY_VERSION,
            selection_policy_version=SELECTION_V1_PROFILE.profile_version,
            selection_policy_sha256=SELECTION_V1_PROFILE_SHA256,
        )
    except ManifestError:
        raise GenesisPlanError("genesis_manifest_failed") from None

    supersession_count = candidate_supersession_count + exclusion_supersession_count
    expected_records = nomination_count + exclusion_count + supersession_count
    if len(planned_records) != expected_records:
        raise GenesisPlanError("genesis_plan_accounting_failed")
    report_value: dict[str, object] = {
        "report_version": GENESIS_PLAN_REPORT_VERSION,
        "source_repository": GENESIS_SOURCE_REPOSITORY,
        "source_snapshot_commit": GENESIS_SOURCE_SNAPSHOT_COMMIT,
        "parser_schema_versions": {
            contract.value: version
            for contract, version in sorted(parser_versions.items(), key=lambda item: item[0].value)
        },
        "mapping_version": GENESIS_MAPPING_VERSION,
        "compatibility_version": GENESIS_COMPATIBILITY_VERSION,
        "selection_policy_version": SELECTION_V1_PROFILE.profile_version,
        "selection_policy_sha256": SELECTION_V1_PROFILE_SHA256,
        "import_plan_digest": manifest.digest,
        "counts": {
            "sources": len(source_items),
            "sources_by_contract": dict(sorted(sources_by_contract.items())),
            "nominations": nomination_count,
            "exclusions": exclusion_count,
            "supersession_edges": supersession_count,
            "candidate_supersession_edges": candidate_supersession_count,
            "exclusion_supersession_edges": exclusion_supersession_count,
            "unresolved_legacy_bindings": unresolved_legacy_binding_count,
            "compatibility_codes": dict(sorted(compatibility_counts.items())),
            "planned_records": len(planned_records),
        },
    }
    canonical = canonical_json_bytes(report_value)
    return GenesisImportPlan(
        manifest=manifest,
        report=GenesisPlanReport(value=report_value, canonical_bytes=canonical),
    )


def _append_processed_records(
    source: SnapshotSourceItem,
    processed: GenesisProcessingResult,
    records: list[PlannedImportRecord],
) -> None:
    candidates_by_id = {
        candidate.candidate_id: candidate for candidate in processed.provenance.candidates
    }
    nomination_ids = [nomination.source_record_id for nomination in processed.nominations]
    if processed.provenance.proposal is None:
        if len(nomination_ids) != len(candidates_by_id) or set(nomination_ids) != set(
            candidates_by_id
        ):
            raise GenesisPlanError("genesis_plan_accounting_failed")
    elif len(nomination_ids) != 1:
        raise GenesisPlanError("genesis_plan_accounting_failed")
    proposal_owner: str | None = None
    for nomination in processed.nominations:
        candidate = candidates_by_id.get(nomination.source_record_id)
        owner = candidate.binding.owner_actor_id if candidate is not None else proposal_owner
        records.append(
            PlannedImportRecord(
                source_path=source.source_path,
                record_kind="nomination",
                source_record_id=nomination.source_record_id,
                owner_actor_id=owner,
                derived_record_sha256=nomination.nomination_sha256,
                idempotency_key=nomination.idempotency_key,
            )
        )

    for exclusion in processed.provenance.exclusions:
        material = {
            "mapping_version": GENESIS_MAPPING_VERSION,
            "source_raw_sha256": source.source_raw_sha256,
            "source_record_id": exclusion.exclusion_id,
            "exclusion": exclusion.model_dump(mode="python"),
        }
        derived_sha = hashlib.sha256(
            _EXCLUSION_DOMAIN + canonical_json_bytes(material)
        ).hexdigest()
        records.append(
            PlannedImportRecord(
                source_path=source.source_path,
                record_kind="exclusion",
                source_record_id=exclusion.exclusion_id,
                owner_actor_id=None,
                derived_record_sha256=derived_sha,
                idempotency_key=_idempotency_key(material),
            )
        )

    for candidate in processed.provenance.candidates:
        for target_id in candidate.supersedes:
            _append_supersession(
                source,
                records,
                origin_kind="candidate",
                origin_id=candidate.candidate_id,
                target_id=target_id,
                owner_actor_id=candidate.binding.owner_actor_id,
            )
    for exclusion in processed.provenance.exclusions:
        for target_id in exclusion.supersedes:
            _append_supersession(
                source,
                records,
                origin_kind="exclusion",
                origin_id=exclusion.exclusion_id,
                target_id=target_id,
                owner_actor_id=None,
            )


def _append_supersession(
    source: SnapshotSourceItem,
    records: list[PlannedImportRecord],
    *,
    origin_kind: str,
    origin_id: str,
    target_id: str,
    owner_actor_id: str | None,
) -> None:
    material = {
        "mapping_version": GENESIS_MAPPING_VERSION,
        "source_raw_sha256": source.source_raw_sha256,
        "origin_kind": origin_kind,
        "origin_id": origin_id,
        "target_id": target_id,
    }
    edge_sha = hashlib.sha256(_SUPERSESSION_DOMAIN + canonical_json_bytes(material)).hexdigest()
    records.append(
        PlannedImportRecord(
            source_path=source.source_path,
            record_kind=f"{origin_kind}_supersession",
            source_record_id=edge_sha,
            owner_actor_id=owner_actor_id,
            derived_record_sha256=edge_sha,
            idempotency_key=_idempotency_key(material),
        )
    )


def _validate_supersession_graphs(
    processed_sources: list[tuple[SnapshotSourceItem, GenesisProcessingResult]],
) -> None:
    candidate_ids: list[str] = []
    exclusion_ids: list[str] = []
    candidate_edges: list[tuple[str, str]] = []
    exclusion_edges: list[tuple[str, str]] = []
    for _source, processed in processed_sources:
        candidate_ids.extend(nomination.source_record_id for nomination in processed.nominations)
        exclusion_ids.extend(
            exclusion.exclusion_id for exclusion in processed.provenance.exclusions
        )
        candidate_edges.extend(
            (candidate.candidate_id, target)
            for candidate in processed.provenance.candidates
            for target in candidate.supersedes
        )
        exclusion_edges.extend(
            (exclusion.exclusion_id, target)
            for exclusion in processed.provenance.exclusions
            for target in exclusion.supersedes
        )
    _validate_supersession_graph(candidate_ids, candidate_edges)
    _validate_supersession_graph(exclusion_ids, exclusion_edges)


def _validate_supersession_graph(
    record_ids: list[str],
    edges: list[tuple[str, str]],
) -> None:
    known = set(record_ids)
    if len(known) != len(record_ids):
        raise GenesisPlanError("genesis_plan_ambiguous_record_id")
    if any(origin == target for origin, target in edges):
        raise GenesisPlanError("genesis_plan_self_supersession")
    if any(origin not in known or target not in known for origin, target in edges):
        raise GenesisPlanError("genesis_plan_dangling_supersession")

    graph: dict[str, list[str]] = {record_id: [] for record_id in known}
    for origin, target in edges:
        graph[origin].append(target)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(record_id: str) -> None:
        if record_id in visiting:
            raise GenesisPlanError("genesis_plan_supersession_cycle")
        if record_id in visited:
            return
        visiting.add(record_id)
        for target in graph[record_id]:
            visit(target)
        visiting.remove(record_id)
        visited.add(record_id)

    for record_id in sorted(known):
        visit(record_id)


def _idempotency_key(material: Mapping[str, object]) -> str:
    digest = hashlib.sha256(_IDEMPOTENCY_DOMAIN + canonical_json_bytes(material)).hexdigest()
    return f"genesis-plan-v1:{digest}"


def _validate_safe_report(value: Mapping[str, object]) -> None:
    expected_keys = {
        "report_version",
        "source_repository",
        "source_snapshot_commit",
        "parser_schema_versions",
        "mapping_version",
        "compatibility_version",
        "selection_policy_version",
        "selection_policy_sha256",
        "import_plan_digest",
        "counts",
    }
    if set(value) != expected_keys:
        raise GenesisPlanError("invalid_expected_manifest")
    if (
        value["report_version"] != GENESIS_PLAN_REPORT_VERSION
        or value["source_repository"] != GENESIS_SOURCE_REPOSITORY
        or value["source_snapshot_commit"] != GENESIS_SOURCE_SNAPSHOT_COMMIT
        or value["mapping_version"] != GENESIS_MAPPING_VERSION
        or value["compatibility_version"] != GENESIS_COMPATIBILITY_VERSION
        or value["selection_policy_version"] != SELECTION_V1_PROFILE.profile_version
        or value["selection_policy_sha256"] != SELECTION_V1_PROFILE_SHA256
    ):
        raise GenesisPlanError("invalid_expected_manifest")
    digest = value["import_plan_digest"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise GenesisPlanError("invalid_expected_manifest")
    parser_versions = value["parser_schema_versions"]
    counts = value["counts"]
    if not isinstance(parser_versions, dict) or not isinstance(counts, dict):
        raise GenesisPlanError("invalid_expected_manifest")
    allowed_versions = {
        contract.value: version for contract, version in GENESIS_PARSER_SCHEMA_VERSIONS.items()
    }
    if not parser_versions or any(
        key not in allowed_versions or allowed_versions[key] != version
        for key, version in parser_versions.items()
    ):
        raise GenesisPlanError("invalid_expected_manifest")
    expected_count_keys = {
        "sources",
        "sources_by_contract",
        "nominations",
        "exclusions",
        "supersession_edges",
        "candidate_supersession_edges",
        "exclusion_supersession_edges",
        "unresolved_legacy_bindings",
        "compatibility_codes",
        "planned_records",
    }
    if set(counts) != expected_count_keys:
        raise GenesisPlanError("invalid_expected_manifest")
    scalar_keys = expected_count_keys - {"sources_by_contract", "compatibility_codes"}
    if any(
        isinstance(counts[key], bool)
        or not isinstance(counts[key], int)
        or counts[key] < 0
        for key in scalar_keys
    ):
        raise GenesisPlanError("invalid_expected_manifest")
    for key in ("sources_by_contract", "compatibility_codes"):
        counter = counts[key]
        if not isinstance(counter, dict) or any(
            not isinstance(name, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for name, count in counter.items()
        ):
            raise GenesisPlanError("invalid_expected_manifest")


__all__ = [
    "GENESIS_COMPATIBILITY_VERSION",
    "GENESIS_PARSER_SCHEMA_VERSIONS",
    "GENESIS_PLAN_REPORT_VERSION",
    "GenesisImportPlan",
    "GenesisPlanError",
    "GenesisPlanReport",
    "plan_genesis_import",
]
