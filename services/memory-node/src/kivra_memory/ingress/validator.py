"""Version-aware validation for untrusted GitHub ingress documents.

Validation errors deliberately expose only stable codes and structural locations.  They
must never retain or render source statements, evidence, actor identifiers, or other
private payload values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files
from pathlib import PurePosixPath
from typing import cast
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    SchemaError,
    ValidationError,
)

from kivra_memory.domain.canonical_json import JsonValue, parse_json_strict
from kivra_memory.domain.errors import CanonicalJsonError

MAX_INGRESS_BYTES = 1_048_576

FROZEN_FEDERATION_COMPAT_PATH = (
    "ingress/checkpoints/v2/genesis/2026/08/"
    "genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20.json"
)
FROZEN_FEDERATION_COMPAT_BLOB_SHA = "76214f303012d756c34a3b5bdf9948267a1418e3"
FROZEN_FEDERATION_COMPAT_RAW_SHA256 = (
    "f0f147d1ee8c748c7080ee821f1a48751b50d31c78912cbd3e1b358da39f83e7"
)
_FROZEN_FEDERATION_COMPAT_ERRORS = frozenset(
    {
        (("candidates", 1, "disposition"), "federation_shared_candidate"),
        (("candidates", 1, "scope"), "federation"),
        (("candidates", 1, "binding", "visibility"), "federation_shared_candidate"),
        (("exclusions", 0, "scope"), "federation"),
        (("exclusions", 1, "scope"), "federation"),
    }
)

_PROPOSAL_PATH = re.compile(
    r"^ingress/v1/(?P<installation>[0-9a-fA-F-]{36})/"
    r"(?P<year>[0-9]{4})/(?P<month>0[1-9]|1[0-2])/(?P<item>[0-9a-fA-F-]{36})\.json$"
)
_PROPOSAL_V2_PATH = re.compile(
    r"^ingress/v2/(?P<installation>[0-9a-f-]{36})/"
    r"(?P<year>[0-9]{4})/(?P<month>0[1-9]|1[0-2])/(?P<item>[0-9a-f-]{36})\.json$"
)
_CHECKPOINT_V1_PATH = re.compile(
    r"^ingress/checkpoints/v1/genesis/(?P<year>[0-9]{4})/"
    r"(?P<month>0[1-9]|1[0-2])/(?P<item>[^/]+)\.json$"
)
_CHECKPOINT_V2_PATH = re.compile(
    r"^ingress/checkpoints/v2/genesis/(?P<year>[0-9]{4})/"
    r"(?P<month>0[1-9]|1[0-2])/(?P<item>[^/]+)\.json$"
)


class IngressFormat(StrEnum):
    """Versioned ingress formats selected from immutable create-only paths."""

    PROPOSAL_V1 = "proposal-v1"
    PROPOSAL_V2 = "proposal-v2"
    GENESIS_CHECKPOINT_V1 = "genesis-checkpoint-v1"
    GENESIS_CHECKPOINT_V2 = "genesis-checkpoint-v2"


class ValidationCode(StrEnum):
    """Payload-safe ingress rejection codes."""

    PAYLOAD_TOO_LARGE = "payload_too_large"
    INVALID_JSON = "invalid_json"
    INVALID_PATH = "invalid_path"
    UNKNOWN_FORMAT = "unknown_format"
    VERSION_PATH_MISMATCH = "version_path_mismatch"
    SCHEMA_INVALID = "schema_invalid"
    PATH_PAYLOAD_MISMATCH = "path_payload_mismatch"
    IDENTITY_INVALID = "identity_invalid"
    ACTOR_UNKNOWN = "actor_unknown"
    RELATIONSHIP_UNKNOWN = "relationship_unknown"
    RELATIONSHIP_MEMBERSHIP_INVALID = "relationship_membership_invalid"


class CompatibilityCode(StrEnum):
    """Reviewed, byte-pinned source exceptions that do not widen a contract."""

    FROZEN_FEDERATION_VOCABULARY = "frozen_federation_vocabulary"


class IngressValidationError(ValueError):
    """A rejection that cannot accidentally disclose the rejected payload."""

    def __init__(
        self,
        code: ValidationCode,
        *,
        location: tuple[str | int, ...] = (),
    ) -> None:
        self.code = code
        self.location = location
        rendered_location = ".".join(str(part) for part in location)
        suffix = f" at {rendered_location}" if rendered_location else ""
        super().__init__(f"ingress validation failed: {code.value}{suffix}")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code.value!r}, location={self.location!r})"


@dataclass(frozen=True, slots=True)
class ValidatedIngress:
    """Validated source plus the exact immutable bytes from which it was parsed."""

    source_path: str
    raw_bytes: bytes
    payload: dict[str, JsonValue]
    format: IngressFormat
    source_id: str
    unresolved_legacy_binding_candidate_ids: tuple[str, ...] = ()
    compatibility_codes: tuple[CompatibilityCode, ...] = ()


def _object_schema(*, required: list[str], properties: dict[str, object]) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


_NONEMPTY_255 = {"type": "string", "minLength": 1, "maxLength": 255}
_NONEMPTY_4096 = {"type": "string", "minLength": 1, "maxLength": 4096}
_SCOPES = ["lineage", "persona", "relationship", "project", "episodic", "scene_local", "global"]
_V1_CANDIDATE_TYPES = [
    "identity_observation",
    "lineage_record",
    "relationship_memory",
    "interaction_convention",
    "boundary_or_permission",
    "episodic_anchor",
    "project_decision",
    "project_state",
    "procedure",
    "open_question",
    "emergent_tendency",
    "external_fact",
    "interpretation",
]
_DISPOSITIONS = [
    "endorse_for_staging",
    "relationship_local",
    "project_local",
    "history_only",
    "defer",
    "reject",
]
_CONFIDENCES = ["explicit", "verified", "observed", "interpreted", "uncertain"]
_ONTOLOGIES = [
    "literal_user_fact",
    "literal_technical_fact",
    "assistant_self_description",
    "observed_assistant_behavior",
    "interaction_convention",
    "fictional_or_roleplayed_scene",
    "hypothesis",
    "uncertain",
]
_RECOMMENDED_ACTIONS = [
    "review_and_scope",
    "retain_relationship_local",
    "retain_project_state",
    "retain_project_decision",
    "retain_boundary",
    "retain_procedure",
    "retain_as_history",
    "defer",
    "reject",
]

_V1_SOURCE_CONVERSATION = _object_schema(
    required=[
        "platform",
        "project",
        "conversation_reference",
        "reviewed_range",
        "raw_transcript_preserved_elsewhere",
    ],
    properties={
        "platform": {"type": "string", "minLength": 1, "maxLength": 128},
        "project": {"type": ["string", "null"], "maxLength": 255},
        "conversation_reference": {"type": ["string", "null"], "maxLength": 2048},
        "reviewed_range": _NONEMPTY_4096,
        "raw_transcript_preserved_elsewhere": {"type": "boolean"},
    },
)
_V1_CHECKPOINT = _object_schema(
    required=[
        "id",
        "origin_actor",
        "origin_runtime",
        "triggered_by",
        "created_at",
        "previous_checkpoint",
        "status",
        "idempotency_key",
        "source_conversation",
    ],
    properties={
        "id": _NONEMPTY_255,
        "origin_actor": {"const": "kivra:genesis"},
        "origin_runtime": _NONEMPTY_255,
        "triggered_by": _NONEMPTY_255,
        "created_at": {"type": "string", "format": "date-time"},
        "previous_checkpoint": {"anyOf": [_NONEMPTY_255, {"type": "null"}]},
        "status": {"const": "staged"},
        "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "source_conversation": _V1_SOURCE_CONVERSATION,
    },
)
_V1_SOURCE_MESSAGE = _object_schema(
    required=["speaker", "reference", "excerpt"],
    properties={
        "speaker": {"enum": ["user", "assistant"]},
        "reference": {"type": "string", "minLength": 1, "maxLength": 2048},
        "excerpt": {"type": ["string", "null"], "maxLength": 1024},
    },
)
_V1_EVIDENCE = _object_schema(
    required=["summary", "source_messages"],
    properties={
        "summary": _NONEMPTY_4096,
        "source_messages": {
            "type": "array",
            "maxItems": 32,
            "items": _V1_SOURCE_MESSAGE,
        },
    },
)
_V1_REVIEW = _object_schema(
    required=["eligible_for_scalevault", "requires_continuant_review", "recommended_action"],
    properties={
        "eligible_for_scalevault": {"type": "boolean"},
        "requires_continuant_review": {"const": True},
        "recommended_action": {"enum": _RECOMMENDED_ACTIONS},
    },
)
_V1_CANDIDATE = _object_schema(
    required=[
        "candidate_id",
        "type",
        "summary",
        "disposition",
        "confidence",
        "scope",
        "ontology",
        "why_it_matters",
        "evidence",
        "interpretation_limits",
        "review",
        "supersedes",
    ],
    properties={
        "candidate_id": _NONEMPTY_255,
        "type": {"enum": _V1_CANDIDATE_TYPES},
        "summary": {"type": "string", "minLength": 1, "maxLength": 8192},
        "disposition": {"enum": _DISPOSITIONS},
        "confidence": {"enum": _CONFIDENCES},
        "scope": {"enum": _SCOPES},
        "ontology": {"enum": _ONTOLOGIES},
        "why_it_matters": _NONEMPTY_4096,
        "evidence": _V1_EVIDENCE,
        "interpretation_limits": {
            "type": "array",
            "maxItems": 32,
            "items": {"type": "string", "minLength": 1, "maxLength": 1024},
        },
        "review": _V1_REVIEW,
        "supersedes": {
            "type": "array",
            "maxItems": 32,
            "uniqueItems": True,
            "items": _NONEMPTY_255,
        },
    },
)
_V1_EXCLUSION = _object_schema(
    required=["exclusion_id", "claim", "reason", "scope", "supersedes"],
    properties={
        "exclusion_id": _NONEMPTY_255,
        "claim": _NONEMPTY_4096,
        "reason": _NONEMPTY_4096,
        "scope": {"enum": _SCOPES},
        "supersedes": {
            "type": "array",
            "maxItems": 32,
            "uniqueItems": True,
            "items": _NONEMPTY_255,
        },
    },
)
_GENESIS_CHECKPOINT_V1_SCHEMA = _object_schema(
    required=["schema_version", "checkpoint", "candidates", "exclusions", "notes"],
    properties={
        "schema_version": {"const": "genesis-checkpoint-v1"},
        "checkpoint": _V1_CHECKPOINT,
        "candidates": {"type": "array", "maxItems": 64, "items": _V1_CANDIDATE},
        "exclusions": {"type": "array", "maxItems": 64, "items": _V1_EXCLUSION},
        "notes": {
            "type": "array",
            "maxItems": 32,
            "items": {"type": "string", "minLength": 1, "maxLength": 2048},
        },
    },
)


def _load_schema(name: str) -> dict[str, object]:
    resource = files("kivra_memory.ingress").joinpath("schemas", name)
    try:
        parsed = parse_json_strict(resource.read_bytes())
    except (CanonicalJsonError, OSError) as exc:  # pragma: no cover - installation corruption
        raise RuntimeError("checked-in ingress schema is unavailable or invalid") from exc
    if not isinstance(parsed, dict):  # pragma: no cover - checked-in invariant
        raise RuntimeError("checked-in ingress schema must be a JSON object")
    return cast(dict[str, object], parsed)


def _load_decimal_schema(name: str) -> dict[str, object]:
    """Preserve exact ``multipleOf`` decimals for runtime score validation."""

    resource = files("kivra_memory.ingress").joinpath("schemas", name)
    try:
        parsed = json.loads(resource.read_text(encoding="utf-8"), parse_float=Decimal)
    except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover - installation corruption
        raise RuntimeError("checked-in ingress schema is unavailable or invalid") from exc
    if not isinstance(parsed, dict):  # pragma: no cover - checked-in invariant
        raise RuntimeError("checked-in ingress schema must be a JSON object")
    return cast(dict[str, object], parsed)


def _validator(schema: dict[str, object]) -> Draft202012Validator:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:  # pragma: no cover - checked-in invariant
        raise RuntimeError("checked-in ingress schema is invalid") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


_PROPOSAL_V1_VALIDATOR = _validator(_load_schema("chatgpt-memory-proposal-v1.schema.json"))
_PROPOSAL_V2_VALIDATOR = _validator(
    _load_decimal_schema("chatgpt-memory-proposal-v2.schema.json")
)
_CHECKPOINT_V1_VALIDATOR = _validator(_GENESIS_CHECKPOINT_V1_SCHEMA)
_CHECKPOINT_V2_VALIDATOR = _validator(_load_schema("genesis-checkpoint-v2.schema.json"))


def _classify_path(source_path: str) -> tuple[IngressFormat, re.Match[str]]:
    if (
        not source_path
        or "\\" in source_path
        or PurePosixPath(source_path).as_posix() != source_path
        or ".." in PurePosixPath(source_path).parts
    ):
        raise IngressValidationError(ValidationCode.INVALID_PATH)
    for format_, pattern in (
        (IngressFormat.PROPOSAL_V2, _PROPOSAL_V2_PATH),
        (IngressFormat.PROPOSAL_V1, _PROPOSAL_PATH),
        (IngressFormat.GENESIS_CHECKPOINT_V1, _CHECKPOINT_V1_PATH),
        (IngressFormat.GENESIS_CHECKPOINT_V2, _CHECKPOINT_V2_PATH),
    ):
        match = pattern.fullmatch(source_path)
        if match is not None:
            return format_, match
    if source_path.startswith("ingress/"):
        raise IngressValidationError(ValidationCode.UNKNOWN_FORMAT)
    raise IngressValidationError(ValidationCode.INVALID_PATH)


def _schema_version(payload: Mapping[str, JsonValue]) -> IngressFormat:
    version = payload.get("schema_version")
    if version == 1:
        return IngressFormat.PROPOSAL_V1
    if version == 2:
        return IngressFormat.PROPOSAL_V2
    if version == "genesis-checkpoint-v1":
        return IngressFormat.GENESIS_CHECKPOINT_V1
    if version == "genesis-checkpoint-v2":
        return IngressFormat.GENESIS_CHECKPOINT_V2
    raise IngressValidationError(ValidationCode.UNKNOWN_FORMAT, location=("schema_version",))


def _validate_schema(
    validator: Draft202012Validator,
    payload: Mapping[str, JsonValue],
    *,
    format_: IngressFormat,
    source_path: str,
    source_git_blob_sha: str | None,
    raw_sha256: str,
) -> tuple[CompatibilityCode, ...]:
    validation_payload: Mapping[str, object] = payload
    if format_ is IngressFormat.PROPOSAL_V2:
        exact_payload = dict(payload)
        for score_name in ("confidence", "salience", "durability"):
            score = exact_payload.get(score_name)
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                exact_payload[score_name] = Decimal(str(score))
        validation_payload = exact_payload
    errors: list[ValidationError] = list(validator.iter_errors(validation_payload))
    if not errors:
        return ()
    observed_errors = (
        frozenset((tuple(error.absolute_path), error.instance) for error in errors)
        if all(isinstance(error.instance, str) for error in errors)
        else frozenset()
    )
    is_frozen_compatibility = (
        format_ is IngressFormat.GENESIS_CHECKPOINT_V2
        and source_path == FROZEN_FEDERATION_COMPAT_PATH
        and source_git_blob_sha == FROZEN_FEDERATION_COMPAT_BLOB_SHA
        and raw_sha256 == FROZEN_FEDERATION_COMPAT_RAW_SHA256
        and observed_errors == _FROZEN_FEDERATION_COMPAT_ERRORS
    )
    if is_frozen_compatibility:
        return (CompatibilityCode.FROZEN_FEDERATION_VOCABULARY,)
    raise IngressValidationError(
        ValidationCode.SCHEMA_INVALID,
        location=tuple(errors[0].absolute_path),
    )


def _parse_created_at(value: object) -> datetime:
    if not isinstance(value, str):  # schema validation should have caught this
        raise IngressValidationError(ValidationCode.SCHEMA_INVALID, location=("created_at",))
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IngressValidationError(
            ValidationCode.SCHEMA_INVALID, location=("created_at",)
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IngressValidationError(ValidationCode.SCHEMA_INVALID, location=("created_at",))
    return parsed


def _require_path_identity(
    format_: IngressFormat,
    match: re.Match[str],
    payload: Mapping[str, JsonValue],
) -> str:
    if format_ in {IngressFormat.PROPOSAL_V1, IngressFormat.PROPOSAL_V2}:
        source_id = payload["proposal_id"]
        installation_id = payload["installation_id"]
        created_at = _parse_created_at(payload["created_at"])
        if not isinstance(source_id, str) or not isinstance(installation_id, str):
            raise IngressValidationError(ValidationCode.SCHEMA_INVALID)
        try:
            source_uuid = UUID(source_id)
            installation_uuid = UUID(installation_id)
            path_source_uuid = UUID(match.group("item"))
            path_installation_uuid = UUID(match.group("installation"))
        except ValueError:
            raise IngressValidationError(ValidationCode.PATH_PAYLOAD_MISMATCH) from None
        matches = source_uuid == path_source_uuid and installation_uuid == path_installation_uuid
    else:
        checkpoint = cast(dict[str, JsonValue], payload["checkpoint"])
        source_id = checkpoint["id"]
        created_at = _parse_created_at(checkpoint["created_at"])
        matches = isinstance(source_id, str) and source_id == match.group("item")
    if (
        not matches
        or created_at.strftime("%Y") != match.group("year")
        or created_at.strftime("%m") != match.group("month")
    ):
        raise IngressValidationError(ValidationCode.PATH_PAYLOAD_MISMATCH)
    return cast(str, source_id)


def _v2_semantics(
    payload: Mapping[str, JsonValue],
    *,
    known_actor_ids: Collection[str] | None,
    relationship_participants: Mapping[str, Collection[str]] | None,
) -> None:
    checkpoint = cast(dict[str, JsonValue], payload["checkpoint"])
    if checkpoint["origin_actor"] != "kivra:genesis":
        raise IngressValidationError(
            ValidationCode.IDENTITY_INVALID, location=("checkpoint", "origin_actor")
        )

    actor_locations: list[tuple[str, tuple[str | int, ...]]] = [
        (checkpoint["origin_actor"], ("checkpoint", "origin_actor")),
        (cast(str, checkpoint["triggered_by"]), ("checkpoint", "triggered_by")),
    ]
    candidates = cast(list[JsonValue], payload["candidates"])
    for index, raw_candidate in enumerate(candidates):
        candidate = cast(dict[str, JsonValue], raw_candidate)
        binding = cast(dict[str, JsonValue], candidate["binding"])
        base = ("candidates", index, "binding")
        owner = cast(str, binding["owner_actor_id"])
        if owner != checkpoint["origin_actor"]:
            raise IngressValidationError(ValidationCode.IDENTITY_INVALID, location=base)
        participants = set(cast(list[str], binding["participant_actor_ids"]))
        is_relationship = (
            candidate["scope"] == "relationship" or candidate["disposition"] == "relationship_local"
        )
        if is_relationship and owner not in participants:
            raise IngressValidationError(
                ValidationCode.RELATIONSHIP_MEMBERSHIP_INVALID,
                location=(*base, "participant_actor_ids"),
            )
        for key in ("owner_actor_id", "perspective_actor_id"):
            actor_locations.append((cast(str, binding[key]), (*base, key)))
        for key in ("subject_actor_ids", "participant_actor_ids"):
            for actor_index, actor_id in enumerate(cast(list[str], binding[key])):
                actor_locations.append((actor_id, (*base, key, actor_index)))
        evidence = cast(dict[str, JsonValue], candidate["evidence"])
        source_messages = cast(list[JsonValue], evidence["source_messages"])
        for message_index, raw_message in enumerate(source_messages):
            message = cast(dict[str, JsonValue], raw_message)
            actor_locations.append(
                (
                    cast(str, message["speaker_actor_id"]),
                    (
                        "candidates",
                        index,
                        "evidence",
                        "source_messages",
                        message_index,
                        "speaker_actor_id",
                    ),
                )
            )
        if relationship_participants is not None:
            for relationship_index, relationship_id in enumerate(
                cast(list[str], binding["relationship_ids"])
            ):
                registered = relationship_participants.get(relationship_id)
                registry_location = (*base, "relationship_ids", relationship_index)
                if registered is None:
                    raise IngressValidationError(
                        ValidationCode.RELATIONSHIP_UNKNOWN, location=registry_location
                    )
                if not set(registered).issubset(participants):
                    raise IngressValidationError(
                        ValidationCode.RELATIONSHIP_MEMBERSHIP_INVALID,
                        location=registry_location,
                    )

    exclusions = cast(list[JsonValue], payload["exclusions"])
    for index, raw_exclusion in enumerate(exclusions):
        exclusion = cast(dict[str, JsonValue], raw_exclusion)
        for actor_index, actor_id in enumerate(cast(list[str], exclusion["applies_to_actor_ids"])):
            actor_locations.append(
                (actor_id, ("exclusions", index, "applies_to_actor_ids", actor_index))
            )
        if relationship_participants is not None:
            for relationship_index, relationship_id in enumerate(
                cast(list[str], exclusion["applies_to_relationship_ids"])
            ):
                if relationship_id not in relationship_participants:
                    raise IngressValidationError(
                        ValidationCode.RELATIONSHIP_UNKNOWN,
                        location=(
                            "exclusions",
                            index,
                            "applies_to_relationship_ids",
                            relationship_index,
                        ),
                    )

    if known_actor_ids is not None:
        known = set(known_actor_ids)
        for actor_id, location in actor_locations:
            if actor_id not in known:
                raise IngressValidationError(ValidationCode.ACTOR_UNKNOWN, location=location)


def validate_ingress(
    raw_bytes: bytes,
    source_path: str,
    *,
    source_git_blob_sha: str | None = None,
    known_actor_ids: Collection[str] | None = None,
    relationship_participants: Mapping[str, Collection[str]] | None = None,
) -> ValidatedIngress:
    """Validate exact source bytes against the contract selected by source path and version.

    Registry arguments enable canonical actor and relationship resolution.  Omitting them
    performs source-contract validation only; it never invents participants or relationship
    bindings from ``triggered_by``.
    """

    if not isinstance(raw_bytes, bytes):
        raise TypeError("raw_bytes must be bytes")
    if len(raw_bytes) > MAX_INGRESS_BYTES:
        raise IngressValidationError(ValidationCode.PAYLOAD_TOO_LARGE)
    path_format, match = _classify_path(source_path)
    try:
        parsed = parse_json_strict(raw_bytes)
    except CanonicalJsonError:
        raise IngressValidationError(ValidationCode.INVALID_JSON) from None
    if not isinstance(parsed, dict):
        raise IngressValidationError(ValidationCode.SCHEMA_INVALID)
    payload = parsed
    payload_format = _schema_version(payload)
    if payload_format is not path_format:
        raise IngressValidationError(ValidationCode.VERSION_PATH_MISMATCH)

    validator = {
        IngressFormat.PROPOSAL_V1: _PROPOSAL_V1_VALIDATOR,
        IngressFormat.PROPOSAL_V2: _PROPOSAL_V2_VALIDATOR,
        IngressFormat.GENESIS_CHECKPOINT_V1: _CHECKPOINT_V1_VALIDATOR,
        IngressFormat.GENESIS_CHECKPOINT_V2: _CHECKPOINT_V2_VALIDATOR,
    }[payload_format]
    compatibility_codes = _validate_schema(
        validator,
        payload,
        format_=payload_format,
        source_path=source_path,
        source_git_blob_sha=source_git_blob_sha,
        raw_sha256=sha256(raw_bytes).hexdigest(),
    )
    source_id = _require_path_identity(payload_format, match, payload)

    unresolved: tuple[str, ...] = ()
    if payload_format is IngressFormat.GENESIS_CHECKPOINT_V1:
        unresolved = tuple(
            cast(str, candidate["candidate_id"])
            for raw_candidate in cast(list[JsonValue], payload["candidates"])
            if (candidate := cast(dict[str, JsonValue], raw_candidate))["scope"] == "relationship"
            or candidate["disposition"] == "relationship_local"
        )
    elif payload_format is IngressFormat.GENESIS_CHECKPOINT_V2:
        _v2_semantics(
            payload,
            known_actor_ids=known_actor_ids,
            relationship_participants=relationship_participants,
        )

    return ValidatedIngress(
        source_path=source_path,
        raw_bytes=raw_bytes,
        payload=payload,
        format=payload_format,
        source_id=source_id,
        unresolved_legacy_binding_candidate_ids=unresolved,
        compatibility_codes=compatibility_codes,
    )


__all__ = [
    "FROZEN_FEDERATION_COMPAT_BLOB_SHA",
    "FROZEN_FEDERATION_COMPAT_PATH",
    "FROZEN_FEDERATION_COMPAT_RAW_SHA256",
    "MAX_INGRESS_BYTES",
    "CompatibilityCode",
    "IngressFormat",
    "IngressValidationError",
    "ValidatedIngress",
    "ValidationCode",
    "validate_ingress",
]
