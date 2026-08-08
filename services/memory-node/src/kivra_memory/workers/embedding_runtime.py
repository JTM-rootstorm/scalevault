"""Deterministic, offline embedding runtime for pinned local ONNX bundles."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from kivra_memory.domain.canonical_json import canonical_json_bytes

EMBEDDING_DIMENSION: Final = 384
MAX_INPUT_TOKENS: Final = 256
MODEL_NAME: Final = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION: Final = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
_BUNDLE_VERSION: Final = "scalevault-embedding-bundle-v1"
_EMBEDDING_CONTRACT: Final = "memory-statement-embedding-v1"
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS = frozenset(
    {
        "contract_version",
        "embedding_contract",
        "model_name",
        "upstream_revision",
        "license",
        "dimension",
        "max_input_tokens",
        "pooling",
        "normalization",
        "distance_metric",
        "tokenizer",
        "runtime",
        "export",
        "files",
    }
)


class EmbeddingRuntimeError(RuntimeError):
    """A safe local-runtime failure that contains no input text."""


@dataclass(frozen=True, slots=True)
class EmbeddingModelContract:
    artifact_sha256: str
    model_name: str
    upstream_revision: str
    dimension: int = EMBEDDING_DIMENSION
    max_input_tokens: int = MAX_INPUT_TOKENS
    pooling: str = "attention_mask_mean"
    normalization: str = "l2"


@dataclass(frozen=True, slots=True)
class EmbeddingOutput:
    vector: tuple[float, ...]
    truncated: bool


@runtime_checkable
class EmbeddingRuntime(Protocol):
    """Injected embedding seam shared by queue and query-boundary handlers."""

    @property
    def contract(self) -> EmbeddingModelContract: ...

    def embed_batch(self, texts: Sequence[str]) -> tuple[EmbeddingOutput, ...]: ...


def embedding_source_sha256(statement: str) -> bytes:
    """Hash statement-only embedding input with an explicit domain separator."""

    encoded = statement.encode("utf-8")
    digest = hashlib.sha256()
    digest.update(b"scalevault.memory.statement.embedding.v1\x00")
    digest.update(encoded)
    return digest.digest()


def _safe_bundle_member(root: Path, relative_name: object, field_name: str) -> Path:
    if (
        not isinstance(relative_name, str)
        or not relative_name
        or Path(relative_name).name != relative_name
    ):
        raise EmbeddingRuntimeError(f"invalid_{field_name}")
    candidate = root / relative_name
    if not candidate.is_file() or candidate.is_symlink():
        raise EmbeddingRuntimeError(f"invalid_{field_name}")
    return candidate


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise EmbeddingRuntimeError(f"invalid_{field_name}")
    return value


def load_embedding_bundle_manifest(
    bundle_directory: Path,
) -> tuple[EmbeddingModelContract, Path, Path, dict[str, object]]:
    """Validate one immutable bundle manifest and every referenced artifact hash."""

    root = bundle_directory.resolve(strict=True)
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise EmbeddingRuntimeError("invalid_manifest")
    try:
        raw = manifest_path.read_bytes()
        if len(raw) > 16 * 1024:
            raise EmbeddingRuntimeError("invalid_manifest")
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise EmbeddingRuntimeError("invalid_manifest") from None
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise EmbeddingRuntimeError("invalid_manifest")
    if raw != canonical_json_bytes(manifest):
        raise EmbeddingRuntimeError("noncanonical_manifest")
    if (
        manifest["contract_version"] != _BUNDLE_VERSION
        or manifest["embedding_contract"] != _EMBEDDING_CONTRACT
        or manifest["model_name"] != MODEL_NAME
        or manifest["upstream_revision"] != MODEL_REVISION
        or manifest["license"] != "Apache-2.0"
        or manifest["dimension"] != EMBEDDING_DIMENSION
        or manifest["max_input_tokens"] != MAX_INPUT_TOKENS
        or manifest["pooling"] != "attention_mask_mean"
        or manifest["normalization"] != "l2"
        or manifest["distance_metric"] != "cosine"
    ):
        raise EmbeddingRuntimeError("unsupported_model_contract")
    tokenizer_contract = manifest["tokenizer"]
    runtime_contract = manifest["runtime"]
    export_contract = manifest["export"]
    if (
        not isinstance(tokenizer_contract, dict)
        or tokenizer_contract
        != {
            "cls_token_id": 101,
            "max_length": MAX_INPUT_TOKENS,
            "pad_token_id": 0,
            "sep_token_id": 102,
            "strategy": "longest_first",
        }
        or not isinstance(runtime_contract, dict)
        or set(runtime_contract) != {"name", "version", "execution_provider"}
        or runtime_contract["name"] != "onnxruntime"
        or runtime_contract["execution_provider"] != "CPUExecutionProvider"
        or not isinstance(runtime_contract["version"], str)
        or not runtime_contract["version"]
        or not isinstance(export_contract, dict)
        or set(export_contract) != {"tool", "version"}
        or not all(
            isinstance(export_contract[key], str) and export_contract[key]
            for key in export_contract
        )
    ):
        raise EmbeddingRuntimeError("unsupported_model_contract")
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != 4:
        raise EmbeddingRuntimeError("invalid_manifest")
    members: dict[str, Path] = {}
    roles: dict[str, Path] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "role", "sha256"}:
            raise EmbeddingRuntimeError("invalid_manifest")
        role = item["role"]
        if role not in {"model", "tokenizer", "config", "license"} or role in roles:
            raise EmbeddingRuntimeError("invalid_manifest")
        path = _safe_bundle_member(root, item["path"], f"{role}_file")
        digest = _require_digest(item["sha256"], f"{role}_sha256")
        if _file_sha256(path) != digest:
            raise EmbeddingRuntimeError("artifact_hash_mismatch")
        roles[role] = path
        members[path.name] = path
    actual_files = {
        path.name for path in root.iterdir() if path.is_file() and path.name != "manifest.json"
    }
    if set(members) != actual_files:
        raise EmbeddingRuntimeError("unrecorded_bundle_file")

    artifact_digest = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    return (
        EmbeddingModelContract(
            artifact_sha256=artifact_digest,
            model_name=MODEL_NAME,
            upstream_revision=MODEL_REVISION,
        ),
        roles["model"],
        roles["tokenizer"],
        runtime_contract,
    )


class OnnxEmbeddingRuntime:
    """CPU-only all-MiniLM-L6-v2 runtime with fixed pooling and normalization."""

    def __init__(self, bundle_directory: Path) -> None:
        contract, model_path, tokenizer_path, runtime_contract = load_embedding_bundle_manifest(
            bundle_directory
        )
        try:
            numpy = importlib.import_module("numpy")
            onnxruntime = importlib.import_module("onnxruntime")
            tokenizers = importlib.import_module("tokenizers")
        except ImportError:
            raise EmbeddingRuntimeError("embedding_runtime_dependency_unavailable") from None

        if onnxruntime.__version__ != runtime_contract["version"]:
            raise EmbeddingRuntimeError("embedding_runtime_version_mismatch")
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.execution_mode = onnxruntime.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = onnxruntime.GraphOptimizationLevel.ORT_ENABLE_ALL
        try:
            session = onnxruntime.InferenceSession(
                str(model_path),
                sess_options=options,
                providers=["CPUExecutionProvider"],
            )
            if session.get_providers() != ["CPUExecutionProvider"]:
                raise EmbeddingRuntimeError("unsupported_execution_provider")
            tokenizer = tokenizers.Tokenizer.from_file(str(tokenizer_path))
        except EmbeddingRuntimeError:
            raise
        except Exception:
            raise EmbeddingRuntimeError("embedding_runtime_initialization_failed") from None
        tokenizer.enable_truncation(max_length=MAX_INPUT_TOKENS, strategy="longest_first")
        tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
        self._contract = contract
        self._numpy: Any = numpy
        self._session: Any = session
        self._tokenizer: Any = tokenizer

    @property
    def contract(self) -> EmbeddingModelContract:
        return self._contract

    def embed_batch(self, texts: Sequence[str]) -> tuple[EmbeddingOutput, ...]:
        if not texts or len(texts) > 64 or any(not text or len(text) > 8192 for text in texts):
            raise EmbeddingRuntimeError("invalid_embedding_batch")
        try:
            encodings = self._tokenizer.encode_batch(list(texts))
            input_ids = self._numpy.asarray([item.ids for item in encodings], dtype="int64")
            attention_mask = self._numpy.asarray(
                [item.attention_mask for item in encodings], dtype="int64"
            )
            token_type_ids = self._numpy.asarray(
                [item.type_ids for item in encodings], dtype="int64"
            )
            for encoding in encodings:
                attended = [
                    token_id
                    for token_id, included in zip(
                        encoding.ids, encoding.attention_mask, strict=True
                    )
                    if included
                ]
                if not attended or attended[0] != 101 or attended[-1] != 102:
                    raise EmbeddingRuntimeError("tokenizer_special_token_mismatch")
            expected_inputs = {item.name for item in self._session.get_inputs()}
            values: dict[str, Any] = {
                "input_ids": input_ids,
                "attention_mask": attention_mask,
            }
            if "token_type_ids" in expected_inputs:
                values["token_type_ids"] = token_type_ids
            if set(values) != expected_inputs:
                raise EmbeddingRuntimeError("unsupported_model_inputs")
            token_embeddings = self._session.run(None, values)[0]
            if token_embeddings.ndim != 3 or token_embeddings.shape[2] != EMBEDDING_DIMENSION:
                raise EmbeddingRuntimeError("invalid_model_output")
            mask = attention_mask.astype("float32")[:, :, None]
            counts = mask.sum(axis=1)
            if self._numpy.any(counts <= 0):
                raise EmbeddingRuntimeError("invalid_model_output")
            pooled = (token_embeddings.astype("float32") * mask).sum(axis=1) / counts
            norms = self._numpy.linalg.norm(pooled, axis=1, keepdims=True)
            if self._numpy.any(~self._numpy.isfinite(pooled)) or self._numpy.any(norms <= 0):
                raise EmbeddingRuntimeError("invalid_model_output")
            normalized = pooled / norms
            vectors = tuple(
                tuple(float(value) for value in row.tolist())
                for row in normalized.astype("float32")
            )
        except EmbeddingRuntimeError:
            raise
        except Exception:
            raise EmbeddingRuntimeError("embedding_inference_failed") from None
        validated = validate_embeddings(vectors, expected_count=len(texts))
        return tuple(
            EmbeddingOutput(vector=vector, truncated=bool(encoding.overflowing))
            for vector, encoding in zip(validated, encodings, strict=True)
        )


def validate_embeddings(
    embeddings: Iterable[Sequence[float]], *, expected_count: int
) -> tuple[tuple[float, ...], ...]:
    """Validate bounded, finite, unit-normalized 384-dimensional outputs."""

    result = tuple(tuple(row) for row in embeddings)
    if len(result) != expected_count:
        raise EmbeddingRuntimeError("invalid_embedding_count")
    for row in result:
        if len(row) != EMBEDDING_DIMENSION or any(not math.isfinite(value) for value in row):
            raise EmbeddingRuntimeError("invalid_embedding_vector")
        norm = math.sqrt(sum(value * value for value in row))
        if not 0.999 <= norm <= 1.001:
            raise EmbeddingRuntimeError("invalid_embedding_norm")
    return result
