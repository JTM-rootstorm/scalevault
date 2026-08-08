from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    MODEL_NAME,
    MODEL_REVISION,
    EmbeddingRuntimeError,
    embedding_source_sha256,
    load_embedding_bundle_manifest,
    validate_embeddings,
)


def _write_bundle(root: Path) -> dict[str, object]:
    root.mkdir()
    files = {
        "model": ("model.onnx", b"synthetic-model"),
        "tokenizer": ("tokenizer.json", b"synthetic-tokenizer"),
        "config": ("config.json", b"synthetic-config"),
        "license": ("LICENSE", b"synthetic-license"),
    }
    entries = []
    for role, (name, content) in files.items():
        (root / name).write_bytes(content)
        entries.append({"path": name, "role": role, "sha256": hashlib.sha256(content).hexdigest()})
    manifest: dict[str, object] = {
        "contract_version": "scalevault-embedding-bundle-v1",
        "embedding_contract": "memory-statement-embedding-v1",
        "model_name": MODEL_NAME,
        "upstream_revision": MODEL_REVISION,
        "license": "Apache-2.0",
        "dimension": EMBEDDING_DIMENSION,
        "max_input_tokens": 256,
        "pooling": "attention_mask_mean",
        "normalization": "l2",
        "distance_metric": "cosine",
        "tokenizer": {
            "cls_token_id": 101,
            "max_length": 256,
            "pad_token_id": 0,
            "sep_token_id": 102,
            "strategy": "longest_first",
        },
        "runtime": {
            "name": "onnxruntime",
            "version": "synthetic-version",
            "execution_provider": "CPUExecutionProvider",
        },
        "export": {"tool": "synthetic-exporter", "version": "1"},
        "files": sorted(entries, key=lambda item: str(item["path"])),
    }
    (root / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    return manifest


def test_bundle_manifest_pins_contract_and_every_file(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    manifest = _write_bundle(root)

    contract, model_path, tokenizer_path, runtime = load_embedding_bundle_manifest(root)

    assert contract.artifact_sha256 == hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    assert contract.upstream_revision == MODEL_REVISION
    assert model_path == root / "model.onnx"
    assert tokenizer_path == root / "tokenizer.json"
    assert runtime["execution_provider"] == "CPUExecutionProvider"

    (root / "unrecorded.bin").write_bytes(b"not accepted")
    with pytest.raises(EmbeddingRuntimeError, match="unrecorded_bundle_file"):
        load_embedding_bundle_manifest(root)


def test_bundle_manifest_rejects_hash_drift_and_noncanonical_json(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    manifest = _write_bundle(root)
    (root / "model.onnx").write_bytes(b"changed")
    with pytest.raises(EmbeddingRuntimeError, match="artifact_hash_mismatch"):
        load_embedding_bundle_manifest(root)

    (root / "model.onnx").write_bytes(b"synthetic-model")
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with pytest.raises(EmbeddingRuntimeError, match="noncanonical_manifest"):
        load_embedding_bundle_manifest(root)


def test_statement_source_hash_uses_exact_accepted_domain_separator() -> None:
    statement = "Synthetic private statement."
    expected = hashlib.sha256(
        b"scalevault.memory.statement.embedding.v1\x00" + statement.encode()
    ).digest()
    assert embedding_source_sha256(statement) == expected


def test_embedding_validation_rejects_nonfinite_dimension_and_norm() -> None:
    unit = (1.0,) + (0.0,) * (EMBEDDING_DIMENSION - 1)
    assert validate_embeddings((unit,), expected_count=1) == (unit,)
    with pytest.raises(EmbeddingRuntimeError, match="invalid_embedding_vector"):
        validate_embeddings(((float("nan"),) * EMBEDDING_DIMENSION,), expected_count=1)
    with pytest.raises(EmbeddingRuntimeError, match="invalid_embedding_norm"):
        validate_embeddings(((0.5,) + (0.0,) * (EMBEDDING_DIMENSION - 1),), expected_count=1)
