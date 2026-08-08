"""Create a canonical, digest-addressed embedding bundle from local files only."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    MAX_INPUT_TOKENS,
    MODEL_NAME,
    MODEL_REVISION,
)

_MAXIMUM_FILE_BYTES = {
    "model": 1024 * 1024 * 1024,
    "tokenizer": 32 * 1024 * 1024,
    "config": 4 * 1024 * 1024,
    "license": 1024 * 1024,
}
_DESTINATION_NAMES = {
    "model": "model.onnx",
    "tokenizer": "tokenizer.json",
    "config": "config.json",
    "license": "LICENSE",
}


class BundlePreparationError(RuntimeError):
    """Safe failure while preparing a local embedding bundle."""


@dataclass(frozen=True, slots=True)
class BundleSources:
    model: Path
    tokenizer: Path
    config: Path
    license: Path


def _validated_source(path: Path, role: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise BundlePreparationError(f"invalid_{role}_source")
    size = path.stat().st_size
    if not 1 <= size <= _MAXIMUM_FILE_BYTES[role]:
        raise BundlePreparationError(f"invalid_{role}_size")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_embedding_bundle(
    *,
    model_root: Path,
    sources: BundleSources,
    onnxruntime_version: str,
    export_tool: str,
    export_version: str,
) -> Path:
    """Atomically create one immutable bundle and return its digest-addressed path."""

    if (
        not model_root.is_absolute()
        or model_root.is_symlink()
        or not model_root.is_dir()
        or any(
            not value or len(value) > 128
            for value in (onnxruntime_version, export_tool, export_version)
        )
    ):
        raise BundlePreparationError("invalid_bundle_configuration")
    source_values = {
        role: _validated_source(getattr(sources, role), role) for role in _DESTINATION_NAMES
    }
    resolved_sources = {path.resolve(strict=True) for path in source_values.values()}
    if len(resolved_sources) != len(source_values):
        raise BundlePreparationError("bundle_sources_must_be_distinct")

    entries = [
        {
            "path": _DESTINATION_NAMES[role],
            "role": role,
            "sha256": _sha256(path),
        }
        for role, path in source_values.items()
    ]
    manifest: dict[str, object] = {
        "contract_version": "scalevault-embedding-bundle-v1",
        "embedding_contract": "memory-statement-embedding-v1",
        "model_name": MODEL_NAME,
        "upstream_revision": MODEL_REVISION,
        "license": "Apache-2.0",
        "dimension": EMBEDDING_DIMENSION,
        "max_input_tokens": MAX_INPUT_TOKENS,
        "pooling": "attention_mask_mean",
        "normalization": "l2",
        "distance_metric": "cosine",
        "tokenizer": {
            "cls_token_id": 101,
            "max_length": MAX_INPUT_TOKENS,
            "pad_token_id": 0,
            "sep_token_id": 102,
            "strategy": "longest_first",
        },
        "runtime": {
            "name": "onnxruntime",
            "version": onnxruntime_version,
            "execution_provider": "CPUExecutionProvider",
        },
        "export": {"tool": export_tool, "version": export_version},
        "files": sorted(entries, key=lambda item: str(item["path"])),
    }
    manifest_bytes = canonical_json_bytes(manifest)
    artifact_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    destination = model_root / artifact_sha256
    if destination.exists() or destination.is_symlink():
        raise BundlePreparationError("bundle_already_exists")

    staging = Path(tempfile.mkdtemp(prefix=".embedding-bundle-", dir=model_root))
    try:
        model_group = model_root.stat().st_gid
        if staging.stat().st_gid != model_group:
            os.chown(staging, -1, model_group)
        staging.chmod(0o2750)
        for role, source in source_values.items():
            target = staging / _DESTINATION_NAMES[role]
            with source.open("rb") as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
            if _sha256(target) != next(
                str(item["sha256"]) for item in entries if item["role"] == role
            ):
                raise BundlePreparationError("copied_artifact_hash_mismatch")
            target.chmod(0o440)
        manifest_path = staging / "manifest.json"
        with manifest_path.open("xb") as manifest_file:
            manifest_file.write(manifest_bytes)
            manifest_file.flush()
            os.fsync(manifest_file.fileno())
        manifest_path.chmod(0o440)
        staging.chmod(0o2550)
        staging.rename(destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a pinned ScaleVault embedding bundle from already-local files."
    )
    parser.add_argument("--model-root", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--tokenizer", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--license", dest="license_file", type=Path, required=True)
    parser.add_argument("--onnxruntime-version", required=True)
    parser.add_argument("--export-tool", required=True)
    parser.add_argument("--export-version", required=True)
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    destination = prepare_embedding_bundle(
        model_root=arguments.model_root,
        sources=BundleSources(
            model=arguments.model,
            tokenizer=arguments.tokenizer,
            config=arguments.config,
            license=arguments.license_file,
        ),
        onnxruntime_version=arguments.onnxruntime_version,
        export_tool=arguments.export_tool,
        export_version=arguments.export_version,
    )
    print(destination.name)


if __name__ == "__main__":
    main()
