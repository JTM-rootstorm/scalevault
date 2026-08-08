from __future__ import annotations

import sys
from pathlib import Path
from stat import S_IMODE

import pytest
from kivra_memory.workers.embedding_runtime import load_embedding_bundle_manifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.prepare_embedding_bundle import (  # noqa: E402
    BundlePreparationError,
    BundleSources,
    prepare_embedding_bundle,
)


def _sources(root: Path) -> BundleSources:
    root.mkdir()
    values = {
        "model": root / "source.onnx",
        "tokenizer": root / "source-tokenizer.json",
        "config": root / "source-config.json",
        "license": root / "source-license.txt",
    }
    for name, path in values.items():
        path.write_bytes(f"synthetic-{name}".encode())
    return BundleSources(**values)


def test_prepare_bundle_is_canonical_complete_and_refuses_overwrite(tmp_path: Path) -> None:
    model_root = tmp_path / "models"
    model_root.mkdir()
    destination = prepare_embedding_bundle(
        model_root=model_root,
        sources=_sources(tmp_path / "sources"),
        onnxruntime_version="1.28.0",
        export_tool="optimum-cli",
        export_version="2.0.0",
    )

    assert destination.parent == model_root
    assert destination.stat().st_gid == model_root.stat().st_gid
    assert S_IMODE(destination.stat().st_mode) == 0o2550
    assert {path.name for path in destination.iterdir()} == {
        "LICENSE",
        "config.json",
        "manifest.json",
        "model.onnx",
        "tokenizer.json",
    }
    assert all(
        path.stat().st_gid == model_root.stat().st_gid and S_IMODE(path.stat().st_mode) == 0o440
        for path in destination.iterdir()
    )
    contract, _model, _tokenizer, runtime = load_embedding_bundle_manifest(destination)
    assert destination.name == contract.artifact_sha256
    assert runtime["version"] == "1.28.0"

    with pytest.raises(BundlePreparationError, match="bundle_already_exists"):
        prepare_embedding_bundle(
            model_root=model_root,
            sources=_sources(tmp_path / "second-sources"),
            onnxruntime_version="1.28.0",
            export_tool="optimum-cli",
            export_version="2.0.0",
        )


def test_prepare_bundle_rejects_symlinked_source(tmp_path: Path) -> None:
    model_root = tmp_path / "models"
    model_root.mkdir()
    sources = _sources(tmp_path / "sources")
    linked = tmp_path / "linked-model.onnx"
    linked.symlink_to(sources.model)

    with pytest.raises(BundlePreparationError, match="invalid_model_source"):
        prepare_embedding_bundle(
            model_root=model_root,
            sources=BundleSources(
                model=linked,
                tokenizer=sources.tokenizer,
                config=sources.config,
                license=sources.license,
            ),
            onnxruntime_version="1.28.0",
            export_tool="optimum-cli",
            export_version="2.0.0",
        )
