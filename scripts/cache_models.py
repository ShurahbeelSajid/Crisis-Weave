"""Create an offline model bundle from immutable Hugging Face revisions."""

from __future__ import annotations

import argparse
import importlib
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import cast


def _load_bundle_helpers() -> ModuleType:
    try:
        return importlib.import_module("scripts.verify_model_bundle")
    except ModuleNotFoundError:
        return importlib.import_module("verify_model_bundle")


ModelRecord = dict[str, str]
WriteManifest = Callable[[Path, Mapping[str, ModelRecord]], Path]
_bundle_helpers = _load_bundle_helpers()
MODEL_ID = cast(re.Pattern[str], _bundle_helpers.MODEL_ID)
write_manifest = cast(WriteManifest, _bundle_helpers.write_manifest)


REVISION = re.compile(r"[a-f0-9]{40}")


def immutable_revision(value: str) -> str:
    if not REVISION.fullmatch(value):
        raise argparse.ArgumentTypeError("revision must be a 40-character lowercase commit hash")
    return value


def model_id(value: str) -> str:
    if not MODEL_ID.fullmatch(value) or ".." in value or "--" in value:
        raise argparse.ArgumentTypeError("model must be a canonical Hugging Face repository ID")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--text-model", required=True, type=model_id)
    parser.add_argument("--text-revision", required=True, type=immutable_revision)
    parser.add_argument("--visual-model", required=True, type=model_id)
    parser.add_argument("--visual-revision", required=True, type=immutable_revision)
    parser.add_argument("--reranker-model", required=True, type=model_id)
    parser.add_argument("--reranker-revision", required=True, type=immutable_revision)
    parser.add_argument("--whisper-model", required=True, type=model_id)
    parser.add_argument("--whisper-revision", required=True, type=immutable_revision)
    parser.add_argument("--output", type=Path, default=Path("/models"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.output.is_symlink() or any(args.output.iterdir()):
        parser.error("output must be a real empty directory")

    with tempfile.TemporaryDirectory(
        prefix="crisisweave-model-cache-", ignore_cleanup_errors=True
    ) as temporary_cache:
        cache = Path(temporary_cache)
        os.environ["HF_HOME"] = str(cache / "huggingface")
        os.environ["HF_HUB_CACHE"] = str(cache / "huggingface" / "hub")
        os.environ["SENTENCE_TRANSFORMERS_HOME"] = str(cache / "sentence-transformers")
        from huggingface_hub import snapshot_download
        from sentence_transformers import CrossEncoder, SentenceTransformer

        SentenceTransformer(
            args.text_model,
            revision=args.text_revision,
            trust_remote_code=False,
            cache_folder=str(cache / "sentence-transformers"),
        ).save_pretrained(str(args.output / "text"))
        SentenceTransformer(
            args.visual_model,
            revision=args.visual_revision,
            trust_remote_code=False,
            cache_folder=str(cache / "sentence-transformers"),
        ).save_pretrained(str(args.output / "visual"))
        CrossEncoder(
            args.reranker_model,
            revision=args.reranker_revision,
            trust_remote_code=False,
            cache_folder=str(cache / "sentence-transformers"),
        ).save_pretrained(str(args.output / "reranker"))
        snapshot_download(
            repo_id=args.whisper_model,
            revision=args.whisper_revision,
            local_dir=args.output / "whisper",
        )

    # Hugging Face documents this local-dir metadata cache as safe to remove after download.
    shutil.rmtree(args.output / "whisper" / ".cache", ignore_errors=True)
    models = {
        "text": {"model": args.text_model, "path": "text", "revision": args.text_revision},
        "visual": {
            "model": args.visual_model,
            "path": "visual",
            "revision": args.visual_revision,
        },
        "reranker": {
            "model": args.reranker_model,
            "path": "reranker",
            "revision": args.reranker_revision,
        },
        "whisper": {
            "model": args.whisper_model,
            "path": "whisper",
            "revision": args.whisper_revision,
        },
    }
    write_manifest(args.output, models)


if __name__ == "__main__":
    main()
