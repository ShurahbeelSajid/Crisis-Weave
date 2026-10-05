"""Create and verify a content-bound offline model-bundle manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

ROLES = ("reranker", "text", "visual", "whisper")
REVISION = re.compile(r"[a-f0-9]{40}")
MODEL_ID = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?)?"
)
SHA256 = re.compile(r"[a-f0-9]{64}")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 100_000
BUFFER_SIZE = 1024 * 1024

ModelRecord = dict[str, str]
FileRecord = dict[str, str | int]


class BundleError(ValueError):
    """Raised when a model bundle is incomplete, unsafe, or does not match its manifest."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(BUFFER_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_model_records(value: object) -> dict[str, ModelRecord]:
    if not isinstance(value, dict) or set(value) != set(ROLES):
        raise BundleError("manifest models must define exactly reranker, text, visual, and whisper")
    records: dict[str, ModelRecord] = {}
    for role in ROLES:
        record = value.get(role)
        if not isinstance(record, dict) or set(record) != {"model", "path", "revision"}:
            raise BundleError(f"manifest model record is invalid: {role}")
        model = record.get("model")
        revision = record.get("revision")
        path = record.get("path")
        if (
            not isinstance(model, str)
            or not MODEL_ID.fullmatch(model)
            or ".." in model
            or "--" in model
        ):
            raise BundleError(f"manifest model ID is invalid: {role}")
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            raise BundleError(f"manifest revision is not an immutable commit: {role}")
        if path != role:
            raise BundleError(f"manifest model path must equal its role: {role}")
        records[role] = {"model": model, "path": role, "revision": revision}
    return records


def collect_file_records(root: Path) -> list[FileRecord]:
    """Hash regular files below the four role directories and reject unexpected entries."""
    if root.is_symlink() or not root.is_dir():
        raise BundleError("model bundle root must be a real directory")
    allowed_root_entries = {*ROLES, "bundle.json"}
    unexpected = sorted(
        item.name for item in root.iterdir() if item.name not in allowed_root_entries
    )
    if unexpected:
        raise BundleError(f"unexpected model bundle root entry: {unexpected[0]}")

    records: list[FileRecord] = []
    for role in ROLES:
        role_root = root / role
        if role_root.is_symlink() or not role_root.is_dir():
            raise BundleError(f"model bundle role directory is unavailable: {role}")
        role_count = 0
        for candidate in sorted(role_root.rglob("*"), key=lambda item: item.as_posix()):
            if candidate.is_symlink():
                raise BundleError(f"model bundle contains a symbolic link: {candidate.name}")
            if candidate.is_dir():
                continue
            if not candidate.is_file():
                raise BundleError(f"model bundle contains a non-regular entry: {candidate.name}")
            relative = candidate.relative_to(root).as_posix()
            if len(relative) > 1024 or any(ord(character) < 32 for character in relative):
                raise BundleError("model bundle contains an unsafe file path")
            records.append(
                {
                    "path": relative,
                    "sha256": sha256_file(candidate),
                    "size": candidate.stat().st_size,
                }
            )
            role_count += 1
            if len(records) > MAX_FILES:
                raise BundleError("model bundle contains too many files")
        if role_count == 0:
            raise BundleError(f"model bundle role directory is empty: {role}")
    return records


def _validate_file_records(value: object) -> list[FileRecord]:
    if not isinstance(value, list) or not value or len(value) > MAX_FILES:
        raise BundleError("manifest files must be a bounded non-empty list")
    records: list[FileRecord] = []
    seen: set[str] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            raise BundleError("manifest contains an invalid file record")
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("size")
        if not isinstance(path, str) or len(path) > 1024 or "\\" in path:
            raise BundleError("manifest contains an invalid file path")
        pure_path = PurePosixPath(path)
        if (
            pure_path.is_absolute()
            or path != pure_path.as_posix()
            or ".." in pure_path.parts
            or not pure_path.parts
            or pure_path.parts[0] not in ROLES
            or any(ord(character) < 32 for character in path)
            or path in seen
        ):
            raise BundleError("manifest contains an unsafe or duplicate file path")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise BundleError(f"manifest contains an invalid file digest: {path}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise BundleError(f"manifest contains an invalid file size: {path}")
        seen.add(path)
        records.append({"path": path, "sha256": digest, "size": size})
    if records != sorted(records, key=lambda item: str(item["path"])):
        raise BundleError("manifest file records must be sorted")
    return records


def _content_digest(models: Mapping[str, ModelRecord], files: Sequence[FileRecord]) -> str:
    content = {"files": files, "models": models, "schema": 2}
    encoded = json.dumps(content, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def write_manifest(root: Path, models: Mapping[str, ModelRecord]) -> Path:
    """Write an atomic schema-v2 manifest for an already materialized bundle."""
    validated_models = _validate_model_records(dict(models))
    files = collect_file_records(root)
    payload: dict[str, Any] = {
        "schema": 2,
        "models": validated_models,
        "files": files,
        "content_sha256": _content_digest(validated_models, files),
    }
    manifest = root / "bundle.json"
    temporary = root / ".bundle.json.tmp"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(manifest)
    return manifest


def verify_manifest(manifest: Path) -> dict[str, int | str]:
    """Verify structure, paths, sizes, and SHA-256 hashes for an offline bundle."""
    if manifest.is_symlink() or not manifest.is_file():
        raise BundleError("model bundle manifest must be a regular file")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise BundleError("model bundle manifest is too large")
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError("model bundle manifest is unreadable") from exc
    if not isinstance(value, dict) or set(value) != {
        "content_sha256",
        "files",
        "models",
        "schema",
    }:
        raise BundleError("model bundle manifest has an unsupported structure")
    if value.get("schema") != 2:
        raise BundleError("model bundle manifest schema must be 2")
    models = _validate_model_records(value.get("models"))
    files = _validate_file_records(value.get("files"))
    content_digest = value.get("content_sha256")
    if not isinstance(content_digest, str) or not SHA256.fullmatch(content_digest):
        raise BundleError("model bundle content digest is invalid")
    if content_digest != _content_digest(models, files):
        raise BundleError("model bundle manifest content digest does not match")
    actual_files = collect_file_records(manifest.parent)
    if actual_files != files:
        raise BundleError("model bundle files do not match the manifest")
    return {
        "content_sha256": content_digest,
        "file_count": len(files),
        "total_bytes": sum(int(record["size"]) for record in files),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--exec", dest="command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        summary = verify_manifest(args.manifest)
    except BundleError as exc:
        parser.error(str(exc))
    if args.command is not None and not args.command:
        parser.error("--exec requires a command")
    if args.command:
        # The deployment entrypoint supplies an argv array; no shell or string expansion is used.
        os.execvp(args.command[0], args.command)  # nosec B606  # noqa: S606
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
