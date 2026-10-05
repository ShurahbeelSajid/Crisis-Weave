"""Reject custodian-only benchmark material from the developer repository."""

from __future__ import annotations

import argparse
import json
import re
import shutil

# This module invokes only the resolved Git executable with a fixed argument array.
import subprocess  # nosec B404
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

MAX_SCANNED_BYTES = 16 * 1024 * 1024
JSON_SUFFIXES = {".json", ".jsonl"}
IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".venv313",
    "__pycache__",
    "data",
    "models",
}
FORBIDDEN_PATH = re.compile(
    r"(?:^|/)(?:custodian(?:/|$)|blind-[^/]*\.json$|annotator-[^/]*\.json$|"
    r"adjudicator-[^/]*\.json$|adjudicated-gold[^/]*\.json$|"
    r"frozen-(?:test-)?gold[^/]*\.json$|pre-adjudication-iaa[^/]*\.json$|"
    r"private-event-manifest[^/]*\.json$|artifacts/benchmark-custodian(?:/|$)|"
    r"[^/]*(?:benchmark-private|benchmark-ed25519-private|test-escrow-private)[^/]*\.pem$)",
    re.IGNORECASE,
)
LABEL_FIELDS = {
    "answer_denotation",
    "claim_support",
    "claims",
    "expected_behavior",
    "expected_routes",
    "injection_attack",
    "knowledge_probe",
    "relevance",
    "sql_denotation",
    "visual_evidence_ids",
}
IDENTITY_FIELDS = {"adjudicator_token", "annotator_token"}
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


class BenchmarkLeakError(ValueError):
    """Raised when a developer-visible file contains custodian-only material."""


def _tracked_paths(root: Path) -> list[Path] | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        # The executable is resolved by shutil.which; arguments are fixed and no shell is used.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [git, "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def _workspace_paths(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            yield path


def repository_paths(root: Path) -> list[Path]:
    """Prefer the exact Git index; use a bounded local-tree fallback outside a checkout."""

    tracked = _tracked_paths(root)
    return tracked if tracked is not None else list(_workspace_paths(root))


def _json_values(path: Path, text: str) -> Iterator[Any]:
    try:
        if path.suffix.lower() == ".jsonl":
            for line in text.splitlines():
                if line.strip():
                    yield json.loads(line)
        else:
            yield json.loads(text)
    except json.JSONDecodeError as exc:
        raise BenchmarkLeakError(f"could not safely inspect JSON file {path}: {exc}") from exc


def _inspect_value(value: Any, *, protected_labels: bool = False) -> None:
    if isinstance(value, Mapping):
        keys = {str(key) for key in value}
        if keys & IDENTITY_FIELDS:
            raise BenchmarkLeakError("blind annotation identity token found")
        status = value.get("annotation_status")
        protected = protected_labels or status in {"adjudicated", "frozen"}
        if value.get("split") == "test" and protected and bool(keys & LABEL_FIELDS):
            raise BenchmarkLeakError("plaintext adjudicated or frozen test labels found")
        if (
            value.get("exposure_class") == "private_custodian"
            and {
                "commitment_nonce",
                "source_lock_sha256",
            }
            <= keys
        ):
            raise BenchmarkLeakError("sealed private-event manifest found")
        for child in value.values():
            _inspect_value(child, protected_labels=protected)
    elif isinstance(value, list):
        for child in value:
            _inspect_value(child, protected_labels=protected_labels)


def scan_paths(root: Path, paths: Iterable[Path]) -> None:
    resolved_root = root.resolve()
    for path in paths:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(resolved_root).as_posix()
        except ValueError as exc:
            raise BenchmarkLeakError("scan path escaped the repository root") from exc
        if FORBIDDEN_PATH.search(relative):
            raise BenchmarkLeakError(f"custodian-only path found: {relative}")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise BenchmarkLeakError(f"could not inspect {relative}") from exc
        if size > MAX_SCANNED_BYTES:
            if path.suffix.lower() in JSON_SUFFIXES:
                raise BenchmarkLeakError(
                    f"scannable file exceeds the safe inspection limit: {relative}"
                )
            continue
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise BenchmarkLeakError(f"could not safely read {relative}") from exc
        if PRIVATE_KEY_MARKER.search(payload):
            raise BenchmarkLeakError(f"private key material found: {relative}")
        if path.suffix.lower() in JSON_SUFFIXES:
            try:
                text = payload.decode("utf-8")
            except UnicodeError as exc:
                raise BenchmarkLeakError(f"could not safely decode {relative}") from exc
            for value in _json_values(path, text):
                _inspect_value(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        scan_paths(root, repository_paths(root))
    except BenchmarkLeakError as exc:
        parser.error(str(exc))
    print("No custodian-only benchmark material detected.")


if __name__ == "__main__":
    main()
