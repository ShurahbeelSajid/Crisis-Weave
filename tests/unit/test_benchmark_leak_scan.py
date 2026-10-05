from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_benchmark_leaks import BenchmarkLeakError, scan_paths


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_scanner_accepts_public_registry_and_encrypted_commitment(tmp_path: Path) -> None:
    public = _write(
        tmp_path / "public.json",
        {
            "annotation_status": "pending_human_adjudication",
            "cases": [
                {
                    "split": "test",
                    "required_gold_fields": ["expected_routes", "claims"],
                }
            ],
        },
    )
    encrypted = _write(
        tmp_path / "encrypted-test-gold.json",
        {"ciphertext": "opaque", "sealed_case_count": 14},
    )

    scan_paths(tmp_path, [public, encrypted])


@pytest.mark.parametrize(
    "payload",
    [
        {
            "annotation_status": "frozen",
            "cases": [{"split": "test", "expected_routes": ["vector"]}],
        },
        {"annotator_token": "anon:opaque", "cases": []},
        {
            "exposure_class": "private_custodian",
            "commitment_nonce": "nonce:secret",
            "source_lock_sha256": "sha256:secret",
        },
    ],
)
def test_scanner_rejects_renamed_custodian_json(tmp_path: Path, payload: object) -> None:
    disguised = _write(tmp_path / "ordinary-name.json", payload)

    with pytest.raises(BenchmarkLeakError):
        scan_paths(tmp_path, [disguised])


def test_scanner_rejects_forbidden_paths_and_private_keys(tmp_path: Path) -> None:
    forbidden = _write(tmp_path / "nested" / "blind-review.json", {})
    with pytest.raises(BenchmarkLeakError, match="custodian-only path"):
        scan_paths(tmp_path, [forbidden])

    key = tmp_path / "renamed.pem"
    key.write_text("-----BEGIN " + "PRIVATE KEY-----\nopaque\n", encoding="utf-8")
    with pytest.raises(BenchmarkLeakError, match="private key"):
        scan_paths(tmp_path, [key])
