"""Fetch the demo manifest with bounded HTTPS downloads and provenance hashes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import ssl
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_HOSTS = ("nasa.gov", "noaa.gov")
MAX_ASSET_BYTES = 100 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024


def allowed_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    return parsed.scheme == "https" and any(
        host == domain or host.endswith(f".{domain}") for domain in ALLOWED_HOSTS
    )


def download(
    url: str, destination: Path, *, expected_sha256: str | None = None
) -> tuple[str, int, dict[str, str | None]]:
    if not allowed_url(url):
        raise ValueError(f"URL is outside the official-domain allowlist: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "CrisisWeaveDataset/1.0"})
    digest = hashlib.sha256()
    size = 0
    actual_sha256 = ""
    context = ssl.create_default_context()
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4()}.part")
    metadata: dict[str, str | None] = {}
    try:
        with (
            # The manifest validator permits reviewed HTTPS sources only.
            urllib.request.urlopen(  # nosec B310
                request, timeout=45, context=context
            ) as response,
            temporary.open("xb") as output,
        ):
            if not allowed_url(response.url):
                raise ValueError("Download redirected outside the official-domain allowlist")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_ASSET_BYTES:
                raise ValueError(f"Asset exceeds {MAX_ASSET_BYTES} bytes")
            metadata = {
                "final_url": response.url,
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "content_type": response.headers.get("Content-Type"),
            }
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > MAX_ASSET_BYTES:
                    raise ValueError(f"Asset exceeds {MAX_ASSET_BYTES} bytes")
                digest.update(block)
                output.write(block)
        actual_sha256 = digest.hexdigest()
        if expected_sha256 and actual_sha256 != expected_sha256:
            raise ValueError(
                f"Upstream bytes changed for {destination.name}; review before refresh"
            )
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return actual_sha256, size, metadata


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("datasets/crisisweave-wildfire/manifest.json"),
    )
    parser.add_argument("--output", type=Path, default=Path("data/demo"))
    parser.add_argument(
        "--refresh-lock",
        action="store_true",
        help="accept reviewed upstream changes and replace the provenance lock",
    )
    args = parser.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    args.output.mkdir(parents=True, exist_ok=True)
    lock_path = args.output / "provenance.lock.json"
    verify_lock = lock_path.is_file() and not args.refresh_lock
    expected: dict[str, dict[str, object]] = {}
    if verify_lock:
        locked = json.loads(lock_path.read_text(encoding="utf-8"))
        if locked.get("dataset") != manifest.get("dataset") or locked.get(
            "version"
        ) != manifest.get("version"):
            raise ValueError("Existing provenance lock does not match the manifest identity")
        expected = {str(item["id"]): item for item in locked.get("assets", [])}
        if not expected:
            raise ValueError("Existing provenance lock has no assets")
    provenance = {
        "dataset": manifest["dataset"],
        "version": manifest["version"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "retrieved_at": datetime.now(UTC).isoformat(),
        "assets": [],
    }
    seen_ids: set[str] = set()
    seen_filenames: set[str] = set()
    for asset in manifest["assets"]:
        asset_id = str(asset["id"])
        raw_filename = str(asset["filename"])
        filename = Path(raw_filename).name
        if (
            not asset_id
            or asset_id in seen_ids
            or not filename
            or filename != raw_filename
            or filename in seen_filenames
        ):
            raise ValueError("Manifest asset IDs and leaf filenames must be unique and safe")
        seen_ids.add(asset_id)
        seen_filenames.add(filename)
        expected_record = expected.get(asset_id)
        if verify_lock and expected_record is None:
            raise ValueError(f"Asset {asset_id} is absent from the existing provenance lock")
        if expected_record and expected_record.get("url") != asset["url"]:
            raise ValueError(f"Asset URL changed for {asset_id}; review before refresh")
        destination = args.output / filename
        sha256, size, response_metadata = download(
            asset["url"],
            destination,
            expected_sha256=str(expected_record["sha256"]) if expected_record else None,
        )
        record = {
            **asset,
            **response_metadata,
            "sha256": sha256,
            "size_bytes": size,
        }
        if destination.suffix == ".gz" and asset.get("decompressed_filename"):
            raw_decompressed = str(asset["decompressed_filename"])
            decompressed_name = Path(raw_decompressed).name
            if not decompressed_name or decompressed_name != raw_decompressed:
                raise ValueError("Decompressed filename must be a safe leaf name")
            decompressed = args.output / decompressed_name
            temporary = decompressed.with_name(f".{decompressed.name}.{uuid.uuid4()}.part")
            try:
                with gzip.open(destination, "rb") as source, temporary.open("xb") as output:
                    decompressed_size = 0
                    while block := source.read(1024 * 1024):
                        decompressed_size += len(block)
                        if decompressed_size > MAX_DECOMPRESSED_BYTES:
                            raise ValueError("Decompressed asset exceeds the safety limit")
                        output.write(block)
                decompressed_sha256 = file_sha256(temporary)
                expected_decompressed = (
                    str(expected_record["decompressed_sha256"])
                    if expected_record and expected_record.get("decompressed_sha256")
                    else None
                )
                if expected_decompressed and decompressed_sha256 != expected_decompressed:
                    raise ValueError("Decompressed upstream bytes changed; review before refresh")
                temporary.replace(decompressed)
            finally:
                temporary.unlink(missing_ok=True)
            record["decompressed_sha256"] = decompressed_sha256
            record["decompressed_size_bytes"] = decompressed_size
        provenance["assets"].append(record)
        print(f"downloaded {destination.name} ({size:,} bytes)")
    if verify_lock and set(expected) != seen_ids:
        raise ValueError("Existing provenance lock contains assets absent from the manifest")
    if not verify_lock:
        temporary_lock = lock_path.with_name(f".{lock_path.name}.{uuid.uuid4()}.part")
        try:
            temporary_lock.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
            temporary_lock.replace(lock_path)
        finally:
            temporary_lock.unlink(missing_ok=True)
        print(f"wrote trust-on-first-use provenance lock {lock_path}")
    else:
        print(f"verified every asset against {lock_path}")


if __name__ == "__main__":
    main()
