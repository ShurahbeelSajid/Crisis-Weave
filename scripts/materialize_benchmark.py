"""Materialize official benchmark sources into ingestible, provenance-locked files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import mimetypes
import ssl
import urllib.request
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

try:
    from scripts.benchmark_metrics import BenchmarkError, load_json_object, validate_event_manifest
except ModuleNotFoundError as exc:  # Direct `python scripts/materialize_benchmark.py` execution.
    if exc.name not in {"scripts", "scripts.benchmark_metrics"}:
        raise
    from benchmark_metrics import (  # type: ignore[no-redef]
        BenchmarkError,
        load_json_object,
        validate_event_manifest,
    )

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "datasets" / "crisisweave-disasters-v1" / "manifest.json"
ALLOWED_HOSTS = {"www.nhc.noaa.gov", "earthquake.usgs.gov"}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = 64 * 1024 * 1024
PRODUCT_TYPES = ("poster", "shakemap", "losspager", "dyfi")
NHC_HURDAT2_URL = "https://www.nhc.noaa.gov/data/hurdat/hurdat2-1851-2025-02272026.txt"
JsonObject = dict[str, Any]


def allowed_url(url: str) -> bool:
    """Allow only the two authoritative HTTPS hosts used by this benchmark."""

    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in ALLOWED_HOSTS
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject a redirect before urllib makes a request to its destination."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        resolved = urljoin(request.full_url, new_url)
        if not allowed_url(resolved):
            raise BenchmarkError("source redirect is outside the official host allowlist")
        return super().redirect_request(request, response, code, message, headers, resolved)


def _fetch(url: str, *, limit: int) -> tuple[bytes, JsonObject]:
    if not allowed_url(url):
        raise BenchmarkError(f"source URL is outside the official allowlist: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "CrisisWeaveBenchmark/1.0"})
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _AllowlistRedirectHandler()
    )
    # The request and every redirect are constrained to the reviewed HTTPS allowlist.
    with opener.open(request, timeout=45) as response:  # nosec B310
        if not allowed_url(response.url):
            raise BenchmarkError("source redirected outside the official host allowlist")
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > limit:
            raise BenchmarkError(f"source exceeds the {limit}-byte safety limit")
        output = bytearray()
        while block := response.read(min(1024 * 1024, limit + 1)):
            output.extend(block)
            if len(output) > limit:
                raise BenchmarkError(f"source exceeds the {limit}-byte safety limit")
        return bytes(output), {
            "final_url": response.url,
            "content_type": response.headers.get("Content-Type"),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
        }


def _fetch_json(url: str) -> tuple[JsonObject, JsonObject]:
    payload, metadata = _fetch(url, limit=MAX_JSON_BYTES)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"official JSON source returned invalid JSON: {url}") from exc
    if not isinstance(value, dict):
        raise BenchmarkError(f"official JSON source returned a non-object: {url}")
    return value, metadata


def _single_usgs_feature(payload: Mapping[str, Any], event_identifier: str) -> JsonObject:
    if payload.get("type") == "Feature" and isinstance(payload.get("properties"), dict):
        feature = dict(payload)
    else:
        features = payload.get("features")
        if (
            not isinstance(features, list)
            or len(features) != 1
            or not isinstance(features[0], dict)
        ):
            raise BenchmarkError(f"USGS query for {event_identifier} did not return one event")
        feature = dict(features[0])
    feature_id = str(feature.get("id", ""))
    properties = feature.get("properties")
    if not isinstance(properties, dict):
        raise BenchmarkError(f"USGS event {event_identifier} has no properties object")
    official_ids = str(properties.get("ids", ""))
    if event_identifier.casefold() not in {
        feature_id.casefold(),
        *official_ids.casefold().split(","),
    }:
        raise BenchmarkError(f"USGS response identity does not match {event_identifier}")
    return feature


def _usgs_csv(feature: Mapping[str, Any], canonical_event_id: str, country_code: str = "") -> bytes:
    properties = feature.get("properties")
    geometry = feature.get("geometry")
    if not isinstance(properties, dict) or not isinstance(geometry, dict):
        raise BenchmarkError("USGS feature is missing properties or geometry")
    coordinates = geometry.get("coordinates")
    if not isinstance(coordinates, list) or len(coordinates) < 3:
        raise BenchmarkError("USGS feature has invalid coordinates")
    event_time = properties.get("time")
    begin_year: int | str = ""
    if isinstance(event_time, (int, float)) and not isinstance(event_time, bool):
        begin_year = datetime.fromtimestamp(event_time / 1000, tz=UTC).year
    fields = (
        "EVENT_ID",
        "YEAR",
        "STATE",
        "EVENT_TYPE",
        "CZ_NAME",
        "MAGNITUDE",
        "EPISODE_NARRATIVE",
        "benchmark_event_id",
        "magnitude_type",
        "time_epoch_ms",
        "updated_epoch_ms",
        "longitude",
        "latitude",
        "depth_km",
        "felt_reports",
        "community_intensity",
        "estimated_intensity",
        "alert",
        "significance",
        "tsunami_flag",
        "status",
        "network",
        "code",
        "detail_url",
    )
    row = {
        "EVENT_ID": feature.get("id"),
        "YEAR": begin_year,
        "STATE": country_code,
        "EVENT_TYPE": properties.get("type"),
        "CZ_NAME": properties.get("title"),
        "MAGNITUDE": properties.get("mag"),
        "EPISODE_NARRATIVE": (
            "Official USGS ComCat event metadata; impact estimates and modeled products "
            "must be cited separately."
        ),
        "benchmark_event_id": canonical_event_id,
        "magnitude_type": properties.get("magType"),
        "time_epoch_ms": properties.get("time"),
        "updated_epoch_ms": properties.get("updated"),
        "longitude": coordinates[0],
        "latitude": coordinates[1],
        "depth_km": coordinates[2],
        "felt_reports": properties.get("felt"),
        "community_intensity": properties.get("cdi"),
        "estimated_intensity": properties.get("mmi"),
        "alert": properties.get("alert"),
        "significance": properties.get("sig"),
        "tsunami_flag": properties.get("tsunami"),
        "status": properties.get("status"),
        "network": properties.get("net"),
        "code": properties.get("code"),
        "detail_url": properties.get("detail"),
    }
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
    return stream.getvalue().encode("utf-8")


def _hurdat2_csv(payload: bytes, official_id: str, canonical_name: str) -> bytes:
    """Filter one storm from HURDAT2 and map its numeric wind field into guarded analytics."""

    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8-sig"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise BenchmarkError("NHC HURDAT2 source is not valid UTF-8 CSV text") from exc
    observations: list[list[str]] | None = None
    for index, row in enumerate(rows):
        if not row or row[0].strip().upper() != official_id.upper():
            continue
        try:
            count = int(row[2].strip())
        except (IndexError, ValueError) as exc:
            raise BenchmarkError(f"HURDAT2 header for {official_id} is malformed") from exc
        observations = rows[index + 1 : index + 1 + count]
        if len(observations) != count:
            raise BenchmarkError(f"HURDAT2 observations for {official_id} are truncated")
        break
    if not observations:
        raise BenchmarkError(f"HURDAT2 does not contain {official_id}")

    fields = (
        "EVENT_ID",
        "YEAR",
        "STATE",
        "EVENT_TYPE",
        "CZ_NAME",
        "MAGNITUDE",
        "EPISODE_NARRATIVE",
        "OBSERVATION_DATE",
        "OBSERVATION_TIME_UTC",
        "RECORD_IDENTIFIER",
        "LATITUDE",
        "LONGITUDE",
        "MAX_WIND_KT",
        "MIN_PRESSURE_MB",
    )
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for observation in observations:
        if len(observation) < 8 or len(observation[0].strip()) != 8:
            raise BenchmarkError(f"HURDAT2 observation for {official_id} is malformed")
        date_text = observation[0].strip()
        maximum_wind = observation[6].strip()
        writer.writerow(
            {
                "EVENT_ID": official_id,
                "YEAR": date_text[:4],
                "STATE": "",
                "EVENT_TYPE": observation[3].strip(),
                "CZ_NAME": canonical_name,
                # The current guarded schema exposes one generic numeric magnitude column.
                # Preserve the explicit MAX_WIND_KT field and require unit-aware gold labels.
                "MAGNITUDE": maximum_wind,
                "EPISODE_NARRATIVE": (
                    "Official NHC HURDAT2 best-track observation; MAGNITUDE and "
                    "MAX_WIND_KT are maximum sustained wind in knots."
                ),
                "OBSERVATION_DATE": date_text,
                "OBSERVATION_TIME_UTC": observation[1].strip(),
                "RECORD_IDENTIFIER": observation[2].strip(),
                "LATITUDE": observation[4].strip(),
                "LONGITUDE": observation[5].strip(),
                "MAX_WIND_KT": maximum_wind,
                "MIN_PRESSURE_MB": observation[7].strip(),
            }
        )
    return stream.getvalue().encode("utf-8")


def _product_assets(detail: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Choose at most one deterministic PDF/image from each useful USGS product type."""

    properties = detail.get("properties")
    products = properties.get("products") if isinstance(properties, dict) else None
    if not isinstance(products, dict):
        return []
    selected: list[tuple[str, str, str]] = []
    for product_type in PRODUCT_TYPES:
        candidates = products.get(product_type)
        if not isinstance(candidates, list):
            continue
        ranked_products = sorted(
            (candidate for candidate in candidates if isinstance(candidate, dict)),
            key=lambda item: (
                int(item.get("preferredWeight", 0) or 0),
                int(item.get("updateTime", 0) or 0),
            ),
            reverse=True,
        )
        for product in ranked_products:
            contents = product.get("contents")
            if not isinstance(contents, dict):
                continue
            usable: list[tuple[int, str, str, str]] = []
            for logical_name, content in contents.items():
                if not isinstance(content, dict):
                    continue
                url = content.get("url")
                media_type = str(content.get("contentType", "")).split(";", 1)[0].lower()
                if not isinstance(url, str) or not allowed_url(url):
                    continue
                rank = {
                    "application/pdf": 0,
                    "image/png": 1,
                    "image/jpeg": 2,
                }.get(media_type)
                if rank is not None:
                    usable.append((rank, str(logical_name), url, media_type))
            if usable:
                _, logical_name, url, media_type = sorted(usable)[0]
                selected.append((product_type, url, media_type))
                break
    return selected


def _extension(media_type: str, url: str) -> str:
    explicit = {
        "application/pdf": ".pdf",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "text/csv": ".csv",
    }.get(media_type.split(";", 1)[0].lower())
    if explicit:
        return explicit
    guessed = mimetypes.guess_extension(media_type) or Path(urlparse(url).path).suffix.lower()
    if guessed not in {".pdf", ".jpg", ".jpeg", ".png", ".csv"}:
        raise BenchmarkError(f"unsupported materialized media type: {media_type}")
    return ".jpg" if guessed == ".jpeg" else guessed


def _record_bytes(
    *,
    output_root: Path,
    relative_path: Path,
    content: bytes,
    event_id: str,
    source_id: str,
    kind: str,
    source_url: str,
    metadata: Mapping[str, Any],
    expected: Mapping[tuple[str, str], Mapping[str, Any]],
    refresh_lock: bool,
) -> JsonObject:
    digest = hashlib.sha256(content).hexdigest()
    key = (event_id, relative_path.as_posix())
    prior = expected.get(key)
    if (
        prior
        and not refresh_lock
        and (prior.get("source_url") != source_url or prior.get("sha256") != digest)
    ):
        raise BenchmarkError(
            f"locked source changed for {relative_path}; review before --refresh-lock"
        )
    destination = (output_root / relative_path).resolve()
    if not destination.is_relative_to(output_root.resolve()):
        raise BenchmarkError("materialized path escaped the output directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.part")
    try:
        temporary.write_bytes(content)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "event_id": event_id,
        "source_id": source_id,
        "kind": kind,
        "source_url": source_url,
        **metadata,
        "path": relative_path.as_posix(),
        "sha256": digest,
        "size_bytes": len(content),
    }


def _selected_events(
    manifest: Mapping[str, Any], event_ids: set[str], splits: set[str]
) -> list[JsonObject]:
    events = [event for event in manifest["events"] if isinstance(event, dict)]
    known_ids = {str(event["event_id"]) for event in events}
    unknown = sorted(event_ids - known_ids)
    if unknown:
        raise BenchmarkError(f"unknown event IDs: {unknown}")
    selected = [
        event
        for event in events
        if (not event_ids or event["event_id"] in event_ids)
        and (not splits or event["split"] in splits)
    ]
    if not selected:
        raise BenchmarkError("selection contains no events")
    return selected


def _load_existing_lock(
    path: Path, manifest: Mapping[str, Any], *, refresh: bool
) -> tuple[JsonObject | None, dict[tuple[str, str], JsonObject]]:
    if refresh or not path.is_file():
        return None, {}
    lock = load_json_object(path)
    if lock.get("benchmark_id") != manifest.get("benchmark_id") or lock.get(
        "version"
    ) != manifest.get("version"):
        raise BenchmarkError("existing provenance lock belongs to another benchmark version")
    records = lock.get("files")
    if not isinstance(records, list):
        raise BenchmarkError("existing provenance lock has an invalid files list")
    expected: dict[tuple[str, str], JsonObject] = {}
    for record in records:
        if not isinstance(record, dict):
            raise BenchmarkError("existing provenance lock has a non-object record")
        key = (str(record.get("event_id")), str(record.get("path")))
        if key in expected:
            raise BenchmarkError("existing provenance lock has duplicate paths")
        expected[key] = record
    return lock, expected


def materialize(
    manifest: Mapping[str, Any],
    selected: Iterable[Mapping[str, Any]],
    output_root: Path,
    *,
    refresh_lock: bool,
) -> JsonObject:
    """Fetch selected official products and return the merged provenance lock."""

    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    lock_path = output_root / "provenance.lock.json"
    old_lock, expected = _load_existing_lock(lock_path, manifest, refresh=refresh_lock)
    merged = dict(expected)
    materialized_events: list[str] = []
    hurdat2_content: bytes | None = None
    hurdat2_metadata: JsonObject = {}
    for event in selected:
        event_id = str(event["event_id"])
        source = event["sources"][0]
        source_id = str(source["source_id"])
        authority = str(event["official_identifier"]["authority"])
        official_id = str(event["official_identifier"]["value"])
        if authority == "NOAA NHC":
            content, metadata = _fetch(str(source["url"]), limit=MAX_ASSET_BYTES)
            media_type = str(source["media_type"])
            relative = Path(event_id) / f"{source_id}{_extension(media_type, str(source['url']))}"
            record = _record_bytes(
                output_root=output_root,
                relative_path=relative,
                content=content,
                event_id=event_id,
                source_id=source_id,
                kind="official_report",
                source_url=str(source["url"]),
                metadata=metadata,
                expected=expected,
                refresh_lock=refresh_lock,
            )
            merged[(event_id, relative.as_posix())] = record
            if hurdat2_content is None:
                hurdat2_content, hurdat2_metadata = _fetch(NHC_HURDAT2_URL, limit=MAX_ASSET_BYTES)
            hurdat_content = _hurdat2_csv(
                hurdat2_content, official_id, str(event["canonical_name"])
            )
            hurdat_relative = Path(event_id) / f"{source_id}-hurdat2.csv"
            hurdat_record = _record_bytes(
                output_root=output_root,
                relative_path=hurdat_relative,
                content=hurdat_content,
                event_id=event_id,
                source_id=f"{source_id}-hurdat2",
                kind="normalized_nhc_hurdat2",
                source_url=NHC_HURDAT2_URL,
                metadata={**hurdat2_metadata, "content_type": "text/csv"},
                expected=expected,
                refresh_lock=refresh_lock,
            )
            merged[(event_id, hurdat_relative.as_posix())] = hurdat_record
        elif authority == "USGS ComCat":
            query_url = "https://earthquake.usgs.gov/fdsnws/event/1/query?" + urlencode(
                {"format": "geojson", "eventid": official_id}
            )
            query, query_metadata = _fetch_json(query_url)
            feature = _single_usgs_feature(query, official_id)
            country_codes = event.get("country_codes")
            country_code = (
                str(country_codes[0])
                if isinstance(country_codes, list) and len(country_codes) == 1
                else ""
            )
            csv_content = _usgs_csv(feature, event_id, country_code)
            csv_relative = Path(event_id) / f"{source_id}-metadata.csv"
            csv_record = _record_bytes(
                output_root=output_root,
                relative_path=csv_relative,
                content=csv_content,
                event_id=event_id,
                source_id=source_id,
                kind="normalized_official_metadata",
                source_url=query_url,
                metadata={**query_metadata, "content_type": "text/csv"},
                expected=expected,
                refresh_lock=refresh_lock,
            )
            merged[(event_id, csv_relative.as_posix())] = csv_record
            properties = feature["properties"]
            detail_url = properties.get("detail")
            if not isinstance(detail_url, str) or not allowed_url(detail_url):
                raise BenchmarkError(f"USGS event {official_id} has no allowed detail feed")
            detail, _ = _fetch_json(detail_url)
            for product_type, product_url, media_type in _product_assets(detail):
                content, metadata = _fetch(product_url, limit=MAX_ASSET_BYTES)
                relative = Path(event_id) / (
                    f"{source_id}-{product_type}{_extension(media_type, product_url)}"
                )
                record = _record_bytes(
                    output_root=output_root,
                    relative_path=relative,
                    content=content,
                    event_id=event_id,
                    source_id=source_id,
                    kind=f"usgs_{product_type}",
                    source_url=product_url,
                    metadata=metadata,
                    expected=expected,
                    refresh_lock=refresh_lock,
                )
                merged[(event_id, relative.as_posix())] = record
        else:
            raise BenchmarkError(f"unsupported source authority: {authority}")
        materialized_events.append(event_id)

    lock: JsonObject = {
        "schema_version": 1,
        "benchmark_id": manifest["benchmark_id"],
        "version": manifest["version"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "materialized_at": datetime.now(UTC).isoformat(),
        "files": sorted(merged.values(), key=lambda item: (item["event_id"], item["path"])),
    }
    output_root.mkdir(parents=True, exist_ok=True)
    temporary_lock = lock_path.with_name(f".{lock_path.name}.part")
    try:
        temporary_lock.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        temporary_lock.replace(lock_path)
    finally:
        temporary_lock.unlink(missing_ok=True)
    return {
        "benchmark_id": manifest["benchmark_id"],
        "version": manifest["version"],
        "materialized_events": materialized_events,
        "locked_file_count": len(lock["files"]),
        "lock_path": str(lock_path),
        "extended_existing_lock": old_lock is not None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "benchmarks")
    parser.add_argument("--event", action="append", default=[])
    parser.add_argument(
        "--split", action="append", choices=("train", "development", "test"), default=[]
    )
    parser.add_argument("--refresh-lock", action="store_true")
    parser.add_argument(
        "--accept-source-terms",
        action="store_true",
        help="confirm source/license review and permit official-network downloads",
    )
    args = parser.parse_args()
    try:
        manifest = load_json_object(args.manifest)
        manifest_report = validate_event_manifest(manifest)
        selected = _selected_events(manifest, set(args.event), set(args.split))
        version_root = args.output / str(manifest["benchmark_id"]) / str(manifest["version"])
        if not args.accept_source_terms:
            report = {
                **manifest_report,
                "mode": "dry_run",
                "selected_events": [event["event_id"] for event in selected],
                "output": str(version_root),
                "next_step": "Review source terms, then repeat with --accept-source-terms.",
            }
        else:
            report = materialize(
                manifest,
                selected,
                version_root,
                refresh_lock=args.refresh_lock,
            )
        print(json.dumps(report, indent=2))
    except BenchmarkError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
