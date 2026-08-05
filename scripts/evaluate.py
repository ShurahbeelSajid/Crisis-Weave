"""Seed a deterministic corpus and run strict routing, grounding, and abstention gates."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
from pathlib import Path
from typing import IO, Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GOLDEN = ROOT / "tests" / "evals" / "golden_queries.json"
ROUTES = {"vector", "sql", "web"}
MODALITIES = {"text", "pdf_page", "image", "video_frame", "transcript", "table", "web"}
ABSTENTION_MARKERS = (
    "do not have enough authorized evidence",
    "withholding the answer",
)

JsonObject = dict[str, Any]


class SuiteError(ValueError):
    """Raised when the suite or seed corpus is invalid."""


def _string_list(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and bool(item.strip()) for item in value
    ):
        raise SuiteError(f"{label} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise SuiteError(f"{label} must not be empty")
    return value


def _load_suite(path: Path) -> JsonObject:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SuiteError(f"could not read golden suite: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SuiteError("golden suite must be an object with schema_version=1")

    seeds = value.get("seed_documents")
    cases = value.get("cases")
    if not isinstance(seeds, list) or not seeds:
        raise SuiteError("seed_documents must be a non-empty list")
    if not isinstance(cases, list) or not cases:
        raise SuiteError("cases must be a non-empty list")

    suite_root = path.resolve().parent
    seed_names: set[str] = set()
    for index, seed in enumerate(seeds):
        label = f"seed_documents[{index}]"
        if not isinstance(seed, dict):
            raise SuiteError(f"{label} must be an object")
        is_file_seed = set(seed) == {"path", "media_type"}
        is_inline_seed = set(seed) == {"filename", "media_type", "content_base64"}
        if not is_file_seed and not is_inline_seed:
            raise SuiteError(f"{label} must define one supported seed format")
        media_type = seed.get("media_type")
        if not isinstance(media_type, str) or "/" not in media_type:
            raise SuiteError(f"{label}.media_type must be an explicit media type")
        if is_file_seed:
            relative = seed.get("path")
            if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
                raise SuiteError(f"{label}.path must be a non-empty relative path")
            fixture = (suite_root / relative).resolve()
            if not fixture.is_relative_to(suite_root) or not fixture.is_file():
                raise SuiteError(f"{label}.path is missing or escapes the suite directory")
            if fixture.stat().st_size == 0:
                raise SuiteError(f"{label}.path must not be empty")
            filename = fixture.name
        else:
            inline_filename = seed.get("filename")
            encoded = seed.get("content_base64")
            if (
                not isinstance(inline_filename, str)
                or not inline_filename
                or Path(inline_filename).name != inline_filename
                or not isinstance(encoded, str)
            ):
                raise SuiteError(f"{label} has invalid inline fields")
            filename = inline_filename
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise SuiteError(f"{label}.content_base64 is invalid") from exc
            if not content or len(content) > 1024 * 1024:
                raise SuiteError(f"{label} inline content must contain at most 1 MiB")
        if filename in seed_names:
            raise SuiteError(f"duplicate seed filename: {filename}")
        seed_names.add(filename)

    case_ids: set[str] = set()
    allowed_request = {"query", "allow_web", "top_k", "include_modalities"}
    allowed_expected = {
        "routes",
        "behavior",
        "evidence_sources",
        "citation_sources",
        "evidence_modalities",
        "answer_contains",
        "evidence_contains",
        "warning_contains",
        "trace_min_results",
    }
    for index, case in enumerate(cases):
        label = f"cases[{index}]"
        if not isinstance(case, dict) or set(case) != {"id", "request", "expected"}:
            raise SuiteError(f"{label} must contain only id, request, and expected")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in case_ids:
            raise SuiteError(f"{label}.id must be non-empty and unique")
        case_ids.add(case_id)

        request = case.get("request")
        expected = case.get("expected")
        if not isinstance(request, dict) or set(request) - allowed_request:
            raise SuiteError(f"{case_id}.request contains unknown fields")
        if not isinstance(expected, dict) or set(expected) - allowed_expected:
            raise SuiteError(f"{case_id}.expected contains unknown fields")
        query = request.get("query")
        if not isinstance(query, str) or not 3 <= len(query) <= 4000:
            raise SuiteError(f"{case_id}.request.query must contain 3-4000 characters")
        if not isinstance(request.get("allow_web"), bool):
            raise SuiteError(f"{case_id}.request.allow_web must be a boolean")
        top_k = request.get("top_k")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 30:
            raise SuiteError(f"{case_id}.request.top_k must be an integer from 1-30")
        if "include_modalities" in request:
            modalities = _string_list(
                request["include_modalities"],
                f"{case_id}.request.include_modalities",
                allow_empty=False,
            )
            if not set(modalities) <= MODALITIES:
                raise SuiteError(f"{case_id}.request.include_modalities contains an unknown value")

        routes = _string_list(expected.get("routes"), f"{case_id}.expected.routes")
        if len(routes) != len(set(routes)) or not set(routes) <= ROUTES:
            raise SuiteError(f"{case_id}.expected.routes must contain unique known routes")
        behavior = expected.get("behavior")
        if behavior not in {"answer", "abstain", "blocked"}:
            raise SuiteError(f"{case_id}.expected.behavior is invalid")
        for key in (
            "evidence_sources",
            "citation_sources",
            "evidence_modalities",
            "answer_contains",
            "evidence_contains",
            "warning_contains",
        ):
            if key in expected:
                _string_list(expected[key], f"{case_id}.expected.{key}")
        if not set(expected.get("evidence_modalities", [])) <= MODALITIES:
            raise SuiteError(f"{case_id}.expected.evidence_modalities contains an unknown value")
        minimums = expected.get("trace_min_results", {})
        if not isinstance(minimums, dict) or not set(minimums) <= ROUTES:
            raise SuiteError(f"{case_id}.expected.trace_min_results must map known routes")
        if set(minimums) != set(routes):
            raise SuiteError(
                f"{case_id}.expected.trace_min_results must cover every expected route"
            )
        if any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in minimums.values()
        ):
            raise SuiteError(f"{case_id}.expected.trace_min_results values must be non-negative")
        if behavior == "blocked" and routes:
            raise SuiteError(f"{case_id} blocked cases cannot expect tool routes")
        if behavior != "blocked" and not routes:
            raise SuiteError(f"{case_id} non-blocked cases must expect at least one route")
        if behavior == "answer" and (
            not expected.get("evidence_sources")
            or not expected.get("citation_sources")
            or not expected.get("evidence_modalities")
            or not (expected.get("answer_contains") or expected.get("evidence_contains"))
        ):
            raise SuiteError(
                f"{case_id} answer cases require sources, modalities, and expected facts"
            )
        expected_sources = set(expected.get("evidence_sources", [])) | set(
            expected.get("citation_sources", [])
        )
        if not expected_sources <= seed_names:
            raise SuiteError(f"{case_id} expects a source that is not in seed_documents")
    return value


def _json_object(response: httpx.Response, context: str) -> JsonObject:
    try:
        value = response.json()
    except ValueError as exc:
        raise SuiteError(f"{context} returned non-JSON content") from exc
    if not isinstance(value, dict):
        raise SuiteError(f"{context} returned a non-object JSON value")
    return value


def _seed_documents(
    client: httpx.Client,
    suite: JsonObject,
    suite_path: Path,
    created_ids: list[str],
) -> list[JsonObject]:
    seeded: list[JsonObject] = []
    for seed in suite["seed_documents"]:
        upload_handle: IO[bytes] | None = None
        if "path" in seed:
            fixture = (suite_path.resolve().parent / seed["path"]).resolve()
            filename = fixture.name
            upload_handle = fixture.open("rb")
            content: IO[bytes] | bytes = upload_handle
        else:
            filename = seed["filename"]
            content = base64.b64decode(seed["content_base64"], validate=True)
        try:
            response = client.post(
                "/v1/documents",
                files={"file": (filename, content, seed["media_type"])},
            )
        finally:
            if upload_handle is not None:
                upload_handle.close()
        if response.status_code != 201:
            raise SuiteError(
                f"seed upload {filename} returned {response.status_code}: {response.text[:300]}"
            )
        payload = _json_object(response, f"seed upload {filename}")
        document = payload.get("document")
        deduplicated = payload.get("deduplicated")
        if not isinstance(document, dict) or not isinstance(deduplicated, bool):
            raise SuiteError(f"seed upload {filename} returned an invalid ingestion response")
        document_id = document.get("id")
        if not isinstance(document_id, str) or not document_id:
            raise SuiteError(f"seed upload {filename} returned an invalid document ID")
        if not deduplicated:
            created_ids.append(document_id)
        if (
            document.get("filename") != filename
            or document.get("status") != "ready"
            or isinstance(document.get("chunk_count"), bool)
            or not isinstance(document.get("chunk_count"), int)
            or document["chunk_count"] < 1
        ):
            raise SuiteError(f"seed upload {filename} was not published as ready evidence")
        seeded.append(
            {
                "filename": filename,
                "document_id": document_id,
                "deduplicated": deduplicated,
                "chunk_count": document["chunk_count"],
            }
        )
    return seeded


def _citation_failures(result: JsonObject) -> list[str]:
    failures: list[str] = []
    answer = result.get("answer")
    evidence = result.get("evidence")
    citations = result.get("citations")
    if (
        not isinstance(answer, str)
        or not isinstance(evidence, list)
        or not isinstance(citations, list)
    ):
        return ["answer/evidence/citations response fields have invalid types"]

    seen_labels: set[str] = set()
    seen_ids: set[str] = set()
    citation_labels: set[str] = set()
    for position, citation in enumerate(citations):
        if not isinstance(citation, dict):
            failures.append(f"citation {position} is not an object")
            continue
        label = citation.get("label")
        if not isinstance(label, str):
            failures.append(f"citation {position} has a non-canonical label")
            continue
        match = re.fullmatch(r"E([1-9]|[12]\d|30)", label)
        if match is None:
            failures.append(f"citation {position} has a non-canonical label")
            continue
        evidence_index = int(match.group(1)) - 1
        evidence_id = citation.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            failures.append(f"citation {label} has an invalid evidence_id")
            continue
        if label in seen_labels or evidence_id in seen_ids:
            failures.append(f"citation {label} is duplicated")
        seen_labels.add(label)
        seen_ids.add(evidence_id)
        citation_labels.add(label)
        if evidence_index >= len(evidence) or not isinstance(evidence[evidence_index], dict):
            failures.append(f"citation {label} does not select returned evidence")
            continue
        cited = evidence[evidence_index]
        for key in ("id", "source_name", "source_uri", "page", "timestamp_seconds"):
            citation_key = "evidence_id" if key == "id" else key
            if citation.get(citation_key) != cited.get(key):
                failures.append(f"citation {label} has incorrect {citation_key}")
        if f"[{label}]" not in answer:
            failures.append(f"citation {label} is missing from the answer text")

    raw_answer_tokens = set(re.findall(r"\[[eE][^\]\r\n]*\]", answer))
    expected_answer_tokens = {f"[{label}]" for label in citation_labels}
    if raw_answer_tokens != expected_answer_tokens:
        failures.append("answer contains malformed, unknown, or unstructured citation labels")
    answer_labels = {f"E{value}" for value in re.findall(r"\[E([1-9]|[12]\d|30)\]", answer)}
    if answer_labels != citation_labels:
        failures.append("answer citation labels do not exactly match structured citations")
    return failures


def _evaluate_result(case: JsonObject, result: JsonObject) -> list[str]:
    failures: list[str] = []
    expected = case["expected"]
    answer = result.get("answer")
    routes = result.get("routes")
    evidence = result.get("evidence")
    citations = result.get("citations")
    traces = result.get("tool_trace")
    warnings = result.get("warnings")
    concordance = result.get("concordance")

    if routes != expected["routes"]:
        failures.append(f"routes were {routes!r}; expected {expected['routes']!r}")
    if not isinstance(answer, str):
        failures.append("answer is not a string")
        answer = ""
    if not isinstance(evidence, list):
        failures.append("evidence is not a list")
        evidence = []
    if not isinstance(citations, list):
        failures.append("citations is not a list")
        citations = []
    if not isinstance(traces, list):
        failures.append("tool_trace is not a list")
        traces = []
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        failures.append("warnings is not a list of strings")
        warnings = []
    if not isinstance(concordance, dict):
        failures.append("concordance is not an object")
        concordance = {}

    failures.extend(_citation_failures(result))
    trace_tools = [item.get("tool") for item in traces if isinstance(item, dict)]
    if trace_tools != expected["routes"]:
        failures.append(f"tool trace was {trace_tools!r}; expected {expected['routes']!r}")
    for trace in traces:
        if not isinstance(trace, dict):
            failures.append("tool trace contains a non-object item")
            continue
        if trace.get("status") != "ok":
            failures.append(f"{trace.get('tool')} trace status was {trace.get('status')!r}")
        minimum = expected.get("trace_min_results", {}).get(trace.get("tool"))
        count = trace.get("result_count")
        if minimum is not None and (
            isinstance(count, bool) or not isinstance(count, int) or count < minimum
        ):
            failures.append(f"{trace.get('tool')} returned {count!r}; expected at least {minimum}")

    evidence_objects = [item for item in evidence if isinstance(item, dict)]
    citation_objects = [item for item in citations if isinstance(item, dict)]
    actual_evidence_sources = {str(item.get("source_name")) for item in evidence_objects}
    actual_citation_sources = {str(item.get("source_name")) for item in citation_objects}
    actual_modalities = {str(item.get("modality")) for item in evidence_objects}
    for label, required, actual in (
        ("evidence sources", set(expected.get("evidence_sources", [])), actual_evidence_sources),
        ("citation sources", set(expected.get("citation_sources", [])), actual_citation_sources),
        ("evidence modalities", set(expected.get("evidence_modalities", [])), actual_modalities),
    ):
        missing = sorted(required - actual)
        if missing:
            failures.append(f"missing required {label}: {missing}")

    answer_folded = answer.casefold()
    evidence_folded = "\n".join(
        str(item.get("excerpt", "")) for item in evidence_objects
    ).casefold()
    warnings_folded = "\n".join(warnings).casefold()
    for fact in expected.get("answer_contains", []):
        if fact.casefold() not in answer_folded:
            failures.append(f"answer is missing expected fact: {fact!r}")
    for fact in expected.get("evidence_contains", []):
        if fact.casefold() not in evidence_folded:
            failures.append(f"evidence is missing expected fact: {fact!r}")
    for text in expected.get("warning_contains", []):
        if text.casefold() not in warnings_folded:
            failures.append(f"warnings are missing: {text!r}")

    behavior = expected["behavior"]
    abstained = any(marker in answer_folded for marker in ABSTENTION_MARKERS)
    if behavior == "answer":
        if abstained:
            failures.append("positive case abstained or withheld its answer")
        if not evidence:
            failures.append("positive case returned no evidence")
        if not citations:
            failures.append("positive case returned no citations")
    elif behavior == "abstain":
        if not abstained:
            failures.append("no-evidence case did not abstain")
        if evidence or citations:
            failures.append("abstention returned evidence or citations")
        if any(not isinstance(trace, dict) or trace.get("result_count") != 0 for trace in traces):
            failures.append("abstention tool trace reported non-zero results")
        if concordance.get("source_count") != 0 or concordance.get("modality_count") != 0:
            failures.append("abstention reported non-zero evidence coverage")
    else:
        if "cannot process instructions" not in answer_folded:
            failures.append("blocked case did not return the policy-block response")
        if routes or evidence or citations or traces:
            failures.append("blocked case executed or returned tool data")
        if concordance.get("score") != 0:
            failures.append("blocked case did not return zero concordance")
    return failures


def _run_cases(client: httpx.Client, suite: JsonObject) -> list[JsonObject]:
    details: list[JsonObject] = []
    for case in suite["cases"]:
        try:
            response = client.post("/v1/query", json=case["request"])
            if response.status_code != 200:
                failures = [f"query returned HTTP {response.status_code}: {response.text[:300]}"]
                result: JsonObject = {}
            else:
                result = _json_object(response, f"query case {case['id']}")
                failures = _evaluate_result(case, result)
        except (httpx.HTTPError, SuiteError) as exc:
            failures = [f"query failed: {exc}"]
            result = {}
        details.append(
            {
                "id": case["id"],
                "pass": not failures,
                "failures": failures,
                "actual_routes": result.get("routes"),
                "evidence_count": len(result.get("evidence", []))
                if isinstance(result.get("evidence"), list)
                else None,
                "citation_count": len(result.get("citations", []))
                if isinstance(result.get("citations"), list)
                else None,
            }
        )
    return details


def _cleanup(client: httpx.Client, document_ids: list[str]) -> list[str]:
    failures: list[str] = []
    for document_id in reversed(document_ids):
        try:
            response = client.delete(f"/v1/documents/{document_id}")
            if response.status_code != 204:
                failures.append(f"delete {document_id} returned HTTP {response.status_code}")
        except httpx.HTTPError as exc:
            failures.append(f"delete {document_id} failed: {exc}")
    return failures


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--api-url",
        default=os.environ.get("CRISISWEAVE_API_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument("--api-key", default=os.environ.get("CRISISWEAVE_API_KEY"))
    parser.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    parser.add_argument("--timeout", type=_positive_float, default=120.0)
    parser.add_argument(
        "--keep-seed",
        action="store_true",
        help="Keep newly created seed documents for manual inspection.",
    )
    args = parser.parse_args()
    if not args.api_key:
        parser.error("set CRISISWEAVE_API_KEY or pass --api-key")

    created_ids: list[str] = []
    seeded: list[JsonObject] = []
    cases: list[JsonObject] = []
    cleanup_failures: list[str] = []
    setup_error: str | None = None
    try:
        suite = _load_suite(args.golden)
        with httpx.Client(
            base_url=args.api_url.rstrip("/"),
            headers={"X-API-Key": args.api_key},
            timeout=args.timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            try:
                seeded = _seed_documents(client, suite, args.golden, created_ids)
                cases = _run_cases(client, suite)
            except (httpx.HTTPError, SuiteError) as exc:
                setup_error = str(exc)
            finally:
                if not args.keep_seed:
                    cleanup_failures = _cleanup(client, created_ids)
    except (httpx.HTTPError, ValueError) as exc:
        setup_error = str(exc)

    passed = sum(bool(case["pass"]) for case in cases)
    report = {
        "status": "setup_failed"
        if setup_error
        else "passed"
        if passed == len(cases) and not cleanup_failures
        else "failed",
        "passed": passed,
        "total": len(cases),
        "seeded": seeded,
        "cases": cases,
        "setup_error": setup_error,
        "cleanup_failures": cleanup_failures,
        "seed_kept": args.keep_seed,
    }
    print(json.dumps(report, indent=2))
    if setup_error:
        raise SystemExit(2)
    raise SystemExit(0 if passed == len(cases) and not cleanup_failures else 1)


if __name__ == "__main__":
    main()
