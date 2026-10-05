"""Thin Streamlit client. Authorization and data access stay behind FastAPI."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx
import streamlit as st

from crisisweave.ui_auth import UIAuthenticationError, UIAuthMode, api_auth_headers

st.set_page_config(page_title="CrisisWeave", page_icon="satellite", layout="wide")
st.title("CrisisWeave")
st.caption("Multimodal disaster evidence—routed, reranked, cited, and uncertainty-aware")

raw_api_url = os.getenv("CRISISWEAVE_API_URL", "http://localhost:8000")
api_url = raw_api_url.rstrip("/")
parsed_api_url = urlparse(api_url)
try:
    invalid_api_port = not (parsed_api_url.port is None or 1 <= parsed_api_url.port <= 65535)
except ValueError:
    invalid_api_port = True
path_segments = parsed_api_url.path.split("/")
if (
    raw_api_url != raw_api_url.strip()
    or any(ord(character) < 32 for character in raw_api_url)
    or parsed_api_url.scheme not in {"http", "https"}
    or invalid_api_port
    or not parsed_api_url.hostname
    or parsed_api_url.username is not None
    or parsed_api_url.password is not None
    or bool(parsed_api_url.params or parsed_api_url.query or parsed_api_url.fragment)
    or "\\" in parsed_api_url.path
    or any(segment in {".", ".."} for segment in path_segments)
):
    st.error("The operator-configured API URL is invalid.")
    st.stop()
max_upload_bytes = int(os.getenv("CRISISWEAVE_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
ingestion_timeout_seconds = float(os.getenv("CRISISWEAVE_INGESTION_CLIENT_TIMEOUT", "620"))
max_batch_files = 20
max_batch_bytes = 4 * max_upload_bytes
raw_ui_auth_mode = os.getenv("CRISISWEAVE_UI_AUTH_MODE", "api_key")
if raw_ui_auth_mode not in {"api_key", "forwarded_bearer"}:
    st.error("The operator-configured UI authentication mode is invalid.")
    st.stop()
ui_auth_mode: UIAuthMode = raw_ui_auth_mode
ui_local_mode = os.getenv("CRISISWEAVE_UI_LOCAL_MODE", "false").casefold() == "true"


def forwarded_authorization_header() -> str | None:
    """Read the one header an organizational ingress is allowed to inject."""

    value = st.context.headers.get("Authorization")
    return value if isinstance(value, str) else None


@st.cache_resource
def api_client() -> httpx.Client:
    return httpx.Client(follow_redirects=False, trust_env=False)


with st.sidebar:
    st.header("Connection")
    st.code(api_url, language=None)
    if ui_local_mode:
        st.info(
            "Local evidence mode: scanned-page OCR and query-matched extracts are enabled. "
            "Questions that require inspecting pixels will abstain unless you configure a "
            "vision model."
        )
    if ui_auth_mode == "api_key":
        api_key = st.text_input("Your scoped API key", value="", type="password")
        st.caption("The API destination is operator-fixed; no shared service key is embedded.")
    else:
        api_key = ""
        st.caption("Authentication is managed by the organizational access gateway.")


credential_material = (
    api_key if ui_auth_mode == "api_key" else (forwarded_authorization_header() or "")
)
auth_context_digest = hashlib.sha256(f"{ui_auth_mode}\0{credential_material}".encode()).hexdigest()
previous_auth_context = st.session_state.get("_ui_auth_context_digest")
if previous_auth_context is not None and previous_auth_context != auth_context_digest:
    protected_state_keys = {
        "active_review_submission",
        "documents",
        "ingestion_jobs",
        "latest_query_result",
        "review_detail",
        "review_queue",
        "selected_review_id",
    }
    protected_state_keys.update(
        key
        for key in st.session_state
        if isinstance(key, str) and key.startswith("decision_rationale_")
    )
    for state_key in protected_state_keys:
        st.session_state.pop(state_key, None)
st.session_state["_ui_auth_context_digest"] = auth_context_digest


def request(
    method: str, path: str, *, timeout_seconds: float = 120.0, **kwargs: object
) -> httpx.Response | None:
    try:
        auth_headers = api_auth_headers(
            ui_auth_mode,
            api_key=api_key,
            forwarded_authorization=forwarded_authorization_header(),
        )
    except UIAuthenticationError as exc:
        st.warning(str(exc))
        return None
    try:
        response = api_client().request(
            method,
            f"{api_url}{path}",
            headers=auth_headers,
            timeout=httpx.Timeout(timeout_seconds),
            **kwargs,
        )
        if response.status_code >= 400:
            if (
                response.status_code == 405
                and method.upper() == "DELETE"
                and path.startswith("/v1/documents?")
            ):
                st.error(
                    "The running API is older than this frontend and does not support "
                    "library reset. Stop the local project, restart it with "
                    "scripts/run_local.ps1, and refresh this page."
                )
                return None
            try:
                detail = response.json().get("detail", "Request failed")
            except (AttributeError, ValueError):
                detail = "Request failed"
            st.error(f"API error {response.status_code}: {detail}")
            return None
        return response
    except httpx.HTTPError as exc:
        st.error(f"API connection failed: {type(exc).__name__}")
        return None


def _percentage(value: object) -> str:
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return "unknown"


def _decimal(value: object, *, digits: int = 2) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "unknown"


def _bounding_box_locator(value: object) -> str:
    if not isinstance(value, Mapping):
        return "box unavailable"
    try:
        return (
            f"x {float(value['x_min']):.1%}-{float(value['x_max']):.1%}, "
            f"y {float(value['y_min']):.1%}-{float(value['y_max']):.1%}"
        )
    except (KeyError, TypeError, ValueError):
        return "box unavailable"


def _region_locator(region: object) -> str:
    """Return a readable locator without implying that an overlay was rendered."""

    if not isinstance(region, Mapping):
        return "Visual locator unavailable"
    kind = region.get("kind")
    box = _bounding_box_locator(region.get("bbox"))
    source = str(region.get("source", "unknown")).replace("_", " ")
    label = region.get("label")
    label_text = f"; label: {label}" if isinstance(label, str) and label else ""
    if kind == "image_bbox":
        return f"Image region ({box}){label_text}; locator source: {source}"
    if kind == "pdf_bbox":
        return (
            f"PDF page {region.get('page', 'unknown')} region ({box}){label_text}; "
            f"locator source: {source}"
        )
    if kind == "chart_element":
        details = [
            f"Chart {str(region.get('element_type', 'element')).replace('_', ' ')}",
            f"element {region.get('element_id', 'unknown')}",
        ]
        if region.get("page") is not None:
            details.append(f"PDF page {region['page']}")
        if region.get("series_label"):
            details.append(f"series {region['series_label']}")
        if region.get("category_label"):
            details.append(f"category {region['category_label']}")
        details.extend([box, f"locator source: {source}"])
        return "; ".join(details)
    if kind == "video_time_range":
        interval = (
            f"{_decimal(region.get('start_seconds'), digits=1)}s to "
            f"{_decimal(region.get('end_seconds'), digits=1)}s"
        )
        spatial = f"; frame region ({box})" if region.get("bbox") is not None else ""
        return f"Video interval {interval}{spatial}{label_text}; locator source: {source}"
    return f"Unknown visual locator; locator source: {source}"


def _render_freshness_and_conflicts(payload: Mapping[str, Any]) -> None:
    freshness = payload.get("source_freshness")
    if isinstance(freshness, Mapping):
        status = str(freshness.get("status", "unknown")).replace("_", " ")
        known = freshness.get("known_source_count", 0)
        unknown = freshness.get("unknown_source_count", 0)
        oldest = freshness.get("oldest_source_age_days")
        age = "unknown" if oldest is None else f"{_decimal(oldest, digits=1)} days"
        st.caption(
            f"Source freshness: {status}; known timestamps: {known}; "
            f"unknown timestamps: {unknown}; oldest source: {age}."
        )

    conflict_labels = (
        ("claim_evidence_conflict", "Claim-to-evidence conflict"),
        ("cross_source_conflict", "Cross-source conflict"),
    )
    for key, label in conflict_labels:
        signal = payload.get(key)
        if not isinstance(signal, Mapping):
            continue
        status = str(signal.get("status", "unknown")).replace("_", " ")
        score = signal.get("score")
        method = signal.get("method")
        score_text = "not scored" if score is None else _percentage(score)
        method_text = f"; method: {method}" if method else ""
        st.caption(f"{label}: {status}; score: {score_text}{method_text}.")


def _render_query_response(result: Mapping[str, Any], *, key_prefix: str) -> None:
    answer = result.get("answer")
    st.text(str(answer) if answer is not None else "No answer was returned.")
    concordance = result.get("concordance")
    if isinstance(concordance, Mapping):
        st.metric("Retrieval and source diversity", _percentage(concordance.get("score")))
        rationale = concordance.get("rationale")
        if rationale:
            st.caption(str(rationale))
        st.caption("This score is a retrieval/diversity heuristic, not answer correctness.")
    _render_freshness_and_conflicts(result)
    warnings = result.get("warnings")
    if isinstance(warnings, list) and warnings:
        important_warnings = [
            str(warning)
            for warning in warnings
            if any(
                term in str(warning).casefold()
                for term in ("abstain", "extractive", "ocr", "pixel", "vision model")
            )
        ]
        if important_warnings:
            st.warning("\n\n".join(important_warnings))
        with st.expander("Limitations and guardrail notices"):
            for warning in warnings:
                st.text(f"- {warning}")
    with st.expander("Tool trace", expanded=False):
        st.json(result.get("tool_trace", []), expanded=False)
    st.subheader("Citations")
    citations = result.get("citations")
    if not isinstance(citations, list) or not citations:
        st.caption("No citations were returned.")
        return
    for citation_index, citation in enumerate(citations):
        if not isinstance(citation, Mapping):
            continue
        location = ""
        if citation.get("page"):
            location += f" - page {citation['page']}"
        if citation.get("timestamp_seconds") is not None:
            location += f" - {_decimal(citation['timestamp_seconds'], digits=1)}s"
        st.text(
            f"[{citation.get('label', '?')}] "
            f"{citation.get('source_name', 'Unknown source')}{location}"
        )
        regions = citation.get("regions")
        if isinstance(regions, list):
            for region_index, region in enumerate(regions, start=1):
                st.caption(f"Region {region_index}: {_region_locator(region)}")
        uri = citation.get("source_uri")
        parsed = urlparse(uri if isinstance(uri, str) else "")
        if parsed.scheme == "https" and parsed.hostname:
            st.caption(f"External source: {parsed.hostname}")
            st.link_button(
                "Open source",
                uri,
                key=f"{key_prefix}_source_{citation_index}",
            )


def _render_review_context(review: Mapping[str, Any]) -> None:
    st.subheader("Review context")
    st.text(f"Question: {review.get('query', 'Unavailable')}")
    status = str(review.get("status", "unknown")).replace("_", " ")
    risk = str(review.get("risk_level", "unknown")).replace("_", " ")
    metric_columns = st.columns(3)
    with metric_columns[0]:
        st.metric("Status", status.title())
    with metric_columns[1]:
        st.metric("Risk", risk.title())
    with metric_columns[2]:
        st.metric("Review confidence", _percentage(review.get("confidence")))
    reasons = review.get("reasons")
    st.text("Review reasons")
    if isinstance(reasons, list) and reasons:
        for reason in reasons:
            st.text(f"- {reason}")
    else:
        st.caption("No review reasons were supplied.")
    _render_freshness_and_conflicts(review)
    contradiction_score = review.get("contradiction_score")
    if contradiction_score is not None:
        st.caption(f"Overall contradiction score: {_percentage(contradiction_score)}.")
    if review.get("reviewed_by"):
        st.caption(
            f"Decision recorded by {review['reviewed_by']}: "
            f"{review.get('decision_reason') or 'No rationale returned.'}"
        )


ask_tab, ingest_tab, library_tab, review_tab = st.tabs(
    ["Ask", "Ingest", "Evidence library", "Human review"]
)

with ask_tab:
    question = st.text_area(
        "Question",
        placeholder=("Example: Which hazard caused the largest share of direct economic losses?"),
        max_chars=4000,
    )
    col1, col2 = st.columns(2)
    with col1:
        allow_web = st.checkbox("Allow current official-domain web search", value=False)
    with col2:
        top_k = st.slider("Evidence units", min_value=3, max_value=15, value=8)
    if st.button("Analyze evidence", type="primary", disabled=len(question.strip()) < 3):
        with st.spinner("Routing tools and checking evidence..."):
            response = request(
                "POST",
                "/v1/query",
                json={"query": question, "allow_web": allow_web, "top_k": top_k},
            )
        if response is not None:
            result = response.json()
            if response.status_code == 202 or (
                isinstance(result, Mapping) and "review_id" in result and "answer" not in result
            ):
                st.session_state["active_review_submission"] = result
                st.session_state.pop("latest_query_result", None)
            elif isinstance(result, Mapping):
                st.session_state["latest_query_result"] = result
                st.session_state.pop("active_review_submission", None)

    latest_result = st.session_state.get("latest_query_result")
    if isinstance(latest_result, Mapping):
        _render_query_response(latest_result, key_prefix="ask")

    active_review = st.session_state.get("active_review_submission")
    if isinstance(active_review, Mapping):
        risk_level = str(active_review.get("risk_level", "unknown")).replace("_", " ")
        st.warning(
            f"Answer withheld for {risk_level} risk review. Review ID: "
            f"{active_review.get('review_id', 'unavailable')}"
        )
        reasons = active_review.get("reasons")
        st.text("Why review is required")
        if isinstance(reasons, list):
            for reason in reasons:
                st.text(f"- {reason}")
        if st.button("Check reviewed result", key="check_active_review_result"):
            review_id = active_review.get("review_id")
            if isinstance(review_id, str):
                reviewed_response = request("GET", f"/v1/reviews/{review_id}/result")
                if reviewed_response is not None:
                    reviewed_result = reviewed_response.json()
                    if isinstance(reviewed_result, Mapping):
                        st.session_state["latest_query_result"] = reviewed_result
                        st.session_state.pop("active_review_submission", None)
                        st.success("The independently reviewed answer is now available.")
                        _render_query_response(reviewed_result, key_prefix="reviewed_query")

with ingest_tab:
    uploads = st.file_uploader(
        "Upload evidence files",
        type=[
            "pdf",
            "jpg",
            "jpeg",
            "png",
            "webp",
            "mp4",
            "webm",
            "csv",
            "json",
            "txt",
            "md",
            "srt",
            "vtt",
        ],
        accept_multiple_files=True,
        help="The server validates signatures and configured size/page/pixel/duration limits.",
    )
    uploads = uploads or []
    st.caption(
        f"Select up to {max_batch_files} files and {max_batch_bytes:,} total bytes. "
        "Files are queued together and processed asynchronously by available workers."
    )
    source_uris = [
        st.text_input(
            f"Original HTTPS source URL for {upload.name} (optional)",
            key=f"source_uri_{position}",
        )
        for position, upload in enumerate(uploads)
    ]
    if st.button("Ingest selected files", disabled=not uploads):
        batch_size = sum(upload.size for upload in uploads)
        invalid_files = [upload.name for upload in uploads if upload.size <= 0]
        oversized_files = [upload.name for upload in uploads if upload.size > max_upload_bytes]
        validation_error = None
        if len(uploads) > max_batch_files:
            validation_error = f"Select no more than {max_batch_files} files per batch."
        elif batch_size > max_batch_bytes:
            validation_error = f"The selected batch exceeds {max_batch_bytes:,} bytes."
        elif invalid_files:
            validation_error = f"Empty files are not accepted: {', '.join(invalid_files)}"
        elif oversized_files:
            validation_error = (
                f"These files exceed {max_upload_bytes:,} bytes: {', '.join(oversized_files)}"
            )

        if validation_error:
            st.error(validation_error)
        else:
            results_by_position: list[dict[str, object] | None] = [None] * len(uploads)
            queued: list[dict[str, object]] = []
            successful = 0
            progress = st.progress(0, text="Preparing evidence batch…")
            for position, upload in enumerate(uploads):
                progress.progress(
                    position / (2 * len(uploads)),
                    text=f"Queuing {upload.name} ({position + 1}/{len(uploads)})…",
                )
                upload.seek(0)
                with st.spinner(f"Queuing {upload.name}…"):
                    response = request(
                        "POST",
                        "/v1/ingestion-jobs",
                        timeout_seconds=ingestion_timeout_seconds,
                        files={"file": (upload.name, upload, "application/octet-stream")},
                        data={"source_uri": source_uris[position]},
                    )
                if response is None:
                    results_by_position[position] = {
                        "name": upload.name,
                        "status": "queue_failed",
                        "chunks": 0,
                    }
                    continue
                result = response.json()
                queued.append(
                    {
                        "position": position,
                        "name": upload.name,
                        "deduplicated": bool(result.get("deduplicated")),
                        "job": result["job"],
                    }
                )

            deadline = time.monotonic() + ingestion_timeout_seconds
            terminal = {"succeeded", "cancelled", "dead_letter", "status_unavailable"}
            while any(item["job"]["status"] not in terminal for item in queued) and (
                time.monotonic() < deadline
            ):
                for item in queued:
                    job = item["job"]
                    if job["status"] in terminal:
                        continue
                    job_response = request(
                        "GET",
                        f"/v1/ingestion-jobs/{job['id']}",
                        timeout_seconds=30,
                    )
                    if job_response is None:
                        job = {**job, "status": "status_unavailable", "stage": "poll_failed"}
                    else:
                        job = job_response.json()
                    item["job"] = job
                mean_job_progress = sum(
                    int(item["job"].get("progress", 0)) for item in queued
                ) / max(1, len(queued))
                progress.progress(
                    min(0.99, 0.5 + mean_job_progress / 200),
                    text=f"Processing {len(queued)} queued file(s): {mean_job_progress:.0f}%",
                )
                if any(item["job"]["status"] not in terminal for item in queued):
                    time.sleep(0.5)

            for item in queued:
                position = int(item["position"])
                job = item["job"]
                if job["status"] not in terminal:
                    job = {**job, "status": "client_timeout"}
                if job["status"] != "succeeded" or not job.get("document_id"):
                    results_by_position[position] = {
                        "name": item["name"],
                        "status": job["status"],
                        "chunks": 0,
                    }
                    continue
                document_response = request(
                    "GET",
                    f"/v1/documents/{job['document_id']}",
                    timeout_seconds=30,
                )
                if document_response is None:
                    results_by_position[position] = {
                        "name": item["name"],
                        "status": "ready_status_unavailable",
                        "chunks": 0,
                    }
                    continue
                document = document_response.json()
                successful += 1
                results_by_position[position] = {
                    "name": document["filename"],
                    "status": "deduplicated" if item["deduplicated"] else "ready",
                    "chunks": document["chunk_count"],
                    "notices": "; ".join(str(value) for value in document.get("warnings", [])),
                }
            batch_results = [
                result
                if result is not None
                else {"name": uploads[position].name, "status": "unknown", "chunks": 0}
                for position, result in enumerate(results_by_position)
            ]
            progress.progress(1.0, text="Evidence batch complete")
            if successful:
                st.session_state.pop("documents", None)
                st.success(f"{successful} of {len(uploads)} evidence files are ready.")
            if successful != len(uploads):
                st.warning("Some files were not ingested. Review the messages above.")
            st.dataframe(batch_results, use_container_width=True, hide_index=True)

with library_tab:
    if st.button("Refresh library"):
        response = request("GET", "/v1/documents")
        if response:
            st.session_state["documents"] = response.json()
        jobs_response = request("GET", "/v1/ingestion-jobs?limit=100")
        if jobs_response:
            st.session_state["ingestion_jobs"] = jobs_response.json()
    documents = st.session_state.get("documents", [])
    if not documents:
        st.info("Refresh to list tenant-authorized evidence.")
    else:
        st.dataframe(
            [
                {
                    "name": item["filename"],
                    "type": item["media_type"],
                    "status": item["status"],
                    "chunks": item["chunk_count"],
                    "notices": "; ".join(str(value) for value in item.get("warnings", [])),
                    "created": item["created_at"],
                }
                for item in documents
            ],
            use_container_width=True,
            hide_index=True,
        )

    ingestion_jobs = st.session_state.get("ingestion_jobs", [])
    if ingestion_jobs:
        st.subheader("Recent ingestion jobs")
        st.dataframe(
            [
                {
                    "file": item["filename"],
                    "status": item["status"],
                    "progress": f"{item['progress']}%",
                    "stage": item["stage"],
                    "attempts": f"{item['attempt_count']}/{item['max_attempts']}",
                    "error": item.get("error_code"),
                }
                for item in ingestion_jobs
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.divider()
    st.subheader("Reset evidence library")
    st.caption(
        "This permanently deletes vectors, analytics rows, metadata, and derived files "
        "for the tenant associated with the current API key."
    )
    reset_confirmation = st.text_input(
        "Type RESET to confirm",
        key="reset_confirmation",
    )
    if st.button(
        "Reset evidence library",
        disabled=reset_confirmation.strip() != "RESET",
    ):
        with st.spinner("Deleting tenant evidence…"):
            response = request(
                "DELETE",
                "/v1/documents?confirmation=RESET",
                timeout_seconds=ingestion_timeout_seconds,
            )
        if response is not None:
            deleted_count = int(response.json()["deleted_count"])
            st.session_state["documents"] = []
            if deleted_count:
                st.success(f"Deleted {deleted_count} evidence files. The library is fresh.")
            else:
                st.info("The evidence library was already empty.")

with review_tab:
    st.caption(
        "This workspace requires a human user with review permissions. "
        "The requester cannot approve their own answer."
    )
    if st.button("Refresh pending reviews", key="refresh_pending_reviews"):
        reviews_response = request("GET", "/v1/reviews?status=pending&limit=100")
        if reviews_response is None:
            # Never retain protected review data after an authorization or lookup failure.
            st.session_state.pop("review_queue", None)
            st.session_state.pop("review_detail", None)
        else:
            review_payload = reviews_response.json()
            if isinstance(review_payload, list):
                st.session_state["review_queue"] = review_payload

    review_queue = st.session_state.get("review_queue", [])
    if not isinstance(review_queue, list) or not review_queue:
        st.info("Refresh to load pending reviews, or there are no pending reviews.")
    else:
        st.dataframe(
            [
                {
                    "review_id": item.get("id"),
                    "risk": item.get("risk_level"),
                    "confidence": _percentage(item.get("confidence")),
                    "freshness": (
                        item.get("source_freshness", {}).get("status", "unknown")
                        if isinstance(item.get("source_freshness"), Mapping)
                        else "unknown"
                    ),
                    "contradiction": _percentage(item.get("contradiction_score")),
                    "created": item.get("created_at"),
                }
                for item in review_queue
                if isinstance(item, Mapping)
            ],
            use_container_width=True,
            hide_index=True,
        )
        review_ids = [
            str(item["id"]) for item in review_queue if isinstance(item, Mapping) and item.get("id")
        ]
        selected_review_id = st.selectbox(
            "Review to inspect",
            review_ids,
            key="selected_review_id",
        )
        if st.button("Inspect selected review", key="inspect_selected_review"):
            detail_response = request("GET", f"/v1/reviews/{selected_review_id}")
            if detail_response is None:
                st.session_state.pop("review_detail", None)
            else:
                detail_payload = detail_response.json()
                if isinstance(detail_payload, Mapping):
                    st.session_state["review_detail"] = detail_payload

    review_detail = st.session_state.get("review_detail")
    if isinstance(review_detail, Mapping):
        review_id = review_detail.get("id")
        if isinstance(review_id, str):
            _render_review_context(review_detail)
            candidate = review_detail.get("candidate_response")
            if isinstance(candidate, Mapping):
                st.subheader("Candidate answer (not yet released to the requester)")
                _render_query_response(candidate, key_prefix=f"candidate_{review_id}")

            review_status = str(review_detail.get("status", "unknown"))
            if review_status == "pending":
                rationale = st.text_area(
                    "Decision rationale",
                    max_chars=1000,
                    key=f"decision_rationale_{review_id}",
                    help="Record the evidence-based reason for approval or rejection.",
                )
                action_columns = st.columns(2)
                with action_columns[0]:
                    approve_clicked = st.button(
                        "Approve answer",
                        type="primary",
                        disabled=len(rationale.strip()) < 3,
                        key=f"approve_{review_id}",
                    )
                with action_columns[1]:
                    reject_clicked = st.button(
                        "Reject answer",
                        disabled=len(rationale.strip()) < 3,
                        key=f"reject_{review_id}",
                    )
                if approve_clicked or reject_clicked:
                    decision = "approve" if approve_clicked else "reject"
                    decision_response = request(
                        "POST",
                        f"/v1/reviews/{review_id}/decision",
                        json={"decision": decision, "reason": rationale.strip()},
                    )
                    if decision_response is not None:
                        decided_review = decision_response.json()
                        if isinstance(decided_review, Mapping):
                            review_detail = decided_review
                            st.session_state["review_detail"] = decided_review
                            st.session_state["review_queue"] = [
                                item
                                for item in review_queue
                                if not isinstance(item, Mapping) or item.get("id") != review_id
                            ]
                            review_status = str(decided_review.get("status", "unknown"))
                            st.success(f"Review {review_status} with an audit rationale.")

            if review_status == "approved" and st.button(
                "Fetch approved result",
                key=f"fetch_result_{review_id}",
            ):
                result_response = request("GET", f"/v1/reviews/{review_id}/result")
                if result_response is not None:
                    approved_result = result_response.json()
                    if isinstance(approved_result, Mapping):
                        st.success("Approved result fetched from the release endpoint.")
                        _render_query_response(
                            approved_result,
                            key_prefix=f"approved_{review_id}",
                        )
