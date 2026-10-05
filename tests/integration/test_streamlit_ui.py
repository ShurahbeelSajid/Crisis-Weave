from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import streamlit as st
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[2] / "apps" / "streamlit_app.py"
REVIEW_ID = "20000000-0000-4000-8000-000000000001"


def _query_payload() -> dict[str, Any]:
    box = {"x_min": 0.1, "y_min": 0.2, "x_max": 0.4, "y_max": 0.6}
    return {
        "answer": "The reviewed evidence supports a localized impact.",
        "concordance": {
            "score": 0.82,
            "rationale": "Three independent modalities agree.",
        },
        "source_freshness": {
            "status": "partial",
            "known_source_count": 3,
            "unknown_source_count": 1,
            "oldest_source_age_days": 4.5,
        },
        "claim_evidence_conflict": {
            "status": "not_detected",
            "score": 0.0,
            "method": "claim-polarity-v1",
        },
        "cross_source_conflict": {
            "status": "detected",
            "score": 0.35,
            "method": "source-polarity-v1",
        },
        "warnings": ["One source has no publication timestamp."],
        "tool_trace": [],
        "citations": [
            {
                "label": "E1",
                "source_name": "damage.jpg",
                "source_uri": None,
                "regions": [
                    {
                        "kind": "image_bbox",
                        "bbox": box,
                        "label": "damaged structure",
                        "source": "model_proposal",
                    }
                ],
            },
            {
                "label": "E2",
                "source_name": "assessment.pdf",
                "source_uri": None,
                "page": 7,
                "regions": [
                    {
                        "kind": "pdf_bbox",
                        "page": 7,
                        "bbox": box,
                        "coordinate_space": "normalized_top_left",
                        "label": "damage table",
                        "source": "derived_provenance",
                    }
                ],
            },
            {
                "label": "E3",
                "source_name": "rainfall-chart.png",
                "source_uri": None,
                "regions": [
                    {
                        "kind": "chart_element",
                        "element_id": "bar-2025",
                        "element_type": "bar",
                        "bbox": box,
                        "series_label": "Rainfall",
                        "category_label": "May",
                        "source": "human_annotation",
                    }
                ],
            },
            {
                "label": "E4",
                "source_name": "survey.mp4",
                "source_uri": None,
                "timestamp_seconds": 14.0,
                "regions": [
                    {
                        "kind": "video_time_range",
                        "start_seconds": 12.5,
                        "end_seconds": 18.0,
                        "bbox": box,
                        "label": "flooded road",
                        "source": "model_proposal",
                    }
                ],
            },
        ],
    }


def _review_payload() -> dict[str, Any]:
    return {
        "id": REVIEW_ID,
        "query": "Should an evacuation order be issued?",
        "status": "pending",
        "risk_level": "high",
        "reasons": ["Operational decision requires independent approval."],
        "confidence": 0.61,
        "oldest_source_age_days": 4.5,
        "contradiction_score": 0.35,
        "source_freshness": {
            "status": "partial",
            "known_source_count": 3,
            "unknown_source_count": 1,
            "oldest_source_age_days": 4.5,
        },
        "claim_evidence_conflict": {
            "status": "not_detected",
            "score": 0.0,
            "method": "claim-polarity-v1",
        },
        "cross_source_conflict": {
            "status": "detected",
            "score": 0.35,
            "method": "source-polarity-v1",
        },
        "requester_subject": "analyst-1",
        "requester_identity_type": "user",
        "created_at": "2026-08-03T10:00:00Z",
        "updated_at": "2026-08-03T10:00:00Z",
        "reviewed_by": None,
        "decision_reason": None,
        "candidate_response": _query_payload(),
    }


@dataclass
class FakeResponse:
    status_code: int
    payload: Any

    def json(self) -> Any:
        return self.payload


class RecordingClient:
    def __init__(
        self,
        *,
        reset_status: int = 200,
        query_status: int = 200,
        review_list_status: int = 200,
        review_detail_status: int = 200,
    ) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.reset_status = reset_status
        self.query_status = query_status
        self.review_list_status = review_list_status
        self.review_detail_status = review_detail_status
        self.documents: dict[str, dict[str, Any]] = {}
        self.review = _review_payload()

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        if method == "POST" and url.endswith("/v1/query"):
            if self.query_status == 202:
                return FakeResponse(
                    202,
                    {
                        "review_id": REVIEW_ID,
                        "status": "pending",
                        "risk_level": "high",
                        "reasons": ["Operational decision requires independent approval."],
                        "request_id": "request-1",
                    },
                )
            return FakeResponse(200, _query_payload())
        if method == "POST" and url.endswith("/v1/ingestion-jobs"):
            filename = kwargs["files"]["file"][0]
            job_id = f"00000000-0000-4000-8000-{len(self.documents) + 1:012d}"
            document_id = f"10000000-0000-4000-8000-{len(self.documents) + 1:012d}"
            self.documents[document_id] = {
                "filename": filename,
                "status": "ready",
                "chunk_count": 1,
            }
            return FakeResponse(
                202,
                {
                    "job": {
                        "id": job_id,
                        "status": "succeeded",
                        "progress": 100,
                        "stage": "completed",
                        "document_id": document_id,
                    },
                    "deduplicated": False,
                },
            )
        if method == "GET" and "/v1/documents/" in url:
            document_id = url.rsplit("/", maxsplit=1)[-1]
            return FakeResponse(200, self.documents[document_id])
        if method == "GET" and url.endswith("/v1/reviews?status=pending&limit=100"):
            if self.review_list_status != 200:
                return FakeResponse(
                    self.review_list_status,
                    {"detail": "Review permission is required"},
                )
            return FakeResponse(200, [deepcopy(self.review)])
        if method == "GET" and url.endswith(f"/v1/reviews/{REVIEW_ID}/result"):
            if self.review["status"] == "pending":
                return FakeResponse(409, {"detail": "Review is still pending"})
            if self.review["status"] == "rejected":
                return FakeResponse(410, {"detail": "Answer was rejected"})
            return FakeResponse(200, _query_payload())
        if method == "GET" and url.endswith(f"/v1/reviews/{REVIEW_ID}"):
            if self.review_detail_status != 200:
                return FakeResponse(self.review_detail_status, {"detail": "Review not found"})
            return FakeResponse(200, deepcopy(self.review))
        if method == "POST" and url.endswith(f"/v1/reviews/{REVIEW_ID}/decision"):
            decision = kwargs["json"]["decision"]
            self.review["status"] = "approved" if decision == "approve" else "rejected"
            self.review["reviewed_by"] = "reviewer-1"
            self.review["decision_reason"] = kwargs["json"]["reason"]
            return FakeResponse(200, deepcopy(self.review))
        if method == "DELETE" and url.endswith("/v1/documents?confirmation=RESET"):
            if self.reset_status == 405:
                return FakeResponse(405, {"detail": "Method Not Allowed"})
            return FakeResponse(200, {"deleted_count": 2})
        if method == "GET" and url.endswith("/v1/documents"):
            return FakeResponse(200, [])
        raise AssertionError(f"Unexpected frontend request: {method} {url}")


def _element_with_label(elements: Any, label: str) -> Any:
    return next(element for element in elements if element.label == label)


def _run_app(
    monkeypatch: Any,
    **client_options: int,
) -> tuple[AppTest, RecordingClient]:
    st.cache_resource.clear()
    client = RecordingClient(**client_options)
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: client)
    app = AppTest.from_file(str(APP)).run()
    assert not list(app.exception)
    return app, client


def test_streamlit_ingests_multiple_files_with_individual_source_uris(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch)
    uploader = app.get("file_uploader")[0]
    assert uploader.accept_multiple_files is True
    assert _element_with_label(app.button, "Ingest selected files").disabled is True

    uploader.set_value(
        [
            ("report.txt", b"Containment was 37 percent.", "text/plain"),
            ("events.csv", b"STATE,DAMAGE\nCA,100\n", "text/csv"),
        ]
    ).run()
    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(
        app.text_input,
        "Original HTTPS source URL for report.txt (optional)",
    ).input("https://agency.example/report").run()
    _element_with_label(
        app.text_input,
        "Original HTTPS source URL for events.csv (optional)",
    ).input("https://agency.example/events").run()
    _element_with_label(app.button, "Ingest selected files").click().run()

    posts = [call for call in client.calls if call[0] == "POST"]
    assert [call[2]["files"]["file"][0] for call in posts] == ["report.txt", "events.csv"]
    assert [call[2]["data"]["source_uri"] for call in posts] == [
        "https://agency.example/report",
        "https://agency.example/events",
    ]
    assert any("2 of 2 evidence files are ready" in item.value for item in app.success)
    assert not list(app.exception)


def test_streamlit_rejects_empty_batch_member_before_any_request(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch)
    app.get("file_uploader")[0].set_value(
        [
            ("empty.txt", b"", "text/plain"),
            ("valid.txt", b"valid", "text/plain"),
        ]
    ).run()
    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(app.button, "Ingest selected files").click().run()

    assert client.calls == []
    assert any("Empty files are not accepted" in item.value for item in app.error)


def test_streamlit_reset_requires_typed_confirmation_and_uses_one_request(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch)
    reset_button = _element_with_label(app.button, "Reset evidence library")
    assert reset_button.disabled is True

    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(app.text_input, "Type RESET to confirm").input("RESET").run()
    reset_button = _element_with_label(app.button, "Reset evidence library")
    assert reset_button.disabled is False
    reset_button.click().run()

    deletes = [call for call in client.calls if call[0] == "DELETE"]
    assert len(deletes) == 1
    assert deletes[0][1].endswith("/v1/documents?confirmation=RESET")
    assert any("Deleted 2 evidence files" in item.value for item in app.success)
    assert not list(app.exception)


def test_streamlit_reset_explains_stale_api_without_delete_fallback(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch, reset_status=405)
    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(app.text_input, "Type RESET to confirm").input("RESET").run()
    _element_with_label(app.button, "Reset evidence library").click().run()

    deletes = [call for call in client.calls if call[0] == "DELETE"]
    assert len(deletes) == 1
    assert any("API is older than this frontend" in item.value for item in app.error)
    assert not list(app.success)
    assert not list(app.exception)


def test_streamlit_renders_query_quality_and_all_visual_region_locators(monkeypatch: Any) -> None:
    app, _client = _run_app(monkeypatch)
    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(app.text_area, "Question").input(
        "Summarize the localized impact evidence."
    ).run()
    _element_with_label(app.button, "Analyze evidence").click().run()

    text_values = [str(item.value) for item in app.text]
    caption_values = [str(item.value) for item in app.caption]
    assert "The reviewed evidence supports a localized impact." in text_values
    assert any(
        item.label == "Retrieval and source diversity" and item.value == "82%"
        for item in app.metric
    )
    assert any("not answer correctness" in value for value in caption_values)
    assert any("Source freshness: partial" in value for value in caption_values)
    assert any("Cross-source conflict: detected" in value for value in caption_values)
    assert any("Image region (x 10.0%-40.0%, y 20.0%-60.0%)" in value for value in caption_values)
    assert any("PDF page 7 region" in value for value in caption_values)
    assert any("Chart bar; element bar-2025" in value for value in caption_values)
    assert any("Video interval 12.5s to 18.0s" in value for value in caption_values)
    assert not list(app.exception)


def test_streamlit_explains_local_ocr_and_pixel_limitations(monkeypatch: Any) -> None:
    monkeypatch.setenv("CRISISWEAVE_UI_LOCAL_MODE", "true")

    app, _client = _run_app(monkeypatch)

    assert any("Local evidence mode" in item.value for item in app.info)
    assert any("pixel" in item.value.casefold() for item in app.info)
    assert not list(app.exception)


def test_streamlit_handles_202_submission_and_pending_result_without_answer_key(
    monkeypatch: Any,
) -> None:
    app, _client = _run_app(monkeypatch, query_status=202)
    _element_with_label(app.text_input, "Your scoped API key").input("local-dev-key").run()
    _element_with_label(app.text_area, "Question").input(
        "Should an evacuation order be issued?"
    ).run()
    _element_with_label(app.button, "Analyze evidence").click().run()

    assert any("Answer withheld for high risk review" in item.value for item in app.warning)
    assert any(
        "Operational decision requires independent approval" in str(item.value) for item in app.text
    )
    assert not list(app.exception)

    _element_with_label(app.button, "Check reviewed result").click().run()
    assert any("API error 409: Review is still pending" in item.value for item in app.error)
    assert not list(app.exception)


def test_streamlit_reviewer_can_inspect_approve_and_fetch_result(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch)
    _element_with_label(app.text_input, "Your scoped API key").input("reviewer-key").run()
    _element_with_label(app.button, "Refresh pending reviews").click().run()
    _element_with_label(app.button, "Inspect selected review").click().run()

    assert any(item.label == "Review confidence" and item.value == "61%" for item in app.metric)
    assert any("Source freshness: partial" in item.value for item in app.caption)
    assert any("Cross-source conflict: detected" in item.value for item in app.caption)
    assert _element_with_label(app.button, "Approve answer").disabled is True

    _element_with_label(app.text_area, "Decision rationale").input(
        "The cited evidence was independently checked."
    ).run()
    _element_with_label(app.button, "Approve answer").click().run()
    assert any("Review approved with an audit rationale" in item.value for item in app.success)

    _element_with_label(app.button, "Fetch approved result").click().run()
    assert any("Approved result fetched" in item.value for item in app.success)
    assert any(
        call[0] == "POST"
        and call[1].endswith(f"/v1/reviews/{REVIEW_ID}/decision")
        and call[2]["json"]
        == {
            "decision": "approve",
            "reason": "The cited evidence was independently checked.",
        }
        for call in client.calls
    )
    assert any(
        call[0] == "GET" and call[1].endswith(f"/v1/reviews/{REVIEW_ID}/result")
        for call in client.calls
    )
    assert not list(app.exception)


def test_streamlit_reviewer_can_reject_with_a_required_rationale(monkeypatch: Any) -> None:
    app, client = _run_app(monkeypatch)
    _element_with_label(app.text_input, "Your scoped API key").input("reviewer-key").run()
    _element_with_label(app.button, "Refresh pending reviews").click().run()
    _element_with_label(app.button, "Inspect selected review").click().run()
    _element_with_label(app.text_area, "Decision rationale").input(
        "Sources conflict on the operational threshold."
    ).run()
    _element_with_label(app.button, "Reject answer").click().run()

    assert any("Review rejected with an audit rationale" in item.value for item in app.success)
    assert any(
        call[0] == "POST"
        and call[2].get("json", {}).get("decision") == "reject"
        and call[2].get("json", {}).get("reason")
        == "Sources conflict on the operational threshold."
        for call in client.calls
    )
    assert not list(app.exception)


def test_streamlit_clears_review_state_on_403_and_surfaces_404(monkeypatch: Any) -> None:
    forbidden_app, _client = _run_app(monkeypatch, review_list_status=403)
    _element_with_label(forbidden_app.text_input, "Your scoped API key").input("viewer-key").run()
    _element_with_label(forbidden_app.button, "Refresh pending reviews").click().run()
    assert any(
        "API error 403: Review permission is required" in item.value for item in forbidden_app.error
    )
    assert not list(forbidden_app.exception)

    missing_app, _client = _run_app(monkeypatch, review_detail_status=404)
    _element_with_label(missing_app.text_input, "Your scoped API key").input("reviewer-key").run()
    _element_with_label(missing_app.button, "Refresh pending reviews").click().run()
    _element_with_label(missing_app.button, "Inspect selected review").click().run()
    assert any("API error 404: Review not found" in item.value for item in missing_app.error)
    assert not list(missing_app.exception)


def test_streamlit_clears_protected_review_content_when_identity_changes(monkeypatch: Any) -> None:
    app, _client = _run_app(monkeypatch)
    key_input = _element_with_label(app.text_input, "Your scoped API key")
    key_input.input("reviewer-key").run()
    _element_with_label(app.button, "Refresh pending reviews").click().run()
    _element_with_label(app.button, "Inspect selected review").click().run()
    assert any(item.label == "Review confidence" for item in app.metric)
    assert any(
        item.value == "The reviewed evidence supports a localized impact." for item in app.text
    )

    _element_with_label(app.text_input, "Your scoped API key").input("different-user-key").run()
    assert not any(item.label == "Review confidence" for item in app.metric)
    assert not any(
        item.value == "The reviewed evidence supports a localized impact." for item in app.text
    )
    assert not list(app.exception)
