from __future__ import annotations

import time
from unittest.mock import ANY, MagicMock

from fastapi.testclient import TestClient

from crisisweave.api import create_app
from crisisweave.config import Settings
from crisisweave.jobs import JobStateConflictError


def test_async_job_api_is_tenant_scoped_cancellable_and_deletable(settings: Settings) -> None:
    configured = settings.model_copy(update={"ingestion_worker_enabled": False})
    alpha = {"X-API-Key": "test-alpha-key"}
    beta = {"X-API-Key": "test-beta-key"}

    with TestClient(create_app(configured)) as client:
        unauthenticated = client.post(
            "/v1/ingestion-jobs",
            files={"file": ("incident.txt", b"queued evidence", "text/plain")},
        )
        assert unauthenticated.status_code == 401

        queued = client.post(
            "/v1/ingestion-jobs",
            headers=alpha,
            files={"file": ("incident.txt", b"queued evidence", "text/plain")},
        )
        assert queued.status_code == 202, queued.text
        payload = queued.json()
        job_id = payload["job"]["id"]
        assert payload["job"]["status"] == "queued"
        assert "tenant_id" not in payload["job"]
        assert "input_object_ref" not in payload["job"]

        assert client.get(f"/v1/ingestion-jobs/{job_id}", headers=alpha).status_code == 200
        assert client.get(f"/v1/ingestion-jobs/{job_id}", headers=beta).status_code == 404

        cancelled = client.post(f"/v1/ingestion-jobs/{job_id}/cancel", headers=alpha)
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        deleted = client.delete(f"/v1/ingestion-jobs/{job_id}", headers=alpha)
        assert deleted.status_code == 204
        assert client.get(f"/v1/ingestion-jobs/{job_id}", headers=alpha).status_code == 404


def test_embedded_development_worker_publishes_queued_document(settings: Settings) -> None:
    headers = {"X-API-Key": "test-alpha-key"}
    with TestClient(create_app(settings)) as client:
        queued = client.post(
            "/v1/ingestion-jobs",
            headers=headers,
            files={"file": ("field-report.txt", b"Cedar Ridge containment was 37 percent.")},
        )
        assert queued.status_code == 202, queued.text
        job = queued.json()["job"]
        deadline = time.monotonic() + 10
        while job["status"] not in {"succeeded", "cancelled", "dead_letter"}:
            assert time.monotonic() < deadline
            time.sleep(0.05)
            response = client.get(f"/v1/ingestion-jobs/{job['id']}", headers=headers)
            assert response.status_code == 200
            job = response.json()

        assert job["status"] == "succeeded"
        assert job["progress"] == 100
        document = client.get(f"/v1/documents/{job['document_id']}", headers=headers)
        assert document.status_code == 200
        assert document.json()["status"] == "ready"


def test_async_job_api_rejects_unsupported_media_without_queue_or_object(
    settings: Settings,
) -> None:
    configured = settings.model_copy(update={"ingestion_worker_enabled": False})
    headers = {"X-API-Key": "test-alpha-key"}
    with TestClient(create_app(configured)) as client:
        response = client.post(
            "/v1/ingestion-jobs",
            headers=headers,
            files={"file": ("payload.exe", b"unsupported text payload")},
        )

        assert response.status_code == 422
        assert "allowed extension" in response.json()["detail"]
        assert client.get("/v1/ingestion-jobs", headers=headers).json() == []
        job_root = configured.object_dir / "jobs"
        assert not job_root.exists() or not any(item.is_file() for item in job_root.rglob("*"))


def test_reset_timeout_never_starts_destructive_document_deletion(settings: Settings) -> None:
    configured = settings.model_copy(
        update={"ingestion_worker_enabled": False, "request_timeout_seconds": 90.0}
    )
    headers = {"X-API-Key": "test-alpha-key"}
    with TestClient(create_app(configured)) as client:
        reset = MagicMock(
            side_effect=JobStateConflictError(
                "Timed out waiting for active ingestion jobs to stop; reset was not run"
            )
        )
        delete_all = MagicMock()
        client.app.state.job_service.reset = reset
        client.app.state.container.ingestion.delete_all = delete_all

        response = client.delete(
            "/v1/documents?confirmation=RESET",
            headers=headers,
        )

        assert response.status_code == 409
        reset.assert_called_once_with(ANY, timeout_seconds=30.0)
        delete_all.assert_not_called()
