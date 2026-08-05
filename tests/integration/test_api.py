from __future__ import annotations

from fastapi.testclient import TestClient

from crisisweave.api import create_app


def test_health_auth_upload_query_and_tenant_isolation(settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        assert client.get("/v1/documents").status_code == 401
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"X-API-Key": "test-alpha-key"}).status_code == 200

        csv_content = (
            b"EVENT_ID,BEGIN_YEARMONTH,STATE,EVENT_TYPE,DAMAGE_PROPERTY\n"
            b"11,201701,TEXAS,Wildfire,1M\n"
        )
        uploaded = client.post(
            "/v1/documents",
            headers={"X-API-Key": "test-alpha-key"},
            files={"file": ("events.csv", csv_content, "application/octet-stream")},
        )
        assert uploaded.status_code == 201, uploaded.text
        document_id = uploaded.json()["document"]["id"]
        assert uploaded.headers["x-content-type-options"] == "nosniff"
        assert uploaded.headers["cache-control"] == "no-store"

        own = client.get(f"/v1/documents/{document_id}", headers={"X-API-Key": "test-alpha-key"})
        foreign = client.get(f"/v1/documents/{document_id}", headers={"X-API-Key": "test-beta-key"})
        assert own.status_code == 200
        assert foreign.status_code == 404

        queried = client.post(
            "/v1/query",
            headers={"X-API-Key": "test-alpha-key"},
            json={"query": "How many events occurred by state?", "top_k": 5},
        )
        assert queried.status_code == 200, queried.text
        assert queried.json()["citations"]
        assert any(
            citation["source_name"] == "events.csv" for citation in queried.json()["citations"]
        )
        assert queried.json()["request_id"]
        for evidence in queried.json()["evidence"]:
            assert "tenant_id" not in evidence
            assert "document_id" not in evidence
            assert "artifact_path" not in evidence
            assert "metadata" not in evidence


def test_request_models_reject_unknown_fields(settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/v1/query",
            headers={"X-API-Key": "test-alpha-key"},
            json={"query": "valid question", "tenant_id": "victim"},
        )
        assert response.status_code == 422

        excessive_modalities = client.post(
            "/v1/query",
            headers={"X-API-Key": "test-alpha-key"},
            json={"query": "valid question", "include_modalities": ["text"] * 8},
        )
        assert excessive_modalities.status_code == 422

        invalid_fields = {f"unexpected_{index}": index for index in range(100)}
        capped = client.post(
            "/v1/query",
            headers={"X-API-Key": "test-alpha-key"},
            json={"query": "valid question", **invalid_fields},
        )
        assert capped.status_code == 422
        assert len(capped.json()["detail"]) == 20


def test_reset_evidence_library_is_confirmed_idempotent_and_tenant_scoped(settings) -> None:
    with TestClient(create_app(settings)) as client:
        alpha_headers = {"X-API-Key": "test-alpha-key"}
        beta_headers = {"X-API-Key": "test-beta-key"}

        shared_content = b"Shared incident evidence for both tenants."
        alpha_uploads = (
            ("shared.txt", shared_content),
            ("alpha-only.txt", b"Evidence belonging only to alpha."),
        )
        alpha_ids: list[str] = []
        for filename, content in alpha_uploads:
            response = client.post(
                "/v1/documents",
                headers=alpha_headers,
                files={"file": (filename, content, "text/plain")},
            )
            assert response.status_code == 201, response.text
            alpha_ids.append(response.json()["document"]["id"])

        beta_upload = client.post(
            "/v1/documents",
            headers=beta_headers,
            files={"file": ("shared.txt", shared_content, "text/plain")},
        )
        assert beta_upload.status_code == 201, beta_upload.text
        beta_id = beta_upload.json()["document"]["id"]

        assert client.delete("/v1/documents?confirmation=RESET").status_code == 401
        assert client.delete("/v1/documents", headers=alpha_headers).status_code == 422
        assert (
            client.delete(
                "/v1/documents?confirmation=wrong",
                headers=alpha_headers,
            ).status_code
            == 422
        )

        reset = client.delete(
            "/v1/documents?confirmation=RESET",
            headers=alpha_headers,
        )
        assert reset.status_code == 200, reset.text
        assert reset.json() == {"deleted_count": 2}
        assert client.get("/v1/documents", headers=alpha_headers).json() == []
        for document_id in alpha_ids:
            assert (
                client.get(f"/v1/documents/{document_id}", headers=alpha_headers).status_code == 404
            )

        beta_document = client.get(f"/v1/documents/{beta_id}", headers=beta_headers)
        assert beta_document.status_code == 200
        assert beta_document.json()["filename"] == "shared.txt"

        repeated = client.delete(
            "/v1/documents?confirmation=RESET",
            headers=alpha_headers,
        )
        assert repeated.status_code == 200
        assert repeated.json() == {"deleted_count": 0}


def test_query_body_is_rejected_before_json_validation(settings) -> None:
    configured = settings.model_copy(update={"max_query_body_bytes": 1024})
    oversized_json = b'{"query":"' + (b"x" * 2000) + b'"}'
    with TestClient(create_app(configured)) as client:
        response = client.post(
            "/v1/query",
            headers={
                "X-API-Key": "test-alpha-key",
                "Content-Type": "application/json",
            },
            content=oversized_json,
        )

        assert response.status_code == 413
