from __future__ import annotations

import base64
import json
import tempfile
import uuid
from pathlib import Path

import httpx
import pytest
from PIL import Image
from pydantic import SecretStr

from crisisweave.auth import tenant_identifier
from crisisweave.bootstrap import build_container
from crisisweave.config import Settings
from crisisweave.models import DocumentStatus
from crisisweave.parser_service import (
    ParserRequest,
    _decode_parser_metadata,
    _extract_job,
    create_parser_app,
)
from crisisweave.security import SecurityError, sha256_file


def _parser_settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        app_env="parser",
        data_dir=tmp_path / "parser-runtime",
        parser_service_token="parser-test-key-0123456789abcdef",
        model_local_files_only=True,
        transcription_provider="faster_whisper",
        tesseract_path="definitely-not-installed-tesseract",
    )


def _job(
    settings: Settings, content: bytes, suffix: str = ".txt"
) -> tuple[ParserRequest, Path, Path]:
    settings.ensure_directories()
    job_id = uuid.uuid4()
    document_id = uuid.uuid4()
    job_root = settings.data_dir / "private-test-jobs" / str(job_id)
    job_root.parent.mkdir()
    job_root.mkdir()
    input_path = job_root / f"input{suffix}"
    input_path.write_bytes(content)
    payload = ParserRequest(
        job_id=job_id,
        input_filename=input_path.name,
        media_type="text/plain",
        tenant_id=tenant_identifier("alpha"),
        document_id=document_id,
        source_name=f"evidence{suffix}",
        expected_sha256=sha256_file(input_path),
        expected_size_bytes=input_path.stat().st_size,
        budget_seconds=30,
    )
    return payload, input_path, job_root / "artifacts"


def _metadata(payload: ParserRequest) -> str:
    encoded = json.dumps(payload.model_dump(mode="json"), separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(encoded).decode("ascii")


def test_parser_service_auth_and_integrity_checks(tmp_path: Path) -> None:
    configured = _parser_settings(tmp_path)
    payload, input_path, artifact_root = _job(configured, b"isolated evidence")
    from fastapi.testclient import TestClient

    with TestClient(create_parser_app(configured)) as client:
        unauthorized = client.post("/v1/extract", content=b"isolated evidence")
        assert unauthorized.status_code == 401

    forged = payload.model_copy(update={"expected_sha256": "0" * 64})
    with pytest.raises(SecurityError, match="integrity"):
        _extract_job(configured, forged, input_path, artifact_root)


def test_parser_worker_happy_path_uses_killable_subprocess(tmp_path: Path) -> None:
    configured = _parser_settings(tmp_path)
    payload, input_path, artifact_root = _job(configured, b"isolated parser evidence")
    result = _extract_job(configured, payload, input_path, artifact_root)
    chunks = result["chunks"]
    assert isinstance(chunks, list) and chunks
    assert chunks[0]["text"] == "isolated parser evidence"


def test_text_job_does_not_load_missing_visual_model(tmp_path: Path) -> None:
    configured = _parser_settings(tmp_path).model_copy(
        update={
            "embedding_provider": "sentence_transformers",
            "visual_embedding_model": str(tmp_path / "missing-visual-model"),
        }
    )
    payload, input_path, artifact_root = _job(configured, b"text needs no visual decoder")
    result = _extract_job(configured, payload, input_path, artifact_root)
    assert result["visual_vectors"] == {}


def test_parser_startup_canary_rejects_unusable_visual_model(tmp_path: Path) -> None:
    configured = _parser_settings(tmp_path).model_copy(
        update={
            "embedding_provider": "sentence_transformers",
            "visual_embedding_model": str(tmp_path / "missing-visual-model"),
        }
    )
    from fastapi.testclient import TestClient

    with pytest.raises(SecurityError), TestClient(create_parser_app(configured)):
        pass


def test_api_remote_parser_streamed_transport_happy_path(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parser_settings = _parser_settings(tmp_path)
    configured = settings.model_copy(
        update={
            "parser_service_url": "http://parser.test:8001",
            "parser_service_token": SecretStr("parser-test-key-0123456789abcdef"),
            "max_concurrent_ingestions": 1,
        }
    )
    configured.ensure_directories()
    container = build_container(configured)
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _decode_parser_metadata(request.headers.get("X-Parser-Metadata"))
        content = request.read()
        with tempfile.TemporaryDirectory(prefix="parser-mock-") as private_root:
            root = Path(private_root)
            input_path = root / payload.input_filename
            input_path.write_bytes(content)
            result = _extract_job(parser_settings, payload, input_path, root / "artifacts")
        return httpx.Response(200, json=result)

    def client_factory(**kwargs: object) -> httpx.Client:
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("crisisweave.ingestion.httpx.Client", client_factory)
    image = tmp_path / "remote.png"
    Image.new("RGB", (16, 12), "red").save(image)
    try:
        document = container.ingestion.ingest_path(
            image,
            tenant_id=tenant_identifier("alpha"),
            filename=image.name,
        ).document
        assert document.status == DocumentStatus.READY
        chunks = container.store.get_chunks(
            tenant_identifier("alpha"),
            [item.id for item in container.index.search(tenant_identifier("alpha"), "red", 5)],
        )
        assert any(item.artifact_path and Path(item.artifact_path).is_file() for item in chunks)
    finally:
        container.close()


def test_parser_http_endpoint_rejects_body_integrity_mismatch(tmp_path: Path) -> None:
    configured = _parser_settings(tmp_path)
    payload, _, _ = _job(configured, b"expected")
    from fastapi.testclient import TestClient

    with TestClient(create_parser_app(configured)) as client:
        response = client.post(
            "/v1/extract",
            headers={
                "X-Parser-Key": "parser-test-key-0123456789abcdef",
                "X-Parser-Metadata": _metadata(payload),
                "Content-Type": "application/octet-stream",
            },
            content=b"tampered",
        )
    assert response.status_code == 422
