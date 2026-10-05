"""Secret-free extraction worker API for the production parser trust zone."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import multiprocessing
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from crisisweave import __version__
from crisisweave.config import Settings, get_settings
from crisisweave.embeddings import VisualEmbeddingConfig
from crisisweave.extractors import ExtractionConfig
from crisisweave.ingestion import IngestionService, _extract_in_worker
from crisisweave.models import StrictModel
from crisisweave.observability import instrument_fastapi_app, validate_stage_observations
from crisisweave.security import (
    ALLOWED_MEDIA_TYPES,
    SecurityError,
    safe_filename,
    sha256_file,
    sniff_media_type,
)


class ParserRequest(StrictModel):
    job_id: uuid.UUID
    input_filename: str = Field(min_length=1, max_length=220)
    media_type: str = Field(min_length=1, max_length=100)
    tenant_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    document_id: uuid.UUID
    source_name: str = Field(min_length=1, max_length=180)
    source_uri: str | None = Field(default=None, max_length=1000)
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_size_bytes: int = Field(ge=1, le=1024**3)
    budget_seconds: float = Field(ge=1.0, le=3600.0)


def _decode_parser_metadata(candidate: str | None) -> ParserRequest:
    if not candidate or not 1 <= len(candidate) <= 16_384:
        raise SecurityError("Parser metadata header is missing or excessive")
    try:
        decoded = base64.b64decode(candidate.encode("ascii"), altchars=b"-_", validate=True)
        payload = json.loads(decoded)
        return ParserRequest.model_validate(payload)
    except (
        UnicodeEncodeError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
        ValueError,
    ):
        raise SecurityError("Parser metadata header is invalid") from None


async def _receive_parser_input(
    request: Request,
    payload: ParserRequest,
    input_path: Path,
    *,
    chunk_timeout_seconds: float,
) -> None:
    digest = hashlib.sha256()
    received = 0
    deadline = time.monotonic() + payload.budget_seconds
    stream = request.stream().__aiter__()
    with input_path.open("xb") as output:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SecurityError("Parser upload budget was exhausted")
            try:
                block = await asyncio.wait_for(
                    anext(stream), timeout=min(remaining, chunk_timeout_seconds)
                )
            except StopAsyncIteration:
                break
            except TimeoutError:
                raise SecurityError("Parser upload stalled") from None
            if not block:
                continue
            received += len(block)
            if received > payload.expected_size_bytes:
                raise SecurityError("Parser input integrity check failed")
            digest.update(block)
            output.write(block)
    if received != payload.expected_size_bytes or digest.hexdigest() != payload.expected_sha256:
        raise SecurityError("Parser input integrity check failed")


def _authorized(candidate: str | None, settings: Settings) -> bool:
    secret = settings.parser_service_token
    return bool(
        candidate
        and secret
        and hmac.compare_digest(candidate.encode(), secret.get_secret_value().encode())
    )


def _extract_job(
    settings: Settings,
    payload: ParserRequest,
    input_path: Path,
    artifact_root: Path,
) -> dict[str, object]:
    deadline = time.monotonic() + min(
        payload.budget_seconds,
        float(settings.extraction_timeout_seconds),
    )
    if Path(payload.input_filename).name != payload.input_filename:
        raise SecurityError("Parser input filename is invalid")
    if payload.media_type not in ALLOWED_MEDIA_TYPES:
        raise SecurityError("Parser media type is not allowed")
    if safe_filename(payload.source_name) != payload.source_name:
        raise SecurityError("Parser source name is invalid")

    if (
        input_path.name != payload.input_filename
        or input_path.is_symlink()
        or not input_path.is_file()
        or input_path.stat().st_size != payload.expected_size_bytes
        or sha256_file(input_path) != payload.expected_sha256
    ):
        raise SecurityError("Parser input integrity check failed")
    if sniff_media_type(input_path) != payload.media_type:
        raise SecurityError("Parser media type does not match the input")
    if time.monotonic() >= deadline:
        raise SecurityError("Parser job budget was exhausted during validation")

    artifact_root.mkdir(mode=0o700)
    parser_config = ExtractionConfig.from_settings(settings, artifact_dir=artifact_root)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_extract_in_worker,
        args=(
            sender,
            parser_config,
            VisualEmbeddingConfig.from_settings(settings),
            settings.parser_worker_memory_bytes,
            settings.extraction_timeout_seconds,
            str(input_path),
            payload.media_type,
            payload.tenant_id,
            str(payload.document_id),
            payload.source_name,
            payload.source_uri,
            deadline,
        ),
    )
    process.start()
    sender.close()
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receiver.poll(remaining):
            IngestionService._terminate_worker_tree(process)
            raise SecurityError("Parser worker exceeded its execution budget")
        raw_result = receiver.recv_bytes(settings.max_extraction_ipc_bytes)
        process.join(timeout=5)
    except (EOFError, OSError) as exc:
        raise SecurityError("Parser worker failed closed") from exc
    finally:
        receiver.close()
        if process.is_alive():
            IngestionService._terminate_worker_tree(process)
    try:
        result = json.loads(raw_result)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError("Parser worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise SecurityError("Parser worker returned invalid output")
    try:
        stage_observations = validate_stage_observations(result.get("stage_observations"))
    except ValueError as exc:
        raise SecurityError("Parser worker returned invalid timing data") from exc
    if result.get("ok") is not True:
        raise SecurityError("Parser worker rejected the document")
    raw_chunks = result.get("chunks", [])
    if not isinstance(raw_chunks, list):
        raise SecurityError("Parser worker returned invalid chunks")
    allowed_artifact_root = (artifact_root / str(payload.document_id)).resolve()
    artifact_budget = min(
        settings.max_derived_bytes_per_document,
        settings.max_extraction_ipc_bytes // 2,
    )
    artifact_bytes = 0
    artifacts: dict[str, str] = {}
    chunks: list[dict[str, object]] = []
    for raw_chunk in raw_chunks:
        if not isinstance(raw_chunk, dict):
            raise SecurityError("Parser worker returned invalid chunks")
        chunk = dict(raw_chunk)
        raw_reference = chunk.get("artifact_path")
        if raw_reference is not None:
            if not isinstance(raw_reference, str):
                raise SecurityError("Parser worker returned an invalid artifact")
            artifact = Path(raw_reference)
            resolved = artifact.resolve()
            if (
                artifact.is_symlink()
                or resolved.parent != allowed_artifact_root
                or not resolved.is_file()
                or safe_filename(resolved.name) != resolved.name
            ):
                raise SecurityError("Parser worker returned an unauthorized artifact")
            if resolved.name not in artifacts:
                content = resolved.read_bytes()
                artifact_bytes += len(content)
                if not content or artifact_bytes > artifact_budget:
                    raise SecurityError("Parser artifacts exceeded the response budget")
                artifacts[resolved.name] = base64.b64encode(content).decode("ascii")
            chunk["artifact_path"] = resolved.name
        chunks.append(chunk)
    response: dict[str, object] = {
        "chunks": chunks,
        "storm_events": result.get("storm_events", []),
        "warnings": result.get("warnings", []),
        "embedding_fingerprint": result.get("embedding_fingerprint"),
        "visual_vector_size": result.get("visual_vector_size"),
        "visual_vectors": result.get("visual_vectors", {}),
        "stage_observations": stage_observations,
        "artifacts": artifacts,
    }
    if (
        len(json.dumps(response, ensure_ascii=False).encode("utf-8"))
        > settings.max_extraction_ipc_bytes
    ):
        raise SecurityError("Parser response exceeded its byte limit")
    return response


def _verify_parser_child(settings: Settings, visual_config: VisualEmbeddingConfig) -> None:
    """Run one disposable pixel-to-vector canary under the real child limits."""
    settings.ensure_directories()
    job_id = uuid.uuid4()
    document_id = uuid.uuid4()
    red_png = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AA"
        "AAMBAQDJ/pLvAAAAAElFTkSuQmCC"
    )
    with tempfile.TemporaryDirectory(prefix="crisisweave-parser-canary-") as private_root:
        root = Path(private_root)
        input_path = root / "canary.png"
        input_path.write_bytes(base64.b64decode(red_png, validate=True))
        request = ParserRequest(
            job_id=job_id,
            input_filename=input_path.name,
            media_type="image/png",
            tenant_id="0" * 32,
            document_id=document_id,
            source_name="canary.png",
            expected_sha256=sha256_file(input_path),
            expected_size_bytes=input_path.stat().st_size,
            budget_seconds=min(120.0, float(settings.extraction_timeout_seconds)),
        )
        result = _extract_job(settings, request, input_path, root / "artifacts")
        vectors = result.get("visual_vectors")
        if (
            result.get("embedding_fingerprint") != visual_config.fingerprint
            or result.get("visual_vector_size") != visual_config.visual_size
            or not isinstance(vectors, dict)
            or len(vectors) != 1
        ):
            raise RuntimeError("Parser child visual capability canary failed")


def create_parser_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    if runtime_settings.app_env != "parser":
        raise RuntimeError("The parser service requires CRISISWEAVE_APP_ENV=parser")
    visual_config = VisualEmbeddingConfig.from_settings(runtime_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await asyncio.to_thread(_verify_parser_child, runtime_settings, visual_config)
        app.state.extraction_slot = threading.BoundedSemaphore(1)
        yield

    app = FastAPI(
        title="CrisisWeave isolated parser",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    instrument_fastapi_app(app, runtime_settings)

    @app.exception_handler(SecurityError)
    async def security_error(_request: Request, _exc: SecurityError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "Parser rejected the job"})

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Parser job failed"})

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/health/ready")
    async def ready(
        x_parser_key: Annotated[str | None, Header(alias="X-Parser-Key")] = None,
    ) -> dict[str, str | int]:
        if not _authorized(x_parser_key, runtime_settings):
            raise HTTPException(status_code=401, detail="Invalid parser service key")
        required = (
            runtime_settings.ffmpeg_path,
            runtime_settings.ffprobe_path,
            runtime_settings.tesseract_path,
        )
        if any(not shutil.which(item) for item in required):
            raise HTTPException(status_code=503, detail="Parser executable unavailable")
        model_directory_exists = await asyncio.to_thread(
            Path(runtime_settings.whisper_model).is_dir
        )
        if not model_directory_exists:
            raise HTTPException(status_code=503, detail="Parser transcription model unavailable")
        return {
            "status": "ok",
            "version": __version__,
            "embedding_fingerprint": visual_config.fingerprint,
            "visual_vector_size": visual_config.visual_size,
        }

    @app.post("/v1/extract")
    async def extract(
        request: Request,
        x_parser_key: Annotated[str | None, Header(alias="X-Parser-Key")] = None,
        x_parser_metadata: Annotated[str | None, Header(alias="X-Parser-Metadata")] = None,
    ) -> dict[str, object]:
        if not _authorized(x_parser_key, runtime_settings):
            raise HTTPException(status_code=401, detail="Invalid parser service key")
        payload = _decode_parser_metadata(x_parser_metadata)
        request_deadline = time.monotonic() + payload.budget_seconds
        acquired = await asyncio.to_thread(
            request.app.state.extraction_slot.acquire, True, payload.budget_seconds
        )
        if not acquired:
            raise HTTPException(status_code=503, detail="Parser capacity exhausted")
        try:
            remaining = request_deadline - time.monotonic()
            if remaining < 1.0:
                raise HTTPException(status_code=504, detail="Parser job budget was exhausted")
            bounded_payload = payload.model_copy(update={"budget_seconds": remaining})
            with tempfile.TemporaryDirectory(prefix="crisisweave-parser-request-") as private_root:
                root = Path(private_root)
                input_path = root / bounded_payload.input_filename
                await _receive_parser_input(
                    request,
                    bounded_payload,
                    input_path,
                    chunk_timeout_seconds=runtime_settings.body_chunk_timeout_seconds,
                )
                return await asyncio.to_thread(
                    _extract_job,
                    runtime_settings,
                    bounded_payload,
                    input_path,
                    root / "artifacts",
                )
        finally:
            request.app.state.extraction_slot.release()

    return app
