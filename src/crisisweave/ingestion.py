"""Idempotent, tenant-serialized, recoverable ingestion orchestration."""

from __future__ import annotations

import base64
import binascii
import importlib
import json
import math
import multiprocessing
import os
import shutil
import signal
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any, Protocol, cast

import httpx

from crisisweave.config import Settings
from crisisweave.embeddings import VisualEmbeddingConfig, build_visual_embedder
from crisisweave.extractors import ExtractionConfig, ExtractionResult, Extractor
from crisisweave.models import (
    ChartElementRegion,
    Chunk,
    Document,
    DocumentStatus,
    ImageBoundingBoxRegion,
    IngestionResult,
    Modality,
    PdfBoundingBoxRegion,
    RegionSource,
    VideoTimeRangeRegion,
)
from crisisweave.object_store import LocalObjectStore, ObjectStore
from crisisweave.observability import (
    collect_stage_observations,
    observed_operation,
    record_stage_observations,
    validate_stage_observations,
)
from crisisweave.security import (
    SecurityError,
    run_malware_scan,
    safe_filename,
    sha256_file,
    sniff_media_type,
)
from crisisweave.storage import MetadataStoreProtocol
from crisisweave.vector_store import EvidenceIndex, qdrant_filter_payload

_PDFIUM_GUARD = threading.RLock()


class IngestionCancelled(Exception):
    """Raised at a safe publication checkpoint after durable cancellation."""


class _PosixProcessApi(Protocol):
    """POSIX process APIs omitted from ``os`` stubs on Windows hosts."""

    def setsid(self) -> int: ...

    def getpgid(self, pid: int) -> int: ...

    def killpg(self, pgid: int, sig: int) -> None: ...


class _ResourceApi(Protocol):
    RLIMIT_AS: int
    RLIMIT_CPU: int

    def setrlimit(self, resource: int, limits: tuple[int, int]) -> None: ...


class _PosixSignalApi(Protocol):
    SIGKILL: int


_POSIX_PROCESS_API = cast(_PosixProcessApi, os)
_POSIX_SIGNAL_API = cast(_PosixSignalApi, signal)


def validate_remote_visual_vectors(
    payload: dict[str, object],
    chunks: list[Chunk],
    *,
    expected_fingerprint: str,
    expected_size: int,
) -> dict[str, list[float]]:
    raw_vectors = payload.get("visual_vectors")
    if (
        payload.get("embedding_fingerprint") != expected_fingerprint
        or payload.get("visual_vector_size") != expected_size
        or not isinstance(raw_vectors, dict)
    ):
        raise ValueError("parser embedding contract mismatch")
    expected_ids = {
        chunk.id
        for chunk in chunks
        if chunk.modality in {Modality.PDF_PAGE, Modality.IMAGE, Modality.VIDEO_FRAME}
        and chunk.artifact_path
    }
    if set(raw_vectors) != expected_ids:
        raise ValueError("parser visual-vector lineage mismatch")
    visual_vectors: dict[str, list[float]] = {}
    for chunk_id, raw_vector in raw_vectors.items():
        if not isinstance(chunk_id, str) or not isinstance(raw_vector, list):
            raise ValueError("invalid parser visual vector")
        if len(raw_vector) != expected_size:
            raise ValueError("invalid parser visual-vector dimension")
        vector: list[float] = []
        for item in raw_vector:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise ValueError("invalid parser visual-vector value")
            try:
                value = float(item)
            except OverflowError as exc:
                raise ValueError("invalid parser visual-vector value") from exc
            if not math.isfinite(value) or abs(value) > 1.0:
                raise ValueError("invalid parser visual-vector value")
            vector.append(value)
        norm = math.sqrt(sum(item * item for item in vector))
        if not 0.99 <= norm <= 1.01:
            raise ValueError("parser visual vector is not normalized")
        visual_vectors[chunk_id] = vector
    return visual_vectors


def ingestion_reservation_bytes(
    settings: Settings,
    *,
    input_size: int,
    additional_original_bytes: int,
) -> int:
    """Conservatively cover permanent and shared-scratch peaks on one filesystem."""
    del input_size
    return additional_original_bytes + settings.max_derived_bytes_per_document


def _extract_in_worker(
    connection: Any,
    parser_settings: ExtractionConfig,
    visual_embedding_config: VisualEmbeddingConfig | None,
    parser_worker_memory_bytes: int,
    extraction_timeout_seconds: int,
    path: str,
    media_type: str,
    tenant_id: str,
    document_id: str,
    source_name: str,
    source_uri: str | None,
    deadline: float,
) -> None:
    stage_observations: list[dict[str, str | float]] = []
    try:
        safe_environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "CUDA_VISIBLE_DEVICES",
                "HF_HUB_OFFLINE",
                "LANG",
                "LC_ALL",
                "LD_LIBRARY_PATH",
                "NVIDIA_VISIBLE_DEVICES",
                "OMP_NUM_THREADS",
                "PATH",
                "SYSTEMROOT",
                "TEMP",
                "TESSDATA_PREFIX",
                "TMP",
                "TMPDIR",
                "TRANSFORMERS_OFFLINE",
                "WINDIR",
            }
        }
        os.environ.clear()
        os.environ.update(safe_environment)
        if os.name == "posix":
            _POSIX_PROCESS_API.setsid()
        try:
            resource_api = cast(_ResourceApi, importlib.import_module("resource"))

            resource_api.setrlimit(
                resource_api.RLIMIT_AS,
                (parser_worker_memory_bytes, parser_worker_memory_bytes),
            )
            cpu_seconds = max(30, int(extraction_timeout_seconds))
            resource_api.setrlimit(
                resource_api.RLIMIT_CPU,
                (cpu_seconds, cpu_seconds + 5),
            )
        except (AttributeError, ImportError, OSError, ValueError) as exc:
            if os.name == "posix":
                raise RuntimeError("Parser resource limits could not be applied") from exc
        with collect_stage_observations() as stage_observations:
            result = Extractor(parser_settings).extract(
                Path(path),
                media_type=media_type,
                tenant_id=tenant_id,
                document_id=document_id,
                source_name=source_name,
                source_uri=source_uri,
                deadline=deadline,
            )
        visual_vectors: dict[str, list[float]] = {}
        visual_chunks = [
            chunk
            for chunk in result.chunks
            if chunk.modality in {Modality.PDF_PAGE, Modality.IMAGE, Modality.VIDEO_FRAME}
            and chunk.artifact_path
        ]
        if visual_embedding_config is not None and visual_chunks:
            visual_embedder = build_visual_embedder(visual_embedding_config)
            for chunk in visual_chunks:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Visual embedding exceeded the extraction budget")
                vector = visual_embedder.embed_visual_chunk(chunk)
                if len(vector) != visual_embedding_config.visual_size:
                    raise ValueError("Visual embedding dimension mismatch")
                if not all(math.isfinite(item) and abs(item) <= 1.0 for item in vector):
                    raise ValueError("Visual embedding contains an invalid value")
                norm = math.sqrt(sum(item * item for item in vector))
                if not 0.99 <= norm <= 1.01:
                    raise ValueError("Visual embedding is not normalized")
                visual_vectors[chunk.id] = vector
        encoded = json.dumps(
            {
                "ok": True,
                "chunks": [item.model_dump(mode="json") for item in result.chunks],
                "storm_events": result.storm_events,
                "warnings": result.warnings,
                "embedding_fingerprint": (
                    visual_embedding_config.fingerprint
                    if visual_embedding_config is not None
                    else None
                ),
                "visual_vector_size": (
                    visual_embedding_config.visual_size
                    if visual_embedding_config is not None
                    else None
                ),
                "visual_vectors": visual_vectors,
                "stage_observations": stage_observations,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        connection.send_bytes(encoded)
    except Exception as exc:
        connection.send_bytes(
            json.dumps(
                {
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "stage_observations": stage_observations,
                }
            ).encode("utf-8")
        )
    finally:
        connection.close()


class IngestionService:
    def __init__(
        self,
        settings: Settings,
        store: MetadataStoreProtocol,
        index: EvidenceIndex,
        extractor: Extractor,
        object_store: ObjectStore | None = None,
        *,
        reconcile_on_startup: bool = True,
    ) -> None:
        self.settings = settings
        self.store = store
        self.index = index
        self.extractor = extractor
        self.object_store = object_store or LocalObjectStore(
            settings.object_dir, settings.artifact_dir
        )
        self._tenant_locks = tuple(threading.RLock() for _ in range(64))
        self._object_guard = threading.RLock()
        self._disk_guard = threading.RLock()
        self._reserved_disk_bytes = 0
        if reconcile_on_startup:
            self.reconcile()

    def _lock_for(self, tenant_id: str) -> threading.RLock:
        return self._tenant_locks[int(tenant_id[:8], 16) % len(self._tenant_locks)]

    @contextmanager
    def tenant_operation(self, tenant_id: str) -> Iterator[None]:
        """Serialize a tenant operation locally and across PostgreSQL workers."""

        with self._lock_for(tenant_id), self.store.tenant_lock(tenant_id):
            yield

    def reserve_disk(self, requested_bytes: int) -> None:
        reservation = max(0, requested_bytes)
        with self._disk_guard:
            roots = {self.settings.data_dir.resolve()}
            for root in roots:
                free_bytes = shutil.disk_usage(root).free
                if (
                    free_bytes - self._reserved_disk_bytes
                    < self.settings.min_free_disk_bytes + reservation
                ):
                    raise SecurityError("Insufficient storage headroom for safe ingestion")
            self._reserved_disk_bytes += reservation

    def release_disk(self, reserved_bytes: int) -> None:
        with self._disk_guard:
            self._reserved_disk_bytes = max(0, self._reserved_disk_bytes - max(0, reserved_bytes))

    def _remove_local_artifact_directory(self, document_id: str) -> None:
        artifact_root = self.settings.artifact_dir.resolve()
        artifact_dir = (artifact_root / document_id).resolve()
        if artifact_dir.parent == artifact_root and artifact_dir.is_dir():
            shutil.rmtree(artifact_dir)

    def _remove_artifacts(
        self,
        tenant_id: str,
        document_id: str,
        references: list[str] | set[str] | None = None,
    ) -> None:
        object_references = (
            list(references)
            if references is not None
            else self.store.artifact_references(tenant_id, document_id)
        )
        for reference in sorted(set(object_references)):
            self.object_store.delete(reference)
        self._remove_local_artifact_directory(document_id)

    def _remove_unshared_original(self, sha256: str, object_ref: str | None) -> None:
        with self._object_guard:
            if object_ref:
                if self.store.object_reference_count(object_ref) > 0:
                    return
                self.object_store.delete(object_ref)
                return
            if self.store.sha_reference_count(sha256) > 0:
                return
            if self.settings.object_store_backend != "local":
                return
            # Compatibility cleanup for documents created before object_ref was persisted.
            original_dir = self.settings.object_dir / sha256[:2]
            if not original_dir.is_dir():
                return
            for original in original_dir.glob(f"{sha256}.*"):
                if original.resolve().parent == original_dir.resolve():
                    original.unlink(missing_ok=True)

    def _publish_artifacts(
        self,
        result: ExtractionResult,
        *,
        tenant_id: str,
        document_id: str,
        published: set[str],
    ) -> ExtractionResult:
        by_path: dict[str, str] = {}
        chunks: list[Chunk] = []
        for chunk in result.chunks:
            if not chunk.artifact_path:
                chunks.append(chunk)
                continue
            reference = by_path.get(chunk.artifact_path)
            if reference is None:
                source = Path(chunk.artifact_path)
                reference = self.object_store.put_artifact(
                    source,
                    tenant_id=tenant_id,
                    document_id=document_id,
                    filename=source.name,
                )
                published.add(reference)
                by_path[chunk.artifact_path] = reference
            chunks.append(chunk.model_copy(update={"artifact_path": reference}))
        return ExtractionResult(
            chunks=chunks,
            storm_events=result.storm_events,
            warnings=result.warnings,
            visual_vectors=result.visual_vectors,
        )

    def parser_healthcheck(self) -> bool:
        if not self.settings.parser_service_url:
            return self.settings.app_env != "production"
        token = self.settings.parser_service_token
        if token is None:
            return False
        try:
            with httpx.Client(timeout=3.0, follow_redirects=False, trust_env=False) as client:
                response = client.get(
                    f"{self.settings.parser_service_url.rstrip('/')}/health/ready",
                    headers={"X-Parser-Key": token.get_secret_value()},
                )
            if response.status_code != 200:
                return False
            payload = response.json()
            return bool(
                isinstance(payload, dict)
                and payload.get("status") == "ok"
                and payload.get("embedding_fingerprint") == self.index.embedder.fingerprint
                and payload.get("visual_vector_size") == self.index.embedder.visual_size
            )
        except (httpx.HTTPError, ValueError):
            return False

    def _extract_remote(
        self,
        object_path: Path,
        *,
        media_type: str,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
        deadline: float,
    ) -> ExtractionResult:
        service_url = self.settings.parser_service_url
        service_token = self.settings.parser_service_token
        if not service_url or not service_token:
            raise RuntimeError("The isolated parser service is not configured")
        payload = {
            "job_id": str(uuid.uuid4()),
            "input_filename": f"input{object_path.suffix.lower()}",
            "media_type": media_type,
            "tenant_id": tenant_id,
            "document_id": document_id,
            "source_name": source_name,
            "source_uri": source_uri,
            "expected_sha256": sha256_file(object_path),
            "expected_size_bytes": object_path.stat().st_size,
            "budget_seconds": max(1.0, deadline - time.monotonic()),
        }
        metadata = base64.urlsafe_b64encode(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        if len(metadata) > 16_384:
            raise SecurityError("Parser metadata exceeded its header budget")
        timeout_seconds = max(5.0, deadline - time.monotonic() + 10)
        try:
            with (
                object_path.open("rb") as input_stream,
                httpx.Client(
                    timeout=httpx.Timeout(timeout_seconds, connect=5.0),
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    "POST",
                    f"{service_url.rstrip('/')}/v1/extract",
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Parser-Key": service_token.get_secret_value(),
                        "X-Parser-Metadata": metadata,
                    },
                    content=input_stream,
                ) as response,
            ):
                if response.status_code == 422:
                    raise SecurityError("Isolated parser rejected the document")
                response.raise_for_status()
                body = bytearray()
                for block in response.iter_bytes():
                    if len(body) + len(block) > self.settings.max_extraction_ipc_bytes:
                        raise SecurityError("Parser response exceeded its byte limit")
                    body.extend(block)
        except SecurityError:
            raise
        except httpx.HTTPError as exc:
            raise RuntimeError("Isolated parser service failed") from exc
        try:
            response_payload = json.loads(body)
            if not isinstance(response_payload, dict):
                raise ValueError("non-object parser response")
            chunks = [Chunk.model_validate(item) for item in response_payload.get("chunks", [])]
            events = response_payload.get("storm_events", [])
            warnings = response_payload.get("warnings", [])
            raw_artifacts = response_payload.get("artifacts", {})
            if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
                raise ValueError("invalid parser records")
            if not isinstance(warnings, list) or not all(
                isinstance(item, str) for item in warnings
            ):
                raise ValueError("invalid parser warnings")
            if not isinstance(raw_artifacts, dict):
                raise ValueError("invalid parser artifacts")
            visual_vectors = validate_remote_visual_vectors(
                response_payload,
                chunks,
                expected_fingerprint=self.index.embedder.fingerprint,
                expected_size=self.index.embedder.visual_size,
            )
            stage_observations = validate_stage_observations(
                response_payload.get("stage_observations")
            )
            artifacts: dict[str, bytes] = {}
            total_artifact_bytes = 0
            for name, encoded in raw_artifacts.items():
                if (
                    not isinstance(name, str)
                    or safe_filename(name) != name
                    or not isinstance(encoded, str)
                ):
                    raise ValueError("invalid parser artifact")
                try:
                    content = base64.b64decode(encoded.encode("ascii"), validate=True)
                except (UnicodeEncodeError, binascii.Error) as exc:
                    raise ValueError("invalid parser artifact encoding") from exc
                total_artifact_bytes += len(content)
                if (
                    not content
                    or total_artifact_bytes > self.settings.max_derived_bytes_per_document
                ):
                    raise ValueError("excessive parser artifacts")
                artifacts[name] = content
            references = {chunk.artifact_path for chunk in chunks if chunk.artifact_path}
            if any(Path(reference).name != reference for reference in references):
                raise ValueError("invalid parser artifact reference")
            if set(artifacts) != references:
                raise ValueError("parser artifact lineage mismatch")
        except (TypeError, ValueError) as exc:
            raise SecurityError("Isolated parser returned invalid bounded JSON") from exc

        permanent_artifact_root = self.settings.artifact_dir / document_id
        published: dict[str, Path] = {}
        try:
            for name, content in artifacts.items():
                permanent_artifact_root.mkdir(parents=True, exist_ok=True)
                target = permanent_artifact_root / name
                temporary = target.with_name(f".{target.name}.{uuid.uuid4()}.tmp")
                try:
                    temporary.write_bytes(content)
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
                published[name] = target
        except Exception:
            if permanent_artifact_root.is_dir():
                shutil.rmtree(permanent_artifact_root)
            raise
        rewritten = [
            chunk.model_copy(update={"artifact_path": str(published[chunk.artifact_path])})
            if chunk.artifact_path
            else chunk
            for chunk in chunks
        ]
        record_stage_observations(stage_observations)
        return ExtractionResult(
            chunks=rewritten,
            storm_events=events,
            warnings=warnings,
            visual_vectors=visual_vectors,
        )

    def _derived_size(self, document_id: str, result: ExtractionResult) -> int:
        """Return a conservative quota estimate for artifacts, metadata, and vectors."""
        total = 0
        artifact_paths: set[Path] = set()
        for chunk in result.chunks:
            serialized = json.dumps(chunk.model_dump(mode="json"), ensure_ascii=False).encode(
                "utf-8"
            )
            total += len(serialized)
            total += len(
                json.dumps(qdrant_filter_payload(chunk), ensure_ascii=False).encode("utf-8")
            )
            total += self.settings.text_vector_size * 4
            if chunk.artifact_path:
                artifact_paths.add(Path(chunk.artifact_path).resolve())
                total += self.settings.visual_vector_size * 4
        total += len(json.dumps(result.storm_events, ensure_ascii=False).encode("utf-8"))
        artifact_root = (self.settings.artifact_dir / document_id).resolve()
        for artifact in artifact_paths:
            if not artifact.is_relative_to(artifact_root) or not artifact.is_file():
                raise SecurityError("Derived artifact escaped its document directory")
            total += artifact.stat().st_size
        return total

    def reconcile(self) -> None:
        """Process one bounded batch of interrupted publications without waiting on live tenants."""
        stale = self.store.list_documents_by_status(
            (
                DocumentStatus.PROCESSING,
                DocumentStatus.DELETING,
                DocumentStatus.CLEANUP_PENDING,
            )
        )
        for document in stale:
            with (
                self._lock_for(document.tenant_id),
                self.store.try_tenant_lock(document.tenant_id) as acquired,
            ):
                if not acquired:
                    continue
                current = self.store.get_document(document.tenant_id, document.id)
                if current is None or current.status not in {
                    DocumentStatus.PROCESSING,
                    DocumentStatus.DELETING,
                    DocumentStatus.CLEANUP_PENDING,
                }:
                    continue
                if current.status == DocumentStatus.DELETING:
                    self._delete_locked(current)
                    continue
                artifact_references = self.store.artifact_references(current.tenant_id, current.id)
                self.index.delete_document(current.tenant_id, current.id)
                self._remove_artifacts(current.tenant_id, current.id, artifact_references)
                self.store.reset_document_for_retry(current.tenant_id, current.id)
                error = (
                    "INGESTION_INTERRUPTED"
                    if current.status == DocumentStatus.PROCESSING
                    else current.error or "INDEX_CLEANUP_RECONCILED"
                )
                self.store.mark_document(
                    current.tenant_id,
                    current.id,
                    DocumentStatus.FAILED,
                    error=error,
                )
                self._remove_unshared_original(current.sha256, current.object_ref)

    def _extract(
        self,
        object_path: Path,
        *,
        media_type: str,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
        deadline: float,
    ) -> ExtractionResult:
        if self.settings.parser_service_url:
            result = self._extract_remote(
                object_path,
                media_type=media_type,
                tenant_id=tenant_id,
                document_id=document_id,
                source_name=source_name,
                source_uri=source_uri,
                deadline=deadline,
            )
            return self._validate_extracted(
                result,
                tenant_id=tenant_id,
                document_id=document_id,
                source_name=source_name,
                source_uri=source_uri,
            )
        if not self.settings.isolate_parsers:
            guard = _PDFIUM_GUARD if media_type == "application/pdf" else nullcontext()
            with guard:
                result = self.extractor.extract(
                    object_path,
                    media_type=media_type,
                    tenant_id=tenant_id,
                    document_id=document_id,
                    source_name=source_name,
                    source_uri=source_uri,
                    deadline=deadline,
                )
            return self._validate_extracted(
                result,
                tenant_id=tenant_id,
                document_id=document_id,
                source_name=source_name,
                source_uri=source_uri,
            )
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_extract_in_worker,
            args=(
                sender,
                ExtractionConfig.from_settings(self.settings),
                None,
                self.settings.parser_worker_memory_bytes,
                self.settings.extraction_timeout_seconds,
                str(object_path),
                media_type,
                tenant_id,
                document_id,
                source_name,
                source_uri,
                deadline,
            ),
        )
        process.start()
        sender.close()
        try:
            timeout = max(0.1, deadline - time.monotonic())
            if not receiver.poll(timeout):
                self._terminate_worker_tree(process)
                raise SecurityError("Parser worker exceeded its execution budget")
            raw_payload = receiver.recv_bytes(self.settings.max_extraction_ipc_bytes)
            process.join(timeout=5)
        except (EOFError, OSError) as exc:
            raise SecurityError("Parser worker failed closed") from exc
        finally:
            receiver.close()
            if process.is_alive():
                self._terminate_worker_tree(process)
        try:
            payload = json.loads(raw_payload)
            if not isinstance(payload, dict) or payload.get("ok") is not True:
                error_type = (
                    payload.get("error_type", "InvalidResult")
                    if isinstance(payload, dict)
                    else "InvalidResult"
                )
                raise SecurityError(f"Parser worker failed ({error_type})")
            chunks = [Chunk.model_validate(item) for item in payload.get("chunks", [])]
            events = payload.get("storm_events", [])
            warnings = payload.get("warnings", [])
            if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
                raise ValueError("invalid structured records")
            if not isinstance(warnings, list) or not all(
                isinstance(item, str) for item in warnings
            ):
                raise ValueError("invalid warnings")
            result = ExtractionResult(chunks=chunks, storm_events=events, warnings=warnings)
        except (TypeError, ValueError) as exc:
            raise SecurityError("Parser worker returned invalid bounded JSON") from exc
        return self._validate_extracted(
            result,
            tenant_id=tenant_id,
            document_id=document_id,
            source_name=source_name,
            source_uri=source_uri,
        )

    @staticmethod
    def _terminate_worker_tree(process: BaseProcess) -> None:
        if not process.is_alive():
            return
        if os.name == "posix":
            try:
                process_group = _POSIX_PROCESS_API.getpgid(process.pid or -1)
                if process_group == process.pid:
                    _POSIX_PROCESS_API.killpg(process_group, signal.SIGTERM)
                else:
                    process.terminate()
            except OSError:
                process.terminate()
        else:
            process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            if os.name == "posix":
                try:
                    process_group = _POSIX_PROCESS_API.getpgid(process.pid or -1)
                    if process_group == process.pid:
                        _POSIX_PROCESS_API.killpg(process_group, _POSIX_SIGNAL_API.SIGKILL)
                    else:
                        process.kill()
                except OSError:
                    process.kill()
            else:
                process.kill()
            process.join(timeout=5)

    def _validate_extracted(
        self,
        result: ExtractionResult,
        *,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
    ) -> ExtractionResult:
        if not 0 < len(result.chunks) <= self.settings.max_chunks_per_document:
            raise SecurityError("Parser returned an invalid evidence-unit count")
        if len(result.storm_events) > self.settings.max_structured_rows:
            raise SecurityError("Parser returned too many structured records")
        artifact_root = (self.settings.artifact_dir / document_id).resolve()
        total_characters = 0
        for ordinal, chunk in enumerate(result.chunks):
            expected_id = str(uuid.uuid5(uuid.UUID(document_id), f"chunk:{ordinal}"))
            if (
                chunk.id != expected_id
                or chunk.tenant_id != tenant_id
                or chunk.document_id != document_id
                or chunk.source_name != source_name
                or chunk.source_uri != source_uri
            ):
                raise SecurityError("Parser returned forged evidence lineage")
            total_characters += len(chunk.text)
            if total_characters > self.settings.max_extracted_chars_per_document:
                raise SecurityError("Parser returned excessive evidence text")
            if chunk.page is not None and not 1 <= chunk.page <= self.settings.max_pdf_pages:
                raise SecurityError("Parser returned an invalid page number")
            if chunk.timestamp_seconds is not None and (
                not math.isfinite(chunk.timestamp_seconds)
                or not 0 <= chunk.timestamp_seconds <= self.settings.max_video_seconds
            ):
                raise SecurityError("Parser returned an invalid timestamp")
            for region in chunk.regions:
                if region.source is not RegionSource.DERIVED_PROVENANCE:
                    raise SecurityError("Parser returned an unauthorized region source")
                if isinstance(region, ChartElementRegion):
                    raise SecurityError("Parser returned an inferred chart region")
                if (
                    isinstance(region, PdfBoundingBoxRegion)
                    and region.page > self.settings.max_pdf_pages
                ):
                    raise SecurityError("Parser returned an invalid PDF region page")
                if isinstance(region, VideoTimeRangeRegion) and (
                    region.end_seconds > self.settings.max_video_seconds
                ):
                    raise SecurityError("Parser returned an invalid video region range")
            if chunk.regions and not chunk.artifact_path:
                raise SecurityError("Parser returned a region without a derived artifact")
            if chunk.artifact_path and chunk.modality in {
                Modality.IMAGE,
                Modality.PDF_PAGE,
                Modality.VIDEO_FRAME,
            }:
                if len(chunk.regions) != 1:
                    raise SecurityError("Parser returned incomplete visual-region provenance")
                region = chunk.regions[0]
                bbox = (
                    region.bbox
                    if isinstance(
                        region,
                        (ImageBoundingBoxRegion, PdfBoundingBoxRegion, VideoTimeRangeRegion),
                    )
                    else None
                )
                if bbox is None or (
                    bbox.x_min != 0.0 or bbox.y_min != 0.0 or bbox.x_max != 1.0 or bbox.y_max != 1.0
                ):
                    raise SecurityError("Parser visual provenance must cover the full artifact")
            if len(json.dumps(chunk.metadata, ensure_ascii=False, default=str)) > 16_384:
                raise SecurityError("Parser returned oversized evidence metadata")
            if (
                len(
                    json.dumps(
                        [region.model_dump(mode="json") for region in chunk.regions],
                        ensure_ascii=False,
                    )
                )
                > 32_768
            ):
                raise SecurityError("Parser returned oversized grounding regions")
            if chunk.artifact_path:
                unresolved = Path(chunk.artifact_path)
                resolved = unresolved.resolve()
                if (
                    unresolved.is_symlink()
                    or not resolved.is_file()
                    or not resolved.is_relative_to(artifact_root)
                ):
                    raise SecurityError("Parser returned an unauthorized artifact path")
        warnings = [item[:300] for item in result.warnings[:20]]
        if result.visual_vectors is not None:
            expected_visual_ids = {
                chunk.id
                for chunk in result.chunks
                if chunk.modality in {Modality.PDF_PAGE, Modality.IMAGE, Modality.VIDEO_FRAME}
                and chunk.artifact_path
            }
            if set(result.visual_vectors) != expected_visual_ids:
                raise SecurityError("Parser returned incomplete visual-vector lineage")
        return ExtractionResult(
            chunks=result.chunks,
            storm_events=result.storm_events,
            warnings=warnings,
            visual_vectors=result.visual_vectors,
        )

    @observed_operation(
        "ingestion",
        "document",
        compute_cost_setting="ingestion_compute_cost_per_hour_usd",
    )
    def ingest_path(
        self,
        path: Path,
        *,
        tenant_id: str,
        filename: str,
        source_uri: str | None = None,
        progress_callback: Callable[[str, int], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> IngestionResult:
        def checkpoint(stage: str, progress: int) -> None:
            if cancel_requested is not None and cancel_requested():
                raise IngestionCancelled("Ingestion cancellation was requested")
            if progress_callback is not None:
                progress_callback(stage, progress)

        filename = safe_filename(filename)
        processing_deadline = time.monotonic() + self.settings.ingestion_timeout_seconds - 5
        size = path.stat().st_size
        if size <= 0 or size > self.settings.max_upload_bytes:
            raise SecurityError(
                f"File must be between 1 and {self.settings.max_upload_bytes} bytes"
            )
        checkpoint("validating", 10)
        media_type = sniff_media_type(path)
        run_malware_scan(path, self.settings, deadline=processing_deadline)
        sha256 = sha256_file(path)
        checkpoint("validated", 20)

        with self.tenant_operation(tenant_id):
            # A reset can cancel a claimed worker while it is validating outside this
            # guard. Re-check after entry so it cannot publish after the reset barrier.
            checkpoint("validated", 20)
            existing = self.store.find_document_by_sha(tenant_id, sha256)
            if existing and existing.status == DocumentStatus.READY:
                return IngestionResult(document=existing, deduplicated=True)
            if existing and existing.status == DocumentStatus.DELETING:
                raise SecurityError("The matching document is currently being deleted")

            document_count, storage_bytes = self.store.tenant_usage(tenant_id)
            if existing and existing.status != DocumentStatus.FAILED:
                document_count = max(0, document_count - 1)
                storage_bytes = max(
                    0,
                    storage_bytes - existing.size_bytes - existing.derived_size_bytes,
                )
            if document_count + 1 > self.settings.max_documents_per_tenant:
                raise SecurityError("Tenant document quota exceeded")
            if storage_bytes + size > self.settings.max_storage_bytes_per_tenant:
                raise SecurityError("Tenant storage quota exceeded")

            if existing:
                document_id = existing.id
                # A retry cannot publish over unknown old vectors; fail until cleanup succeeds.
                old_artifact_references = self.store.artifact_references(tenant_id, document_id)
                self.index.delete_document(tenant_id, document_id)
                self._remove_artifacts(tenant_id, document_id, old_artifact_references)
                self.store.reset_document_for_retry(tenant_id, document_id)
                document = self.store.get_document(tenant_id, document_id)
                if document is None:
                    raise RuntimeError("Document retry state disappeared")
            else:
                document_id = str(uuid.uuid4())
                document = Document(
                    id=document_id,
                    tenant_id=tenant_id,
                    filename=filename,
                    media_type=media_type,
                    sha256=sha256,
                    size_bytes=size,
                    status=DocumentStatus.PROCESSING,
                    source_uri=source_uri,
                )
                self.store.create_document(document)

            reservation_bytes = 0
            object_ref = document.object_ref
            published_artifact_references: set[str] = set()
            try:
                suffix = Path(filename).suffix.lower()
                additional_original_bytes = 0
                if self.settings.object_store_backend == "local":
                    local_object = (
                        self.settings.object_dir
                        / "tenants"
                        / tenant_id
                        / "originals"
                        / sha256[:2]
                        / f"{sha256}{suffix}"
                    )
                    additional_original_bytes = 0 if local_object.exists() else size
                requested_reservation = ingestion_reservation_bytes(
                    self.settings,
                    input_size=size,
                    additional_original_bytes=additional_original_bytes,
                )
                self.reserve_disk(requested_reservation)
                reservation_bytes = requested_reservation
                with self._object_guard:
                    object_ref = self.object_store.put_original(
                        path,
                        tenant_id=tenant_id,
                        sha256=sha256,
                        suffix=suffix,
                    )
                    self.store.set_document_object_ref(tenant_id, document_id, object_ref)

                checkpoint("extracting", 35)
                extraction_deadline = min(
                    processing_deadline,
                    time.monotonic() + self.settings.extraction_timeout_seconds,
                )
                extracted = self._extract(
                    path,
                    media_type=media_type,
                    tenant_id=tenant_id,
                    document_id=document_id,
                    source_name=filename,
                    source_uri=source_uri,
                    deadline=extraction_deadline,
                )
                checkpoint("extracted", 65)
                if not extracted.chunks:
                    raise SecurityError("No evidence units were extracted")
                derived_size = self._derived_size(document_id, extracted)
                if derived_size > self.settings.max_derived_bytes_per_document:
                    raise SecurityError("Derived-document quota exceeded")
                if storage_bytes + size + derived_size > self.settings.max_storage_bytes_per_tenant:
                    raise SecurityError("Tenant storage quota exceeded")
                if (
                    self.store.storm_event_count(tenant_id) + len(extracted.storm_events)
                    > self.settings.max_structured_rows_per_tenant
                ):
                    raise SecurityError("Tenant structured-record quota exceeded")
                if (
                    shutil.disk_usage(self.settings.data_dir).free
                    < self.settings.min_free_disk_bytes
                ):
                    raise SecurityError("Storage headroom was exhausted during ingestion")
                if self.settings.object_store_backend == "s3" and extracted.visual_vectors is None:
                    extracted.visual_vectors = {
                        chunk.id: self.index.embedder.embed_visual_chunk(chunk)
                        for chunk in extracted.chunks
                        if chunk.modality
                        in {Modality.IMAGE, Modality.PDF_PAGE, Modality.VIDEO_FRAME}
                        and chunk.artifact_path
                    }
                extracted = self._publish_artifacts(
                    extracted,
                    tenant_id=tenant_id,
                    document_id=document_id,
                    published=published_artifact_references,
                )
                checkpoint("persisting", 75)
                # All staged rows remain invisible until the final READY transition.
                self.store.replace_chunks(tenant_id, document_id, extracted.chunks)
                self.store.replace_storm_events(tenant_id, document_id, extracted.storm_events)
                checkpoint("indexing", 85)
                self.index.index(
                    extracted.chunks,
                    deadline=processing_deadline,
                    visual_vectors=extracted.visual_vectors,
                )
                if self.settings.object_store_backend == "s3":
                    self._remove_local_artifact_directory(document_id)
                checkpoint("publishing", 95)
                self.store.mark_document(
                    tenant_id,
                    document_id,
                    DocumentStatus.READY,
                    chunk_count=len(extracted.chunks),
                    derived_size_bytes=derived_size,
                    warnings=extracted.warnings,
                )
                checkpoint("ready", 100)
            except Exception as exc:
                cleanup_errors: list[str] = []
                cleanup_pending = False
                try:
                    self.index.delete_document(tenant_id, document_id)
                except Exception as cleanup_exc:
                    cleanup_pending = True
                    cleanup_errors.append(f"index cleanup: {type(cleanup_exc).__name__}")
                try:
                    artifact_references = set(published_artifact_references)
                    artifact_references.update(
                        self.store.artifact_references(tenant_id, document_id)
                    )
                    self._remove_artifacts(
                        tenant_id,
                        document_id,
                        artifact_references,
                    )
                except Exception as cleanup_exc:
                    cleanup_pending = True
                    cleanup_errors.append(f"object cleanup: {type(cleanup_exc).__name__}")
                try:
                    if cleanup_pending:
                        self.store.mark_document(
                            tenant_id,
                            document_id,
                            DocumentStatus.CLEANUP_PENDING,
                            error="INGESTION_CLEANUP_PENDING",
                        )
                    else:
                        self.store.reset_document_for_retry(tenant_id, document_id)
                        self.store.mark_document(
                            tenant_id,
                            document_id,
                            DocumentStatus.FAILED,
                            error=f"INGESTION_{type(exc).__name__.upper()}"[:80],
                        )
                        self._remove_unshared_original(sha256, object_ref)
                except Exception as cleanup_exc:
                    cleanup_pending = True
                    cleanup_errors.append(f"metadata cleanup: {type(cleanup_exc).__name__}")
                    # Preserve the strongest recoverable state if a partial cleanup occurred.
                    with suppress(Exception):
                        self.store.mark_document(
                            tenant_id,
                            document_id,
                            DocumentStatus.CLEANUP_PENDING,
                            error="INGESTION_CLEANUP_PENDING",
                        )
                try:
                    self.store.purge_failed_documents(
                        tenant_id, self.settings.max_failed_documents_per_tenant
                    )
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"failed-record cleanup: {type(cleanup_exc).__name__}")
                if cleanup_errors:
                    exc.add_note("; ".join(cleanup_errors))
                raise
            finally:
                if reservation_bytes:
                    self.release_disk(reservation_bytes)

            ready = self.store.get_document(tenant_id, document_id)
            if ready is None:
                raise RuntimeError("Ingested document disappeared from metadata store")
            return IngestionResult(document=ready)

    def _delete_locked(self, document: Document) -> bool:
        artifact_references = self.store.artifact_references(document.tenant_id, document.id)
        self.index.delete_document(document.tenant_id, document.id)
        self._remove_artifacts(document.tenant_id, document.id, artifact_references)
        with self._object_guard:
            deleted = self.store.delete_document(document.tenant_id, document.id)
            self._remove_unshared_original(document.sha256, document.object_ref)
        return deleted

    def delete(self, tenant_id: str, document_id: str) -> bool:
        with self.tenant_operation(tenant_id):
            document = self.store.get_document(tenant_id, document_id)
            if not document:
                return False
            if document.status != DocumentStatus.DELETING:
                self.store.mark_document(tenant_id, document_id, DocumentStatus.DELETING)
                document = document.model_copy(update={"status": DocumentStatus.DELETING})
            return self._delete_locked(document)

    def _delete_all_locked(self, tenant_id: str) -> int:
        deleted_count = 0
        while documents := self.store.list_documents(tenant_id, limit=500):
            for document in documents:
                if document.status != DocumentStatus.DELETING:
                    self.store.mark_document(tenant_id, document.id, DocumentStatus.DELETING)
                    document = document.model_copy(update={"status": DocumentStatus.DELETING})
                if self._delete_locked(document):
                    deleted_count += 1
        return deleted_count

    def reset_tenant(self, tenant_id: str, cancel_pending: Callable[[], None]) -> int:
        """Cancel new queue work and delete evidence at one tenant linearization point."""

        with self.tenant_operation(tenant_id):
            cancel_pending()
            return self._delete_all_locked(tenant_id)

    def delete_all(self, tenant_id: str) -> int:
        """Delete every document for one server-derived tenant under its ingestion lock."""

        with self.tenant_operation(tenant_id):
            return self._delete_all_locked(tenant_id)
