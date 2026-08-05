"""Bounded extraction for text, PDFs, images, videos, and NOAA-style tables."""

from __future__ import annotations

import csv
import importlib.util
import json
import math
import multiprocessing
import os
import re
import shutil

# Extractors use fixed executable/argument arrays and never enable a shell.
import subprocess  # nosec B404
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pypdfium2 as pdfium
from PIL import Image, ImageOps

from crisisweave.config import Settings
from crisisweave.models import (
    Chunk,
    GroundingRegion,
    ImageBoundingBoxRegion,
    Modality,
    NormalizedBoundingBox,
    PdfBoundingBoxRegion,
    RegionSource,
    VideoTimeRangeRegion,
)
from crisisweave.observability import observe_stage
from crisisweave.security import SecurityError, assess_prompt, validate_image


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def _transcribe_worker(
    connection: Any,
    model_path: str,
    media_path: str,
    local_files_only: bool,
    max_segments: int,
    max_characters: int,
) -> None:
    try:
        from faster_whisper import WhisperModel

        model = WhisperModel(
            model_path,
            device="cpu",
            compute_type="int8",
            local_files_only=local_files_only,
        )
        segments, _ = model.transcribe(media_path, vad_filter=True, beam_size=1)
        bounded_segments: list[list[float | str]] = []
        characters = 0
        for item in segments:
            text = item.text.strip()
            characters += len(text)
            if len(bounded_segments) >= max_segments or characters > max_characters:
                raise ValueError("transcription output exceeded its budget")
            bounded_segments.append([float(item.start), text])
        connection.send_bytes(
            json.dumps({"ok": True, "segments": bounded_segments}).encode("utf-8")
        )
    except Exception as exc:
        connection.send_bytes(
            json.dumps({"ok": False, "error_type": type(exc).__name__}).encode("utf-8")
        )
    finally:
        connection.close()


@dataclass
class ExtractionResult:
    chunks: list[Chunk] = field(default_factory=list)
    storm_events: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # A non-None mapping means a remote, isolated parser computed every visual
    # vector. Keeping vectors out of Chunk prevents them from entering metadata
    # rows, Qdrant payloads, citations, or public API responses.
    visual_vectors: dict[str, list[float]] | None = None


@dataclass
class ExtractionBudget:
    characters: int = 0
    chunks: int = 0
    derived_bytes: int = 0
    deadline: float = float("inf")


@dataclass(frozen=True)
class ExtractionConfig:
    """Secret-free parser configuration safe to pass across a process boundary."""

    artifact_dir: Path
    chunk_chars: int
    chunk_overlap_chars: int
    command_timeout_seconds: int
    extraction_timeout_seconds: int
    ffmpeg_path: str
    ffprobe_path: str
    max_chunks_per_document: int
    max_derived_bytes_per_document: int
    max_extracted_chars_per_document: int
    max_extraction_ipc_bytes: int
    max_image_pixels: int
    max_pdf_pages: int
    max_structured_cell_chars: int
    max_structured_rows: int
    max_video_dimension: int
    max_video_frames: int
    max_video_seconds: int
    model_local_files_only: bool
    tesseract_path: str
    transcription_provider: str
    transcription_timeout_seconds: int
    video_frame_interval_seconds: int
    whisper_model: str
    # Windows Runtime OCR is a zero-download convenience for the single-process
    # development launcher. Production/parser workers keep using Tesseract.
    windows_ocr_fallback: bool = False

    @classmethod
    def from_settings(
        cls, settings: Settings, *, artifact_dir: Path | None = None
    ) -> ExtractionConfig:
        return cls(
            artifact_dir=artifact_dir or settings.artifact_dir,
            chunk_chars=settings.chunk_chars,
            chunk_overlap_chars=settings.chunk_overlap_chars,
            command_timeout_seconds=settings.command_timeout_seconds,
            extraction_timeout_seconds=settings.extraction_timeout_seconds,
            ffmpeg_path=settings.ffmpeg_path,
            ffprobe_path=settings.ffprobe_path,
            max_chunks_per_document=settings.max_chunks_per_document,
            max_derived_bytes_per_document=settings.max_derived_bytes_per_document,
            max_extracted_chars_per_document=settings.max_extracted_chars_per_document,
            max_extraction_ipc_bytes=settings.max_extraction_ipc_bytes,
            max_image_pixels=settings.max_image_pixels,
            max_pdf_pages=settings.max_pdf_pages,
            max_structured_cell_chars=settings.max_structured_cell_chars,
            max_structured_rows=settings.max_structured_rows,
            max_video_dimension=settings.max_video_dimension,
            max_video_frames=settings.max_video_frames,
            max_video_seconds=settings.max_video_seconds,
            model_local_files_only=settings.model_local_files_only,
            tesseract_path=settings.tesseract_path,
            transcription_provider=settings.transcription_provider,
            transcription_timeout_seconds=settings.transcription_timeout_seconds,
            video_frame_interval_seconds=settings.video_frame_interval_seconds,
            whisper_model=settings.whisper_model,
            windows_ocr_fallback=settings.app_env == "development",
        )


def bounded_render_dimensions(
    width: float, height: float, scale: float, max_pixels: int
) -> tuple[int, int]:
    if not math.isfinite(float(width)) or not math.isfinite(float(height)):
        raise SecurityError("PDF page dimensions exceed the image-pixel limit")
    scaled_width = float(width) * scale
    scaled_height = float(height) * scale
    if (
        not math.isfinite(scaled_width)
        or not math.isfinite(scaled_height)
        or scaled_width <= 0
        or scaled_height <= 0
        or scaled_width > max_pixels
        or scaled_height > max_pixels
    ):
        raise SecurityError("PDF page dimensions exceed the image-pixel limit")
    rendered_width = math.ceil(scaled_width)
    rendered_height = math.ceil(scaled_height)
    if rendered_width <= 0 or rendered_height <= 0 or rendered_width * rendered_height > max_pixels:
        raise SecurityError("PDF page dimensions exceed the image-pixel limit")
    return rendered_width, rendered_height


class Extractor:
    def __init__(self, settings: Settings | ExtractionConfig) -> None:
        self.settings = settings

    def extract(
        self,
        path: Path,
        *,
        media_type: str,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
        deadline: float | None = None,
    ) -> ExtractionResult:
        common = {
            "tenant_id": tenant_id,
            "document_id": document_id,
            "source_name": source_name,
            "source_uri": source_uri,
            "budget": ExtractionBudget(
                deadline=deadline
                if deadline is not None
                else time.monotonic() + self.settings.extraction_timeout_seconds
            ),
        }
        if media_type == "application/pdf":
            return self._pdf(path, **common)
        if media_type.startswith("image/"):
            return self._image(path, **common)
        if media_type.startswith("video/"):
            return self._video(path, **common)
        if media_type == "text/csv":
            return self._csv(path, **common)
        if media_type == "application/json":
            return self._json(path, **common)
        if media_type == "text/plain" and path.suffix.lower() in {".srt", ".vtt"}:
            return self._captions(path, **common)
        if media_type == "text/plain":
            return self._text(path, **common)
        raise SecurityError(f"No extractor is available for {media_type}")

    @staticmethod
    def _remaining(budget: ExtractionBudget, maximum: float) -> float:
        remaining = budget.deadline - time.monotonic()
        if remaining <= 0:
            raise SecurityError("Document extraction exceeded its execution budget")
        return max(0.1, min(maximum, remaining))

    @staticmethod
    def _chunk_id(document_id: str, ordinal: int) -> str:
        return str(uuid.uuid5(uuid.UUID(document_id), f"chunk:{ordinal}"))

    @staticmethod
    def _full_visual_box() -> NormalizedBoundingBox:
        """Return a provenance locator for the full derived visual, not an entailment box."""

        return NormalizedBoundingBox(x_min=0.0, y_min=0.0, x_max=1.0, y_max=1.0)

    def _chunks_from_text(
        self,
        text: str,
        *,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
        modality: Modality = Modality.TEXT,
        page: int | None = None,
        timestamp_seconds: float | None = None,
        artifact_path: str | None = None,
        start_ordinal: int = 0,
        metadata: dict[str, Any] | None = None,
        regions: list[GroundingRegion] | None = None,
        budget: ExtractionBudget,
    ) -> list[Chunk]:
        cleaned = re.sub(r"[ \t]+", " ", text.replace("\x00", " "))
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        self._remaining(budget, 1.0)
        budget.characters += len(cleaned)
        if budget.characters > self.settings.max_extracted_chars_per_document:
            raise SecurityError("Document exceeds the extracted-character limit")
        if not cleaned and not artifact_path:
            return []
        pieces: list[str] = []
        if len(cleaned) <= self.settings.chunk_chars:
            pieces = [cleaned]
        else:
            cursor = 0
            while cursor < len(cleaned):
                end = min(len(cleaned), cursor + self.settings.chunk_chars)
                if end < len(cleaned):
                    boundary = max(
                        cleaned.rfind("\n", cursor, end),
                        cleaned.rfind(". ", cursor, end),
                    )
                    if boundary > cursor + self.settings.chunk_chars // 2:
                        end = boundary + 1
                pieces.append(cleaned[cursor:end].strip())
                if end >= len(cleaned):
                    break
                next_cursor = end - self.settings.chunk_overlap_chars
                cursor = max(cursor + 1, next_cursor)
        chunks: list[Chunk] = []
        budget.chunks += len([piece for piece in pieces if piece or artifact_path])
        if budget.chunks > self.settings.max_chunks_per_document:
            raise SecurityError("Document exceeds the evidence-unit limit")
        for index, piece in enumerate(piece for piece in pieces if piece or artifact_path):
            assessment = assess_prompt(piece)
            source_assessment = assess_prompt(source_name)
            item_metadata = dict(metadata or {})
            if assessment.suspicious or source_assessment.suspicious:
                item_metadata["prompt_injection_suspected"] = True
            chunks.append(
                Chunk(
                    id=self._chunk_id(document_id, start_ordinal + index),
                    tenant_id=tenant_id,
                    document_id=document_id,
                    source_name=source_name,
                    source_uri=source_uri,
                    modality=modality,
                    text=assessment.sanitized,
                    page=page,
                    timestamp_seconds=timestamp_seconds,
                    artifact_path=artifact_path if index == 0 else None,
                    metadata=item_metadata,
                    regions=list(regions or []) if index == 0 else [],
                )
            )
        return chunks

    def _ocr(self, image_path: Path, budget: ExtractionBudget) -> tuple[str, str | None]:
        with observe_stage("ocr"):
            return self._ocr_unobserved(image_path, budget)

    def _ocr_unobserved(self, image_path: Path, budget: ExtractionBudget) -> tuple[str, str | None]:
        texts, warning = self._ocr_many_unobserved([image_path], budget)
        return texts.get(str(image_path.resolve()), ""), warning

    def _ocr_many(
        self, image_paths: list[Path], budget: ExtractionBudget
    ) -> tuple[dict[str, str], str | None]:
        with observe_stage("ocr"):
            return self._ocr_many_unobserved(image_paths, budget)

    def _ocr_many_unobserved(
        self, image_paths: list[Path], budget: ExtractionBudget
    ) -> tuple[dict[str, str], str | None]:
        if not image_paths:
            return {}, None
        executable = shutil.which(self.settings.tesseract_path)
        if executable:
            texts: dict[str, str] = {}
            failed = False
            for image_path in image_paths:
                try:
                    result = subprocess.run(  # noqa: S603  # nosec B603
                        [executable, str(image_path), "stdout", "--psm", "3"],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=self._remaining(
                            budget,
                            min(float(self.settings.command_timeout_seconds), 60.0),
                        ),
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    failed = True
                    continue
                if result.returncode != 0:
                    failed = True
                    continue
                text = result.stdout.strip()
                if text:
                    texts[str(image_path.resolve())] = text
            return texts, "OCR failed for one or more images" if failed else None

        if self._windows_ocr_enabled():
            return self._windows_ocr(image_paths, budget)
        return {}, "Tesseract is unavailable; OCR was skipped"

    def _windows_ocr_enabled(self) -> bool:
        if os.name != "nt":
            return False
        configured = getattr(self.settings, "windows_ocr_fallback", None)
        if configured is not None:
            return bool(configured)
        return getattr(self.settings, "app_env", None) == "development"

    def _windows_ocr(
        self, image_paths: list[Path], budget: ExtractionBudget
    ) -> tuple[dict[str, str], str | None]:
        helper = Path(__file__).resolve().parents[2] / "scripts" / "windows_ocr.ps1"
        powershell = shutil.which("powershell.exe")
        artifact_root = self.settings.artifact_dir.resolve()
        resolved_paths = [path.resolve() for path in image_paths]
        if (
            not powershell
            or not helper.is_file()
            or any(
                path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff"}
                or not path.is_relative_to(artifact_root)
                for path in resolved_paths
            )
        ):
            return {}, "Windows OCR fallback is unavailable; OCR was skipped"

        parents = {path.parent for path in resolved_paths}
        if len(parents) == 1 and len(resolved_paths) > 1:
            target_arguments = ["-DirectoryPath", str(next(iter(parents)))]
        else:
            target_arguments = ["-ImagePath", str(resolved_paths[0])]
        command = [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper),
            *target_arguments,
        ]
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._remaining(
                    budget,
                    min(float(self.settings.command_timeout_seconds), 180.0),
                ),
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}, "Windows OCR failed or timed out"
        if (
            result.returncode != 0
            or not result.stdout
            or len(result.stdout.encode("utf-8")) > self.settings.max_extraction_ipc_bytes
        ):
            return {}, "Windows OCR returned an error"
        try:
            payload = json.loads(result.stdout)
        except (TypeError, ValueError):
            return {}, "Windows OCR returned malformed output"
        if not isinstance(payload, list):
            return {}, "Windows OCR returned malformed output"

        requested = {str(path): path for path in resolved_paths}
        texts: dict[str, str] = {}
        language = "unknown"
        for item in payload:
            if not isinstance(item, dict):
                continue
            raw_path = item.get("path")
            raw_text = item.get("text")
            if not isinstance(raw_path, str) or not isinstance(raw_text, str):
                continue
            try:
                returned_path = str(Path(raw_path).resolve())
            except OSError:
                continue
            if returned_path not in requested:
                continue
            bounded_text = raw_text.strip()
            if len(bounded_text) > self.settings.max_extracted_chars_per_document:
                return {}, "Windows OCR output exceeded the character limit"
            if bounded_text:
                texts[returned_path] = bounded_text
            raw_language = item.get("language")
            if isinstance(raw_language, str) and raw_language:
                language = raw_language[:32]
        if not texts:
            return {}, "Windows OCR could not read text from the supplied images"
        return (
            texts,
            f"Windows OCR fallback ({language}) was used; verify critical numbers on cited pages",
        )

    def _pdf(self, path: Path, **common: Any) -> ExtractionResult:
        # Default PDFium wheels omit V8/XFA; reject active-content markers as an extra guardrail.
        with path.open("rb") as handle:
            active_probe = handle.read(min(path.stat().st_size, 8 * 1024 * 1024))
        if any(marker in active_probe for marker in (b"/JavaScript", b"/JS ", b"/Launch")):
            raise SecurityError("Active PDF content is not accepted")
        result = ExtractionResult()
        artifact_dir = self.settings.artifact_dir / common["document_id"]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        try:
            document = pdfium.PdfDocument(path)
        except (pdfium.PdfiumError, OSError, ValueError) as exc:
            raise SecurityError("PDF is corrupt or encrypted with unsupported settings") from exc
        with document:
            if len(document) > self.settings.max_pdf_pages:
                raise SecurityError(f"PDF exceeds the {self.settings.max_pdf_pages}-page limit")
            rendered_pages: list[tuple[int, str, Path]] = []
            for page_index in range(len(document)):
                self._remaining(common["budget"], 1.0)
                page_number = page_index + 1
                page = document[page_index]
                try:
                    width, height = page.get_size()
                    # Roughly 144 DPI materially improves OCR on charts and small PDF text
                    # while remaining inside the existing pixel and derived-byte budgets.
                    scale = 2.0
                    bounded_render_dimensions(
                        float(width), float(height), scale, self.settings.max_image_pixels
                    )
                    text_page = page.get_textpage()
                    try:
                        page_text = text_page.get_text_bounded().replace("\r\n", "\n").strip()
                    finally:
                        text_page.close()
                    bitmap = page.render(scale=scale, rotation=0, draw_annots=False)
                    try:
                        image = bitmap.to_pil().convert("RGB")
                        if image.width * image.height > self.settings.max_image_pixels:
                            raise SecurityError("Rendered PDF page exceeds the image-pixel limit")
                        artifact = artifact_dir / f"page-{page_number:04d}.jpg"
                        image.save(artifact, format="JPEG", quality=82, optimize=True)
                        common["budget"].derived_bytes += artifact.stat().st_size
                        if (
                            common["budget"].derived_bytes
                            > self.settings.max_derived_bytes_per_document
                        ):
                            raise SecurityError("Document exceeds the derived-artifact byte limit")
                    finally:
                        bitmap.close()
                finally:
                    page.close()
                rendered_pages.append((page_number, page_text, artifact))

            pending_ocr = [
                artifact
                for _page_number, page_text, artifact in rendered_pages
                if len(page_text) < 40
            ]
            ocr_texts, ocr_warning = self._ocr_many(pending_ocr, common["budget"])
            if ocr_warning:
                result.warnings.append(ocr_warning)

            ordinal = 0
            for page_number, embedded_text, artifact in rendered_pages:
                ocr_text = ocr_texts.get(str(artifact.resolve()), "")
                page_text = ocr_text if len(embedded_text) < 40 and ocr_text else embedded_text
                text_available = bool(page_text)
                page_text = page_text or (
                    f"Rendered page {page_number} from {common['source_name']}"
                )
                page_chunks = self._chunks_from_text(
                    page_text,
                    modality=Modality.PDF_PAGE,
                    page=page_number,
                    artifact_path=str(artifact),
                    start_ordinal=ordinal,
                    metadata={
                        "kind": "rendered_pdf_page",
                        "content_kind": (
                            "ocr_text"
                            if ocr_text
                            else "native_text"
                            if text_available
                            else "provenance_only"
                        ),
                        "text_available": text_available,
                        "ocr_available": bool(ocr_text),
                    },
                    regions=[
                        PdfBoundingBoxRegion(
                            page=page_number,
                            bbox=self._full_visual_box(),
                            label="entire rendered page",
                            source=RegionSource.DERIVED_PROVENANCE,
                        )
                    ],
                    **common,
                )
                result.chunks.extend(page_chunks)
                ordinal += len(page_chunks)
        return result

    def _image(self, path: Path, **common: Any) -> ExtractionResult:
        validate_image(path, self.settings.max_image_pixels)
        artifact_dir = self.settings.artifact_dir / common["document_id"]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact = artifact_dir / "image.jpg"
        with Image.open(path) as image:
            normalized = ImageOps.exif_transpose(image).convert("RGB")
            normalized.thumbnail((2400, 2400))
            normalized.save(artifact, format="JPEG", quality=88, optimize=True)
        common["budget"].derived_bytes += artifact.stat().st_size
        if common["budget"].derived_bytes > self.settings.max_derived_bytes_per_document:
            raise SecurityError("Document exceeds the derived-artifact byte limit")
        ocr_text, warning = self._ocr(artifact, common["budget"])
        text = ocr_text or f"Visual evidence from {common['source_name']}"
        chunks = self._chunks_from_text(
            text,
            modality=Modality.IMAGE,
            artifact_path=str(artifact),
            metadata={
                "kind": "normalized_image",
                "content_kind": "ocr_text" if ocr_text else "provenance_only",
                "text_available": bool(ocr_text),
                "ocr_available": bool(ocr_text),
            },
            regions=[
                ImageBoundingBoxRegion(
                    bbox=self._full_visual_box(),
                    label="entire normalized image",
                    source=RegionSource.DERIVED_PROVENANCE,
                )
            ],
            **common,
        )
        return ExtractionResult(chunks=chunks, warnings=[warning] if warning else [])

    def _probe_video(self, path: Path, budget: ExtractionBudget | None = None) -> float:
        executable = shutil.which(self.settings.ffprobe_path)
        if not executable:
            raise RuntimeError("ffprobe is required for video ingestion")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                [
                    executable,
                    "-v",
                    "error",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "default=noprint_wrappers=1:nokey=1",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=self._remaining(budget, 30.0) if budget else 30,
                check=False,
            )
            duration = float(result.stdout.strip())
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SecurityError("Video metadata could not be safely decoded") from exc
        if result.returncode != 0 or not math.isfinite(duration) or duration <= 0:
            raise SecurityError("Video metadata could not be safely decoded")
        if duration > self.settings.max_video_seconds:
            raise SecurityError(f"Video exceeds the {self.settings.max_video_seconds}-second limit")
        return duration

    def _transcribe(
        self, path: Path, budget: ExtractionBudget
    ) -> tuple[list[tuple[float, str]], str | None]:
        with observe_stage("transcription"):
            return self._transcribe_unobserved(path, budget)

    def _transcribe_unobserved(
        self, path: Path, budget: ExtractionBudget
    ) -> tuple[list[tuple[float, str]], str | None]:
        if self.settings.transcription_provider == "disabled":
            return [], "Audio transcription is disabled"
        if importlib.util.find_spec("faster_whisper") is None:
            raise RuntimeError("Install the 'ml' extra for Faster Whisper transcription")
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_transcribe_worker,
            args=(
                sender,
                self.settings.whisper_model,
                str(path),
                self.settings.model_local_files_only,
                self.settings.max_chunks_per_document,
                self.settings.max_extracted_chars_per_document,
            ),
            daemon=True,
        )
        process.start()
        sender.close()
        try:
            timeout = self._remaining(budget, float(self.settings.transcription_timeout_seconds))
            if not receiver.poll(timeout):
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=5)
                return [], "Audio transcription timed out; frame evidence was retained"
            raw_payload = receiver.recv_bytes(self.settings.max_extraction_ipc_bytes)
            process.join(timeout=5)
        except (EOFError, OSError) as exc:
            raise SecurityError("Audio transcription worker failed closed") from exc
        finally:
            receiver.close()
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        try:
            message = json.loads(raw_payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurityError("Audio transcription worker returned invalid JSON") from exc
        if not isinstance(message, dict) or message.get("ok") is not True:
            error_type = (
                message.get("error_type", "InvalidResult")
                if isinstance(message, dict)
                else "InvalidResult"
            )
            safe_error_type = (
                error_type
                if isinstance(error_type, str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type)
                else "InvalidResult"
            )
            return (
                [],
                f"Audio transcription failed ({safe_error_type}); frame evidence was retained",
            )
        payload = message.get("segments")
        if not isinstance(payload, list) or len(payload) > self.settings.max_chunks_per_document:
            raise SecurityError("Audio transcription worker returned an invalid result")
        transcripts: list[tuple[float, str]] = []
        total_characters = 0
        for item in payload:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or isinstance(item[0], bool)
                or not isinstance(item[0], (int, float))
                or not isinstance(item[1], str)
                or not math.isfinite(float(item[0]))
                or not 0 <= float(item[0]) <= self.settings.max_video_seconds
            ):
                raise SecurityError("Audio transcription worker returned an invalid segment")
            total_characters += len(item[1])
            if total_characters > self.settings.max_extracted_chars_per_document:
                raise SecurityError("Audio transcription worker returned excessive text")
            transcripts.append((float(item[0]), item[1]))
        return transcripts, None

    def _probe_video_dimensions(
        self, path: Path, budget: ExtractionBudget | None = None
    ) -> tuple[int, int]:
        executable = shutil.which(self.settings.ffprobe_path)
        if not executable:
            raise RuntimeError("ffprobe is required for video ingestion")
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603
                [
                    executable,
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=width,height",
                    "-of",
                    "csv=p=0:s=x",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=self._remaining(budget, 30.0) if budget else 30,
                check=False,
            )
            width, height = (int(value) for value in result.stdout.strip().split("x", 1))
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SecurityError("Video dimensions could not be safely decoded") from exc
        if (
            result.returncode != 0
            or width <= 0
            or height <= 0
            or width > self.settings.max_video_dimension
            or height > self.settings.max_video_dimension
            or width * height > self.settings.max_image_pixels
        ):
            raise SecurityError("Video dimensions exceed the configured decode limits")
        return width, height

    def _video(self, path: Path, **common: Any) -> ExtractionResult:
        budget = common["budget"]
        duration = self._probe_video(path, budget)
        self._probe_video_dimensions(path, budget)
        executable = shutil.which(self.settings.ffmpeg_path)
        if not executable:
            raise RuntimeError("ffmpeg is required for video ingestion")
        artifact_dir = self.settings.artifact_dir / common["document_id"]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        pattern = artifact_dir / "frame-%04d.jpg"
        interval = self.settings.video_frame_interval_seconds
        command = [
            executable,
            "-nostdin",
            "-v",
            "error",
            "-i",
            str(path),
            "-vf",
            f"fps=fps=1/{interval}:start_time=0,"
            "scale=1280:1280:force_original_aspect_ratio=decrease",
            "-frames:v",
            str(self.settings.max_video_frames),
            "-q:v",
            "3",
            str(pattern),
        ]
        try:
            process = subprocess.Popen(  # noqa: S603  # nosec B603
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise SecurityError("Video frame extraction failed to start") from exc
        deadline = min(budget.deadline, time.monotonic() + self.settings.command_timeout_seconds)
        killed_for_budget = False
        while process.poll() is None:
            current_bytes = sum(item.stat().st_size for item in artifact_dir.glob("frame-*.jpg"))
            if current_bytes > self.settings.max_derived_bytes_per_document:
                killed_for_budget = True
            if killed_for_budget or time.monotonic() >= deadline:
                process.kill()
                process.wait(timeout=5)
                break
            time.sleep(0.1)
        if killed_for_budget:
            raise SecurityError("Document exceeds the derived-artifact byte limit")
        if process.returncode is None or time.monotonic() >= deadline:
            raise SecurityError("Video frame extraction timed out")
        if process.returncode != 0:
            raise SecurityError("Video frame extraction failed")
        result = ExtractionResult()
        ordinal = 0
        ocr_warning_added = False
        for frame_index, frame in enumerate(sorted(artifact_dir.glob("frame-*.jpg"))):
            common["budget"].derived_bytes += frame.stat().st_size
            if common["budget"].derived_bytes > self.settings.max_derived_bytes_per_document:
                raise SecurityError("Document exceeds the derived-artifact byte limit")
            with Image.open(frame) as image:
                if image.width * image.height > self.settings.max_image_pixels:
                    raise SecurityError("Video frame exceeds the image-pixel limit")
            timestamp = self._frame_timestamp(frame_index, interval, duration)
            frame_start, frame_end = self._frame_time_range(timestamp, interval, duration)
            self._remaining(budget, 1.0)
            ocr_text, warning = self._ocr(frame, budget)
            if warning and not ocr_warning_added:
                result.warnings.append(warning)
                ocr_warning_added = True
            text = ocr_text or f"Video frame at {timestamp:.1f} seconds"
            frame_chunks = self._chunks_from_text(
                text,
                modality=Modality.VIDEO_FRAME,
                timestamp_seconds=timestamp,
                artifact_path=str(frame),
                start_ordinal=ordinal,
                metadata={
                    "kind": "sampled_video_frame",
                    "content_kind": "ocr_text" if ocr_text else "provenance_only",
                    "duration_seconds": duration,
                    "text_available": bool(ocr_text),
                    "ocr_available": bool(ocr_text),
                },
                regions=[
                    VideoTimeRangeRegion(
                        start_seconds=frame_start,
                        end_seconds=frame_end,
                        bbox=self._full_visual_box(),
                        label="sampled frame window",
                        source=RegionSource.DERIVED_PROVENANCE,
                    )
                ],
                **common,
            )
            result.chunks.extend(frame_chunks)
            ordinal += len(frame_chunks)
        transcripts, transcript_warning = self._transcribe(path, budget)
        if transcript_warning:
            result.warnings.append(transcript_warning)
        for timestamp, text in transcripts:
            transcript_chunks = self._chunks_from_text(
                text,
                modality=Modality.TRANSCRIPT,
                timestamp_seconds=timestamp,
                start_ordinal=ordinal,
                metadata={"kind": "audio_transcript"},
                **common,
            )
            result.chunks.extend(transcript_chunks)
            ordinal += len(transcript_chunks)
        if not result.chunks:
            raise SecurityError("No evidence could be extracted from the video")
        return result

    @staticmethod
    def _frame_timestamp(frame_index: int, interval: int, duration: float) -> float:
        return min(duration, float(frame_index * interval))

    @staticmethod
    def _frame_time_range(timestamp: float, interval: int, duration: float) -> tuple[float, float]:
        end = min(duration, timestamp + float(interval))
        if end > timestamp:
            return timestamp, end
        # An exact-duration final sample still needs a non-empty, bounded locator.
        return max(0.0, duration - min(float(interval), duration)), duration

    def _text(self, path: Path, **common: Any) -> ExtractionResult:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise SecurityError("Text must be valid UTF-8") from exc
        chunks = self._chunks_from_text(text, **common)
        if not chunks:
            raise SecurityError("The text file is empty")
        return ExtractionResult(chunks=chunks)

    @staticmethod
    def _caption_seconds(value: str) -> float:
        normalized = value.strip().replace(",", ".")
        parts = normalized.split(":")
        if len(parts) not in {2, 3}:
            raise SecurityError("Caption timestamp is malformed")
        try:
            if len(parts) == 3:
                hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
            else:
                hours, minutes, seconds = 0, int(parts[0]), float(parts[1])
        except ValueError as exc:
            raise SecurityError("Caption timestamp is malformed") from exc
        timestamp = hours * 3600 + minutes * 60 + seconds
        if (
            hours < 0
            or not 0 <= minutes < 60
            or not 0 <= seconds < 60
            or not math.isfinite(timestamp)
        ):
            raise SecurityError("Caption timestamp is outside the valid range")
        return timestamp

    def _captions(self, path: Path, **common: Any) -> ExtractionResult:
        try:
            content = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SecurityError("Captions must be valid UTF-8") from exc
        result = ExtractionResult()
        ordinal = 0
        cue_index = 0
        for block in re.split(r"\r?\n\s*\r?\n", content.strip()):
            self._remaining(common["budget"], 1.0)
            lines = [line.strip() for line in block.splitlines() if line.strip()]
            if not lines or lines[0].upper().startswith(("WEBVTT", "NOTE", "STYLE", "REGION")):
                continue
            if lines[0].isdigit():
                lines = lines[1:]
            timing_index = next((index for index, line in enumerate(lines) if "-->" in line), None)
            if timing_index is None:
                continue
            timing = lines[timing_index].split("-->", 1)
            start = self._caption_seconds(timing[0])
            end_token = timing[1].strip().split(maxsplit=1)[0]
            end = self._caption_seconds(end_token)
            if end < start or end > self.settings.max_video_seconds:
                raise SecurityError("Caption cue duration is outside the configured limit")
            text = "\n".join(lines[timing_index + 1 :]).strip()
            if not text:
                continue
            chunks = self._chunks_from_text(
                text,
                modality=Modality.TRANSCRIPT,
                timestamp_seconds=start,
                start_ordinal=ordinal,
                metadata={"kind": "caption_cue", "cue_index": cue_index, "end_seconds": end},
                **common,
            )
            result.chunks.extend(chunks)
            ordinal += len(chunks)
            cue_index += 1
        if not result.chunks:
            raise SecurityError("Caption file contains no valid cues")
        return result

    @staticmethod
    def _number(value: Any) -> float | None:
        if value is None:
            return None
        try:
            cleaned = str(value).strip().upper().replace(",", "").replace("$", "")
        except (ValueError, OverflowError):
            return None
        if not cleaned:
            return None
        factor = 1.0
        if cleaned.endswith("K"):
            factor, cleaned = 1_000.0, cleaned[:-1]
        elif cleaned.endswith("M"):
            factor, cleaned = 1_000_000.0, cleaned[:-1]
        elif cleaned.endswith("B"):
            factor, cleaned = 1_000_000_000.0, cleaned[:-1]
        try:
            result = float(cleaned) * factor
        except ValueError:
            return None
        return result if math.isfinite(result) else None

    def _structured_text(self, value: Any, *, max_chars: int | None = None) -> str | None:
        if value is None:
            return None
        limit = max_chars or self.settings.max_structured_cell_chars
        try:
            cleaned = str(value).strip()
        except (ValueError, OverflowError):
            return None
        return cleaned[:limit] or None

    def _bounded_raw_record(self, row: dict[str, Any]) -> dict[str, Any]:
        bounded: dict[str, Any] = {}
        limit = self.settings.max_structured_cell_chars
        for index, (key, value) in enumerate(row.items()):
            if index >= 250:
                break
            safe_key = str(key).strip()[:256] or f"column_{index}"
            safe_value: bool | int | float | str | None
            if value is None or isinstance(value, bool):
                safe_value = value
            elif isinstance(value, int):
                safe_value = value if value.bit_length() <= 256 else None
            elif isinstance(value, float):
                safe_value = value if math.isfinite(value) else None
            elif isinstance(value, str):
                safe_value = value[:limit]
            else:
                try:
                    safe_value = json.dumps(
                        value, ensure_ascii=False, allow_nan=False, default=str
                    )[:limit]
                except (TypeError, ValueError, OverflowError):
                    safe_value = str(value)[:limit]
            bounded[safe_key] = safe_value
        return bounded

    def _normalize_event(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = {str(key).strip().upper(): value for key, value in row.items()}
        year_value = normalized.get("YEAR") or normalized.get("BEGIN_YEARMONTH")
        year_text = self._structured_text(year_value, max_chars=32) or ""
        year_match = re.search(r"(?:19|20)\d{2}", year_text)
        return {
            "event_id": self._structured_text(normalized.get("EVENT_ID"), max_chars=256),
            "begin_year": int(year_match.group()) if year_match else None,
            "state": (self._structured_text(normalized.get("STATE"), max_chars=256) or "").upper()
            or None,
            "event_type": self._structured_text(
                normalized.get("EVENT_TYPE") or normalized.get("TYPE"), max_chars=512
            ),
            "cz_name": self._structured_text(
                normalized.get("CZ_NAME") or normalized.get("LOCATION"), max_chars=512
            ),
            "injuries_direct": self._number(normalized.get("INJURIES_DIRECT")),
            "deaths_direct": self._number(normalized.get("DEATHS_DIRECT")),
            "damage_property": self._number(normalized.get("DAMAGE_PROPERTY")),
            "damage_crops": self._number(normalized.get("DAMAGE_CROPS")),
            "magnitude": self._number(normalized.get("MAGNITUDE")),
            "episode_narrative": self._structured_text(
                normalized.get("EPISODE_NARRATIVE") or normalized.get("EVENT_NARRATIVE")
            ),
            "raw": self._bounded_raw_record(row),
        }

    def _tabular_chunks(
        self, rows: Iterable[dict[str, Any]], *, common: dict[str, Any]
    ) -> list[Chunk]:
        materialized = list(rows)
        chunks: list[Chunk] = []
        ordinal = 0
        for offset in range(0, len(materialized), 15):
            batch = materialized[offset : offset + 15]
            text = "\n".join(json.dumps(row, ensure_ascii=False, default=str) for row in batch)
            batch_chunks = self._chunks_from_text(
                text,
                modality=Modality.TABLE,
                start_ordinal=ordinal,
                metadata={"row_start": offset, "row_end": offset + len(batch) - 1},
                **common,
            )
            chunks.extend(batch_chunks)
            ordinal += len(batch_chunks)
        return chunks

    def _csv(self, path: Path, **common: Any) -> ExtractionResult:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames or len(reader.fieldnames) > 250:
                    raise SecurityError("CSV has no header or too many columns")
                rows = []
                for index, row in enumerate(reader):
                    if index >= self.settings.max_structured_rows:
                        raise SecurityError(
                            f"CSV exceeds the {self.settings.max_structured_rows:,}-row limit"
                        )
                    rows.append(dict(row))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise SecurityError("CSV is malformed or not UTF-8") from exc
        if not rows:
            raise SecurityError("CSV contains no data rows")
        events = [self._normalize_event(row) for row in rows]
        return ExtractionResult(
            chunks=self._tabular_chunks([event["raw"] for event in events], common=common),
            storm_events=events,
        )

    def _json(self, path: Path, **common: Any) -> ExtractionResult:
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise SecurityError("JSON is malformed or not UTF-8") from exc
        rows: list[dict[str, Any]]
        if isinstance(value, list):
            rows = [item for item in value if isinstance(item, dict)]
        elif isinstance(value, dict):
            candidate = value.get("events") or value.get("features") or value.get("records")
            rows = candidate if isinstance(candidate, list) else [value]
            rows = [item for item in rows if isinstance(item, dict)]
        else:
            rows = []
        if not rows or len(rows) > self.settings.max_structured_rows:
            raise SecurityError(
                "JSON must contain between 1 and "
                f"{self.settings.max_structured_rows:,} object records"
            )
        events = [self._normalize_event(row) for row in rows]
        return ExtractionResult(
            chunks=self._tabular_chunks([event["raw"] for event in events], common=common),
            storm_events=events,
        )
