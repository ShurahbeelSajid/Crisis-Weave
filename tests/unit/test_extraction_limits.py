from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PIL import Image

from crisisweave.extractors import ExtractionBudget, Extractor, bounded_render_dimensions
from crisisweave.models import Modality
from crisisweave.security import SecurityError


def _common() -> dict[str, str | None]:
    return {
        "tenant_id": "a" * 32,
        "document_id": str(uuid.uuid4()),
        "source_name": "evidence.txt",
        "source_uri": None,
    }


def test_extracted_character_budget_fails_closed(settings, tmp_path: Path) -> None:
    path = tmp_path / "evidence.txt"
    path.write_text("bounded evidence " * 200, encoding="utf-8")
    configured = settings.model_copy(update={"max_extracted_chars_per_document": 1000})
    with pytest.raises(SecurityError, match="character"):
        Extractor(configured).extract(path, media_type="text/plain", **_common())


def test_chunk_budget_fails_closed(settings, tmp_path: Path) -> None:
    path = tmp_path / "evidence.txt"
    path.write_text("x" * 500, encoding="utf-8")
    configured = settings.model_copy(
        update={"chunk_chars": 200, "chunk_overlap_chars": 0, "max_chunks_per_document": 1}
    )
    with pytest.raises(SecurityError, match="evidence-unit"):
        Extractor(configured).extract(path, media_type="text/plain", **_common())


@pytest.mark.parametrize(
    ("width", "height"),
    [
        (float("nan"), 10.0),
        (10.0, float("inf")),
        (100_000.0, 100_000.0),
        (1e308, 1.0),
    ],
)
def test_pdf_render_preflight_rejects_nonfinite_or_huge_pages(width: float, height: float) -> None:
    with pytest.raises(SecurityError, match="pixel"):
        bounded_render_dimensions(width, height, 1.25, 40_000_000)


def test_video_timestamp_starts_at_first_sample(settings) -> None:
    extractor = Extractor(settings)
    assert extractor._frame_timestamp(0, 15, 100.0) == 0.0  # noqa: SLF001
    assert extractor._frame_timestamp(2, 15, 20.0) == 20.0  # noqa: SLF001


@pytest.mark.parametrize("reported", ["nan", "inf", "-inf"])
def test_video_probe_rejects_nonfinite_duration(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reported: str
) -> None:
    path = tmp_path / "evidence.mp4"
    path.write_bytes(b"not-read-by-mocked-ffprobe")
    monkeypatch.setattr("crisisweave.extractors.shutil.which", lambda _name: "ffprobe")
    monkeypatch.setattr(
        "crisisweave.extractors.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=reported),
    )
    with pytest.raises(SecurityError, match="metadata"):
        Extractor(settings)._probe_video(path)  # noqa: SLF001


def test_malformed_caption_timestamp_is_rejected(settings, tmp_path: Path) -> None:
    path = tmp_path / "bad.vtt"
    path.write_text("WEBVTT\n\n99:99.000 --> 00:01.000\nsmoke", encoding="utf-8")
    with pytest.raises(SecurityError, match="timestamp"):
        Extractor(settings).extract(path, media_type="text/plain", **_common())


def test_structured_cells_are_bounded_before_storage_and_chunking(settings, tmp_path: Path) -> None:
    path = tmp_path / "large-narrative.json"
    path.write_text(
        '[{"EVENT_ID":"1","EPISODE_NARRATIVE":"' + ("x" * 2000) + '"}]',
        encoding="utf-8",
    )
    configured = settings.model_copy(update={"max_structured_cell_chars": 256})

    result = Extractor(configured).extract(path, media_type="application/json", **_common())

    event = result.storm_events[0]
    assert len(event["episode_narrative"]) == 256
    assert len(event["raw"]["EPISODE_NARRATIVE"]) == 256
    assert all("x" * 257 not in chunk.text for chunk in result.chunks)


def test_nonfinite_json_number_is_rejected(settings, tmp_path: Path) -> None:
    path = tmp_path / "nonfinite.json"
    path.write_text('[{"MAGNITUDE":NaN}]', encoding="utf-8")

    with pytest.raises(SecurityError, match="malformed"):
        Extractor(settings).extract(path, media_type="application/json", **_common())


def test_mocked_video_pipeline_emits_frames_and_transcript(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.mp4"
    path.write_bytes(b"mocked-video")
    extractor = Extractor(settings)
    monkeypatch.setattr(extractor, "_probe_video", lambda *_args: 20.0)
    monkeypatch.setattr(extractor, "_probe_video_dimensions", lambda *_args: (16, 12))
    monkeypatch.setattr(extractor, "_ocr", lambda *_args: ("visible smoke", None))
    monkeypatch.setattr(
        extractor,
        "_transcribe",
        lambda *_args: ([(2.5, "radio transcript")], None),
    )
    monkeypatch.setattr("crisisweave.extractors.shutil.which", lambda _name: "ffmpeg")

    class CompletedProcess:
        returncode = 0

        @staticmethod
        def poll() -> int:
            return 0

    def popen(command: list[str], **_kwargs: object) -> CompletedProcess:
        pattern = Path(command[-1])
        for number, color in ((1, "red"), (2, "orange")):
            frame = Path(str(pattern).replace("%04d", f"{number:04d}"))
            Image.new("RGB", (16, 12), color).save(frame)
        return CompletedProcess()

    monkeypatch.setattr("crisisweave.extractors.subprocess.Popen", popen)

    result = extractor.extract(path, media_type="video/mp4", **_common())

    assert [chunk.modality for chunk in result.chunks] == [
        Modality.VIDEO_FRAME,
        Modality.VIDEO_FRAME,
        Modality.TRANSCRIPT,
    ]
    assert [chunk.timestamp_seconds for chunk in result.chunks] == [0.0, 15.0, 2.5]
    assert result.chunks[-1].text == "radio transcript"


class _FakeProcess:
    def __init__(self, *, remains_alive: bool = False) -> None:
        self.remains_alive = remains_alive
        self.started = False
        self.terminated = False
        self.killed = False

    def start(self) -> None:
        self.started = True

    def join(self, timeout: int) -> None:
        assert timeout == 5

    def is_alive(self) -> bool:
        return self.remains_alive and not self.killed

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


class _FakeConnection:
    def __init__(self, payload: bytes, *, ready: bool = True) -> None:
        self.payload = payload
        self.ready = ready
        self.closed = False

    def poll(self, _timeout: float) -> bool:
        return self.ready

    def recv_bytes(self, _maximum: int) -> bytes:
        return self.payload

    def close(self) -> None:
        self.closed = True


class _FakeTranscriptionContext:
    def __init__(self, payload: bytes, *, ready: bool = True, alive: bool = False) -> None:
        self.receiver = _FakeConnection(payload, ready=ready)
        self.sender = _FakeConnection(b"")
        self.process = _FakeProcess(remains_alive=alive)

    def Pipe(self, *, duplex: bool) -> tuple[_FakeConnection, _FakeConnection]:
        assert duplex is False
        return self.receiver, self.sender

    def Process(self, **kwargs: Any) -> _FakeProcess:
        assert kwargs["daemon"] is True
        return self.process


def _mock_transcription_context(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    *,
    ready: bool = True,
    alive: bool = False,
) -> _FakeTranscriptionContext:
    encoded = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    context = _FakeTranscriptionContext(encoded, ready=ready, alive=alive)
    monkeypatch.setattr("crisisweave.extractors.importlib.util.find_spec", lambda _name: object())
    monkeypatch.setattr("crisisweave.extractors.multiprocessing.get_context", lambda _name: context)
    return context


def test_transcription_worker_result_is_strictly_validated(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _mock_transcription_context(
        monkeypatch,
        {"ok": True, "segments": [[0, "first"], [3.25, "second"]]},
    )

    result, warning = Extractor(
        settings.model_copy(update={"transcription_provider": "faster_whisper"})
    )._transcribe(  # noqa: SLF001
        tmp_path / "video.mp4", ExtractionBudget(deadline=10**9)
    )

    assert result == [(0.0, "first"), (3.25, "second")]
    assert warning is None
    assert context.process.started
    assert context.receiver.closed and context.sender.closed


def test_transcription_timeout_kills_stuck_worker(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _mock_transcription_context(
        monkeypatch,
        {},
        ready=False,
        alive=True,
    )

    result, warning = Extractor(
        settings.model_copy(update={"transcription_provider": "faster_whisper"})
    )._transcribe(  # noqa: SLF001
        tmp_path / "video.mp4", ExtractionBudget(deadline=10**9)
    )

    assert result == []
    assert warning and "timed out" in warning
    assert context.process.terminated and context.process.killed


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        {"ok": True, "segments": [[float("nan"), "invalid"]]},
        {"ok": True, "segments": "invalid"},
    ],
)
def test_transcription_rejects_malformed_worker_payloads(
    settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    _mock_transcription_context(monkeypatch, payload)

    with pytest.raises(SecurityError, match="invalid"):
        Extractor(
            settings.model_copy(update={"transcription_provider": "faster_whisper"})
        )._transcribe(  # noqa: SLF001
            tmp_path / "video.mp4", ExtractionBudget(deadline=10**9)
        )


def test_transcription_failure_exposes_only_bounded_error_type(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_transcription_context(
        monkeypatch,
        {"ok": False, "error_type": "unsafe details / secret"},
    )

    result, warning = Extractor(
        settings.model_copy(update={"transcription_provider": "faster_whisper"})
    )._transcribe(  # noqa: SLF001
        tmp_path / "video.mp4", ExtractionBudget(deadline=10**9)
    )

    assert result == []
    assert warning and "InvalidResult" in warning
    assert "secret" not in warning


@pytest.mark.parametrize(
    ("reported", "expected"),
    [("640x480", (640, 480)), ("0x480", None), ("bad", None)],
)
def test_video_dimension_probe_is_bounded(
    settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported: str,
    expected: tuple[int, int] | None,
) -> None:
    path = tmp_path / "video.mp4"
    path.write_bytes(b"mock")
    monkeypatch.setattr("crisisweave.extractors.shutil.which", lambda _name: "ffprobe")
    monkeypatch.setattr(
        "crisisweave.extractors.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=reported),
    )

    if expected is None:
        with pytest.raises(SecurityError, match="dimensions"):
            Extractor(settings)._probe_video_dimensions(path)  # noqa: SLF001
    else:
        assert Extractor(settings)._probe_video_dimensions(path) == expected  # noqa: SLF001


@pytest.mark.parametrize(
    ("value", "expected"),
    [("$1.5K", 1500.0), ("2M", 2_000_000.0), ("0.5B", 500_000_000.0), ("bad", None)],
)
def test_structured_damage_number_suffixes(value: str, expected: float | None) -> None:
    assert Extractor._number(value) == expected  # noqa: SLF001
