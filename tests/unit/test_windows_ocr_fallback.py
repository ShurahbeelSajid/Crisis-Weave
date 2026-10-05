from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from PIL import Image

import crisisweave.extractors as extractor_module
from crisisweave.extractors import ExtractionBudget, Extractor


def simulate_windows_for_ocr_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Report Windows to the OCR enablement check only.

    Patching os.name for the whole test makes pathlib build WindowsPath objects, which cannot be
    instantiated on POSIX CI runners.
    """
    enabled = Extractor._windows_ocr_enabled  # noqa: SLF001

    def enabled_on_windows(extractor: Extractor) -> bool:
        with pytest.MonkeyPatch.context() as windows:
            windows.setattr(extractor_module.os, "name", "nt")
            return enabled(extractor)

    monkeypatch.setattr(Extractor, "_windows_ocr_enabled", enabled_on_windows)


def test_windows_ocr_uses_a_fixed_helper_and_bounded_argv(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = settings.model_copy(update={"app_env": "development"})
    configured.ensure_directories()
    artifact_dir = configured.artifact_dir / "document-1"
    artifact_dir.mkdir(parents=True)
    image_path = artifact_dir / "page-0001.jpg"
    Image.new("RGB", (20, 20), "white").save(image_path)
    captured: dict[str, object] = {}

    def fake_which(command: str) -> str | None:
        if command == configured.tesseract_path:
            return None
        if command == "powershell.exe":
            return r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        return None

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        payload = [
            {
                "path": str(image_path.resolve()),
                "text": "Floods represented 64.8% of direct losses.",
                "language": "en-US",
                "width": 20,
                "height": 20,
            }
        ]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    simulate_windows_for_ocr_gate(monkeypatch)
    monkeypatch.setattr(extractor_module.shutil, "which", fake_which)
    monkeypatch.setattr(extractor_module.subprocess, "run", fake_run)

    text, warning = Extractor(configured)._ocr(  # noqa: SLF001
        image_path, ExtractionBudget(deadline=float("inf"))
    )

    assert text == "Floods represented 64.8% of direct losses."
    assert warning is not None and "Windows OCR fallback (en-US)" in warning
    command = captured["command"]
    assert isinstance(command, list)
    assert "-File" in command
    assert command[-2:] == ["-ImagePath", str(image_path.resolve())]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL


def test_windows_ocr_rejects_paths_outside_the_artifact_root(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = settings.model_copy(update={"app_env": "development"})
    configured.ensure_directories()
    outside = tmp_path / "outside.jpg"
    Image.new("RGB", (20, 20), "white").save(outside)
    invoked = False

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal invoked
        invoked = True
        raise AssertionError("subprocess must not be invoked for an unauthorized path")

    simulate_windows_for_ocr_gate(monkeypatch)
    monkeypatch.setattr(
        extractor_module.shutil,
        "which",
        lambda command: (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            if command == "powershell.exe"
            else None
        ),
    )
    monkeypatch.setattr(extractor_module.subprocess, "run", fake_run)

    text, warning = Extractor(configured)._ocr(  # noqa: SLF001
        outside, ExtractionBudget(deadline=float("inf"))
    )

    assert text == ""
    assert warning is not None and "unavailable" in warning
    assert invoked is False
