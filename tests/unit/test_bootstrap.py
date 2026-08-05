from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from crisisweave import bootstrap
from crisisweave.config import Settings


def production_settings(settings: Settings, **updates: Any) -> Settings:
    values: dict[str, Any] = {"app_env": "production"}
    values.update(updates)
    return settings.model_copy(update=values)


def test_production_bootstrap_lists_missing_executables(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="ffmpeg, ffprobe, tesseract"):
        bootstrap.build_ingestion_worker_container(
            production_settings(settings, runtime_role="ingestion_worker")
        )


def test_production_bootstrap_checks_absolute_scanner_executable(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _name: "C:/tools/found.exe")
    configured = production_settings(
        settings,
        runtime_role="ingestion_worker",
        malware_scanner_path="C:/tools/missing.exe",
    )
    with pytest.raises(RuntimeError, match="malware scanner"):
        bootstrap.build_ingestion_worker_container(configured)


def test_production_bootstrap_requires_transcription_dependency(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _name: "C:/tools/found.exe")
    monkeypatch.setattr(bootstrap.importlib.util, "find_spec", lambda _name: None)
    with pytest.raises(RuntimeError, match="transcription dependency"):
        bootstrap.build_ingestion_worker_container(
            production_settings(settings, runtime_role="ingestion_worker")
        )


def test_production_bootstrap_lists_missing_model_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _name: "C:/tools/found.exe")
    monkeypatch.setattr(bootstrap.importlib.util, "find_spec", lambda _name: object())
    configured = production_settings(
        settings,
        text_embedding_model=str(tmp_path / "text"),
        visual_embedding_model=str(tmp_path / "visual"),
        reranker_model=str(tmp_path / "reranker"),
        whisper_model=str(tmp_path / "whisper"),
    )
    with pytest.raises(RuntimeError) as raised:
        bootstrap.build_container(configured)
    assert str(raised.value) == (
        "Missing preloaded production models: text embedding, visual embedding, reranker"
    )


def create_model_bundle(tmp_path: Path) -> dict[str, Path]:
    models: dict[str, Path] = {}
    for name in ("text", "visual", "reranker", "whisper"):
        models[name] = tmp_path / name
        models[name].mkdir()
    return models


def bundled_settings(settings: Settings, tmp_path: Path, **updates: Any) -> Settings:
    models = create_model_bundle(tmp_path)
    values: dict[str, Any] = {
        "text_embedding_model": str(models["text"]),
        "visual_embedding_model": str(models["visual"]),
        "reranker_model": str(models["reranker"]),
        "whisper_model": str(models["whisper"]),
    }
    values.update(updates)
    return production_settings(settings, **values)


def install_successful_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _name: "C:/tools/found.exe")
    monkeypatch.setattr(bootstrap.importlib.util, "find_spec", lambda _name: object())


def test_production_bootstrap_requires_bundle_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    install_successful_preflight(monkeypatch)
    configured = bundled_settings(settings, tmp_path)
    with pytest.raises(RuntimeError, match="bundle manifest"):
        bootstrap.build_container(configured)


def test_production_bootstrap_runs_canaries_and_composes_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    install_successful_preflight(monkeypatch)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    configured = bundled_settings(settings, tmp_path, model_bundle_manifest=manifest)

    class FakeModel:
        verified = False

        async def verify_capabilities(self) -> None:
            self.verified = True

    model = FakeModel()
    object_store = SimpleNamespace(close=MagicMock())
    store = SimpleNamespace(close=MagicMock())
    embedder = object()
    index = SimpleNamespace(close=MagicMock())
    reranker = object()
    extractor = object()
    ingestion = object()
    ingestion_factory = MagicMock(return_value=ingestion)
    web = object()
    runner = SimpleNamespace(close=MagicMock())
    agent = object()
    scanner_check = MagicMock()

    monkeypatch.setattr(bootstrap, "verify_malware_scanner", scanner_check)
    monkeypatch.setattr(bootstrap, "build_object_store", lambda _settings: object_store)
    monkeypatch.setattr(bootstrap, "ModelGateway", lambda _settings, _objects: model)
    monkeypatch.setattr(bootstrap, "MetadataStore", lambda *_args, **_kwargs: store)
    monkeypatch.setattr(bootstrap, "build_embedder", lambda _settings: embedder)
    monkeypatch.setattr(bootstrap, "EvidenceIndex", lambda *_args: index)
    monkeypatch.setattr(bootstrap, "build_reranker", lambda _settings: reranker)
    monkeypatch.setattr(bootstrap, "Extractor", lambda _settings: extractor)
    monkeypatch.setattr(bootstrap, "IngestionService", ingestion_factory)
    monkeypatch.setattr(bootstrap, "WebSearch", lambda _settings: web)
    monkeypatch.setattr(bootstrap, "BlockingRunner", lambda _limit: runner)
    monkeypatch.setattr(bootstrap, "CrisisAgent", lambda *_args: agent)

    container = bootstrap.build_container(configured)

    scanner_check.assert_not_called()
    assert model.verified
    assert container.settings is configured
    assert container.store is store
    assert container.object_store is object_store
    assert container.embedder is embedder
    assert container.index is index
    assert container.reranker is reranker
    assert container.ingestion is ingestion
    assert container.agent is agent
    assert container.blocking_runner is runner
    assert ingestion_factory.call_args.kwargs == {
        "reconcile_on_startup": False,
    }

    container.close()
    runner.close.assert_called_once_with()
    index.close.assert_called_once_with()
    store.close.assert_called_once_with()
    object_store.close.assert_called_once_with()


def test_ingestion_worker_container_omits_query_stack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    object_store = SimpleNamespace(close=MagicMock())
    store = SimpleNamespace(close=MagicMock())
    embedder = object()
    index = SimpleNamespace(close=MagicMock())
    extractor = object()
    ingestion = object()
    ingestion_factory = MagicMock(return_value=ingestion)

    monkeypatch.setattr(bootstrap, "build_object_store", lambda _settings: object_store)
    monkeypatch.setattr(bootstrap, "_build_metadata_store", lambda _settings: store)
    monkeypatch.setattr(bootstrap, "build_embedder", lambda _settings: embedder)
    monkeypatch.setattr(bootstrap, "EvidenceIndex", lambda *_args: index)
    monkeypatch.setattr(bootstrap, "Extractor", lambda _settings: extractor)
    monkeypatch.setattr(bootstrap, "IngestionService", ingestion_factory)
    monkeypatch.setattr(
        bootstrap,
        "ModelGateway",
        MagicMock(side_effect=AssertionError("worker loaded model gateway")),
    )
    monkeypatch.setattr(
        bootstrap,
        "build_reranker",
        MagicMock(side_effect=AssertionError("worker loaded reranker")),
    )
    monkeypatch.setattr(
        bootstrap,
        "WebSearch",
        MagicMock(side_effect=AssertionError("worker loaded web search")),
    )
    monkeypatch.setattr(
        bootstrap,
        "CrisisAgent",
        MagicMock(side_effect=AssertionError("worker loaded query agent")),
    )

    container = bootstrap.build_ingestion_worker_container(settings)

    assert container.store is store
    assert container.object_store is object_store
    assert container.embedder is embedder
    assert container.index is index
    assert container.ingestion is ingestion
    assert ingestion_factory.call_args.kwargs == {
        "reconcile_on_startup": True,
    }

    container.close()
    index.close.assert_called_once_with()
    store.close.assert_called_once_with()
    object_store.close.assert_called_once_with()


def test_production_builders_reject_the_wrong_runtime_role(settings: Settings) -> None:
    with pytest.raises(RuntimeError, match="API container"):
        bootstrap.build_container(
            settings.model_copy(
                update={"app_env": "production", "runtime_role": "ingestion_worker"}
            )
        )
    with pytest.raises(RuntimeError, match="ingestion worker"):
        bootstrap.build_ingestion_worker_container(
            settings.model_copy(update={"app_env": "production", "runtime_role": "api"})
        )
