from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from PIL import Image

from crisisweave.config import Settings
from crisisweave.embeddings import (
    HashEmbedder,
    SentenceTransformerEmbedder,
    SentenceTransformerVisualEmbedder,
    VisualEmbeddingConfig,
    build_embedder,
    build_visual_embedder,
    embedding_fingerprint,
)
from crisisweave.models import Chunk, Modality


class FakeSentenceTransformer:
    dimensions: dict[str, int] = {}
    instances: list[FakeSentenceTransformer] = []

    def __init__(
        self,
        model_name: str,
        *,
        trust_remote_code: bool,
        local_files_only: bool,
    ) -> None:
        self.model_name = model_name
        self.trust_remote_code = trust_remote_code
        self.local_files_only = local_files_only
        self.calls: list[tuple[str, object, bool]] = []
        self.instances.append(self)

    def get_sentence_embedding_dimension(self) -> int:
        return self.dimensions[self.model_name]

    def encode_document(self, value: str, *, normalize_embeddings: bool) -> tuple[int, int]:
        self.calls.append(("document", value, normalize_embeddings))
        return (1, 2)

    def encode_query(self, value: str, *, normalize_embeddings: bool) -> tuple[int, int]:
        self.calls.append(("query", value, normalize_embeddings))
        return (3, 4)

    def encode(self, value: object, *, normalize_embeddings: bool) -> tuple[int, int]:
        self.calls.append(("encode", value, normalize_embeddings))
        return (5, 6)


def install_fake_sentence_transformers(
    monkeypatch: pytest.MonkeyPatch, dimensions: dict[str, int]
) -> None:
    FakeSentenceTransformer.dimensions = dimensions
    FakeSentenceTransformer.instances = []
    module = ModuleType("sentence_transformers")
    module.SentenceTransformer = FakeSentenceTransformer  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentence_transformers", module)


def sentence_settings(settings: Settings, **updates: Any) -> Settings:
    values: dict[str, Any] = {
        "embedding_provider": "sentence_transformers",
        "text_embedding_model": "text-model",
        "visual_embedding_model": "visual-model",
        "text_vector_size": 64,
        "visual_vector_size": 96,
        "model_local_files_only": True,
    }
    values.update(updates)
    return settings.model_copy(update=values)


def chunk(*, artifact_path: str | None = None, text: str = "flood map") -> Chunk:
    return Chunk(
        id="chunk-1",
        document_id="doc-1",
        source_name="map.png",
        modality=Modality.IMAGE,
        text=text,
        artifact_path=artifact_path,
    )


def test_hash_embedder_is_deterministic_normalized_and_namespace_separated() -> None:
    embedder = HashEmbedder(text_size=64, visual_size=96)
    document = embedder.embed_text_document("Flood warning in District 7")
    query = embedder.embed_text_query("Flood warning in District 7")
    visual = embedder.embed_visual_text("Flood warning in District 7")

    assert document == query
    assert len(document) == 64
    assert len(visual) == 96
    assert sum(value * value for value in document) == pytest.approx(1.0)
    assert embedder.embed_text_query("") == embedder.embed_text_query("")
    assert embedder.embed_visual_chunk(chunk(text="")) == embedder.embed_visual_text("map.png")


def test_embedding_fingerprint_tracks_manifest_content(tmp_path: Path, settings: Settings) -> None:
    manifest = tmp_path / "models.json"
    manifest.write_text('{"bundle": 1}', encoding="utf-8")
    configured = sentence_settings(settings, model_bundle_manifest=manifest)
    first = embedding_fingerprint(configured)
    manifest.write_text('{"bundle": 2}', encoding="utf-8")

    assert embedding_fingerprint(configured) != first
    assert VisualEmbeddingConfig.from_settings(configured) == VisualEmbeddingConfig(
        provider="sentence_transformers",
        visual_model="visual-model",
        visual_size=96,
        local_files_only=True,
        fingerprint=embedding_fingerprint(configured),
    )


def test_embedding_fingerprint_fails_closed_when_manifest_is_unreadable(
    tmp_path: Path, settings: Settings
) -> None:
    configured = sentence_settings(settings, model_bundle_manifest=tmp_path)
    with pytest.raises(RuntimeError, match="manifest could not be read"):
        embedding_fingerprint(configured)


def test_hash_fingerprint_and_factory_reflect_dimensions(settings: Settings) -> None:
    configured = settings.model_copy(update={"text_vector_size": 64, "visual_vector_size": 96})
    built = build_embedder(configured)
    assert isinstance(built, HashEmbedder)
    assert (built.text_size, built.visual_size) == (64, 96)
    assert embedding_fingerprint(configured) == built.fingerprint


def test_visual_sentence_transformer_requires_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)
    config = VisualEmbeddingConfig("sentence_transformers", "visual-model", 96, True, "fp")
    with pytest.raises(RuntimeError, match="Install the 'ml' extra"):
        SentenceTransformerVisualEmbedder(config)


def test_visual_sentence_transformer_validates_dimension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"visual-model": 64})
    config = VisualEmbeddingConfig("sentence_transformers", "visual-model", 96, True, "fp")
    with pytest.raises(RuntimeError, match="emits 64 dimensions"):
        SentenceTransformerVisualEmbedder(config)


def test_visual_sentence_transformer_embeds_real_pixels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"visual-model": 96})
    image_path = tmp_path / "map.png"
    Image.new("L", (2, 2), 127).save(image_path)
    config = VisualEmbeddingConfig("sentence_transformers", "visual-model", 96, True, "fp")
    embedder = SentenceTransformerVisualEmbedder(config)

    assert embedder.embed_visual_chunk(chunk(artifact_path=str(image_path))) == [5.0, 6.0]
    assert embedder.visual_size == 96
    assert embedder.fingerprint == "fp"
    model = FakeSentenceTransformer.instances[0]
    assert model.trust_remote_code is False
    assert model.local_files_only is True
    encoded_image = model.calls[0][1]
    assert isinstance(encoded_image, Image.Image)
    assert encoded_image.mode == "RGB"


def test_visual_sentence_transformer_requires_existing_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"visual-model": 96})
    config = VisualEmbeddingConfig("sentence_transformers", "visual-model", 96, True, "fp")
    embedder = SentenceTransformerVisualEmbedder(config)
    with pytest.raises(RuntimeError, match="visual artifact is required"):
        embedder.embed_visual_chunk(chunk(artifact_path=str(tmp_path / "missing.png")))


def test_embedding_vector_conversion_rejects_non_iterables() -> None:
    with pytest.raises(RuntimeError, match="non-iterable"):
        SentenceTransformerVisualEmbedder._list(7)
    with pytest.raises(RuntimeError, match="non-iterable"):
        SentenceTransformerEmbedder._list(None)


def test_build_visual_hash_embedder_preserves_contract_fingerprint() -> None:
    config = VisualEmbeddingConfig("hash", "unused", 96, True, "contract-fingerprint")
    embedder = build_visual_embedder(config)
    assert isinstance(embedder, HashEmbedder)
    assert embedder.visual_size == 96
    assert embedder.fingerprint == "contract-fingerprint"


def test_build_visual_sentence_embedder_selects_production_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"visual-model": 96})
    config = VisualEmbeddingConfig("sentence_transformers", "visual-model", 96, True, "fp")
    assert isinstance(build_visual_embedder(config), SentenceTransformerVisualEmbedder)


def test_sentence_transformer_embedder_requires_optional_dependency(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)
    with pytest.raises(RuntimeError, match="Install the 'ml' extra"):
        SentenceTransformerEmbedder(sentence_settings(settings))


@pytest.mark.parametrize(
    ("dimensions", "message"),
    [
        ({"text-model": 65, "visual-model": 96}, "Text model emits 65"),
        ({"text-model": 64, "visual-model": 97}, "Visual model emits 97"),
    ],
)
def test_sentence_transformer_embedder_validates_both_dimensions(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    dimensions: dict[str, int],
    message: str,
) -> None:
    install_fake_sentence_transformers(monkeypatch, dimensions)
    with pytest.raises(RuntimeError, match=message):
        SentenceTransformerEmbedder(sentence_settings(settings))


def test_sentence_transformer_embedder_exercises_asymmetric_and_visual_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"text-model": 64, "visual-model": 96})
    configured = sentence_settings(settings)
    embedder = SentenceTransformerEmbedder(configured)
    image_path = tmp_path / "map.png"
    Image.new("L", (2, 2), 127).save(image_path)

    assert embedder.embed_text_document("document") == [1.0, 2.0]
    assert embedder.embed_text_query("query") == [3.0, 4.0]
    assert embedder.embed_visual_text("visual query") == [5.0, 6.0]
    assert embedder.embed_visual_chunk(chunk(artifact_path=str(image_path))) == [5.0, 6.0]
    assert embedder.embed_visual_chunk(chunk(artifact_path="missing", text="fallback")) == [
        5.0,
        6.0,
    ]
    assert (embedder.text_size, embedder.visual_size) == (64, 96)
    assert embedder.fingerprint == embedding_fingerprint(configured)
    assert len(FakeSentenceTransformer.instances) == 2


def test_build_embedder_selects_sentence_transformer(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    install_fake_sentence_transformers(monkeypatch, {"text-model": 64, "visual-model": 96})
    assert isinstance(build_embedder(sentence_settings(settings)), SentenceTransformerEmbedder)
