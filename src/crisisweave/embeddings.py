"""Local deterministic and production sentence-transformer embedding adapters."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from PIL import Image

from crisisweave.config import Settings
from crisisweave.models import Chunk


class Embedder(Protocol):
    text_size: int
    visual_size: int
    fingerprint: str

    def embed_text_document(self, text: str) -> list[float]: ...

    def embed_text_query(self, text: str) -> list[float]: ...

    def embed_visual_text(self, text: str) -> list[float]: ...

    def embed_visual_chunk(self, chunk: Chunk) -> list[float]: ...


class VisualEmbedder(Protocol):
    visual_size: int
    fingerprint: str

    def embed_visual_chunk(self, chunk: Chunk) -> list[float]: ...


def _hash_vector(value: str | bytes, size: int, namespace: bytes) -> list[float]:
    data = value.encode("utf-8", errors="ignore") if isinstance(value, str) else value
    vector = [0.0] * size
    tokens = re.findall(rb"[a-z0-9]{2,}", data.lower()) or [data[:256] or b"empty"]
    for token in tokens:
        digest = hashlib.blake2b(namespace + token, digest_size=16).digest()
        index = int.from_bytes(digest[:8], "little") % size
        vector[index] += 1.0 if digest[8] & 1 else -1.0
    norm = math.sqrt(sum(item * item for item in vector)) or 1.0
    return [item / norm for item in vector]


class HashEmbedder:
    """Zero-download fallback for tests and local plumbing checks, not quality evaluation."""

    def __init__(self, text_size: int = 384, visual_size: int = 512) -> None:
        self.text_size = text_size
        self.visual_size = visual_size
        self.fingerprint = hashlib.sha256(f"hash-v1:{text_size}:{visual_size}".encode()).hexdigest()

    def embed_text_document(self, text: str) -> list[float]:
        return _hash_vector(text, self.text_size, b"text:")

    def embed_text_query(self, text: str) -> list[float]:
        return _hash_vector(text, self.text_size, b"text:")

    def embed_visual_text(self, text: str) -> list[float]:
        return _hash_vector(text, self.visual_size, b"visual:")

    def embed_visual_chunk(self, chunk: Chunk) -> list[float]:
        # Text remains cross-modal in development; production uses actual pixels through CLIP.
        value = chunk.text or chunk.source_name
        return _hash_vector(value, self.visual_size, b"visual:")


def embedding_fingerprint(settings: Settings) -> str:
    if settings.embedding_provider == "hash":
        return HashEmbedder(
            settings.text_vector_size,
            settings.visual_vector_size,
        ).fingerprint
    manifest_digest = ""
    if settings.model_bundle_manifest:
        try:
            manifest_digest = hashlib.sha256(
                settings.model_bundle_manifest.read_bytes()
            ).hexdigest()
        except OSError as exc:
            raise RuntimeError("Model bundle manifest could not be read") from exc
    descriptor = {
        "pipeline": "crisisweave-asymmetric-text-clip-v2",
        "provider": "sentence_transformers",
        "text_model": settings.text_embedding_model,
        "visual_model": settings.visual_embedding_model,
        "text_size": settings.text_vector_size,
        "visual_size": settings.visual_vector_size,
        "bundle_manifest_sha256": manifest_digest,
    }
    return hashlib.sha256(json.dumps(descriptor, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class VisualEmbeddingConfig:
    """Secret-free visual model configuration safe for an isolated child process."""

    provider: Literal["hash", "sentence_transformers"]
    visual_model: str
    visual_size: int
    local_files_only: bool
    fingerprint: str

    @classmethod
    def from_settings(cls, settings: Settings) -> VisualEmbeddingConfig:
        return cls(
            provider=settings.embedding_provider,
            visual_model=settings.visual_embedding_model,
            visual_size=settings.visual_vector_size,
            local_files_only=settings.model_local_files_only,
            fingerprint=embedding_fingerprint(settings),
        )


class SentenceTransformerVisualEmbedder:
    """CLIP adapter loaded only inside the killable parser subprocess."""

    def __init__(self, config: VisualEmbeddingConfig) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install the 'ml' extra for production embeddings") from exc
        self._model = SentenceTransformer(
            config.visual_model,
            trust_remote_code=False,
            local_files_only=config.local_files_only,
        )
        self.visual_size = int(self._model.get_sentence_embedding_dimension())
        if self.visual_size != config.visual_size:
            raise RuntimeError(
                f"Visual model emits {self.visual_size} dimensions; configured {config.visual_size}"
            )
        self.fingerprint = config.fingerprint

    @staticmethod
    def _list(value: object) -> list[float]:
        if not isinstance(value, Iterable):
            raise RuntimeError("Embedding model returned a non-iterable vector")
        return [float(item) for item in value]

    def embed_visual_chunk(self, chunk: Chunk) -> list[float]:
        if not chunk.artifact_path or not Path(chunk.artifact_path).is_file():
            raise RuntimeError("A visual artifact is required for isolated embedding")
        with Image.open(chunk.artifact_path) as image:
            return self._list(self._model.encode(image.convert("RGB"), normalize_embeddings=True))


def build_visual_embedder(config: VisualEmbeddingConfig) -> VisualEmbedder:
    if config.provider == "sentence_transformers":
        return SentenceTransformerVisualEmbedder(config)
    embedder = HashEmbedder(visual_size=config.visual_size)
    embedder.fingerprint = config.fingerprint
    return embedder


class SentenceTransformerEmbedder:
    def __init__(self, settings: Settings) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install the 'ml' extra for production embeddings") from exc
        self._text_model = SentenceTransformer(
            settings.text_embedding_model,
            trust_remote_code=False,
            local_files_only=settings.model_local_files_only,
        )
        self._visual_model = SentenceTransformer(
            settings.visual_embedding_model,
            trust_remote_code=False,
            local_files_only=settings.model_local_files_only,
        )
        self.text_size = int(self._text_model.get_sentence_embedding_dimension())
        self.visual_size = int(self._visual_model.get_sentence_embedding_dimension())
        if self.text_size != settings.text_vector_size:
            raise RuntimeError(
                f"Text model emits {self.text_size} dimensions; "
                f"configured {settings.text_vector_size}"
            )
        if self.visual_size != settings.visual_vector_size:
            raise RuntimeError(
                f"Visual model emits {self.visual_size} dimensions; "
                f"configured {settings.visual_vector_size}"
            )
        self.fingerprint = embedding_fingerprint(settings)

    @staticmethod
    def _list(value: object) -> list[float]:
        if not isinstance(value, Iterable):
            raise RuntimeError("Embedding model returned a non-iterable vector")
        return [float(item) for item in value]

    def embed_text_document(self, text: str) -> list[float]:
        return self._list(self._text_model.encode_document(text, normalize_embeddings=True))

    def embed_text_query(self, text: str) -> list[float]:
        return self._list(self._text_model.encode_query(text, normalize_embeddings=True))

    def embed_visual_text(self, text: str) -> list[float]:
        return self._list(self._visual_model.encode(text, normalize_embeddings=True))

    def embed_visual_chunk(self, chunk: Chunk) -> list[float]:
        if chunk.artifact_path and Path(chunk.artifact_path).is_file():
            with Image.open(chunk.artifact_path) as image:
                return self._list(
                    self._visual_model.encode(image.convert("RGB"), normalize_embeddings=True)
                )
        return self.embed_visual_text(chunk.text or chunk.source_name)


def build_embedder(settings: Settings) -> Embedder:
    if settings.embedding_provider == "sentence_transformers":
        return SentenceTransformerEmbedder(settings)
    return HashEmbedder(settings.text_vector_size, settings.visual_vector_size)
