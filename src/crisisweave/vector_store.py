"""Qdrant named-vector adapter with mandatory tenant filters."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from qdrant_client import QdrantClient, models

from crisisweave.config import Settings
from crisisweave.embeddings import Embedder
from crisisweave.models import Chunk, Modality

VISUAL_MODALITIES = {Modality.PDF_PAGE, Modality.IMAGE, Modality.VIDEO_FRAME}
SCHEMA_POINT_ID = "00000000-0000-0000-0000-000000000001"
REQUIRED_PAYLOAD_INDEXES = ("tenant_id", "document_id", "modality")


@dataclass(frozen=True)
class VectorHit:
    id: str
    score: float


def validate_named_vector_schema(vectors: object, expected: dict[str, int]) -> None:
    if not isinstance(vectors, dict):
        raise RuntimeError("Qdrant collection must use named vectors")
    for name, size in expected.items():
        actual = vectors.get(name)
        if actual is None or actual.size != size or actual.distance != models.Distance.COSINE:
            raise RuntimeError(
                f"Qdrant vector schema mismatch for {name}; run a versioned index migration"
            )
    unexpected = set(vectors) - set(expected)
    if unexpected:
        names = ", ".join(sorted(unexpected))
        raise RuntimeError(
            f"Qdrant vector schema has unexpected named vectors ({names}); "
            "run a versioned index migration"
        )


def collection_is_ready(information: object) -> bool:
    status = getattr(information, "status", None)
    status_value = getattr(status, "value", status)
    optimizer = getattr(information, "optimizer_status", None)
    optimizer_value = getattr(optimizer, "value", optimizer)
    return status_value in {"green", "yellow"} and optimizer_value == "ok"


def validate_payload_indexes(information: object) -> set[str]:
    payload_schema = getattr(information, "payload_schema", None)
    if not isinstance(payload_schema, dict):
        return set(REQUIRED_PAYLOAD_INDEXES)
    missing: set[str] = set()
    for field in REQUIRED_PAYLOAD_INDEXES:
        index = payload_schema.get(field)
        data_type = getattr(index, "data_type", None)
        if data_type != models.PayloadSchemaType.KEYWORD:
            missing.add(field)
    return missing


def qdrant_filter_payload(chunk: Chunk) -> dict[str, str]:
    """External Qdrant receives only fields required for authorization filters."""
    return {
        "tenant_id": chunk.tenant_id,
        "document_id": chunk.document_id,
        "modality": chunk.modality.value,
    }


class EvidenceIndex:
    def __init__(
        self,
        settings: Settings,
        embedder: Embedder,
        *,
        provision_schema: bool | None = None,
    ) -> None:
        self.settings = settings
        self.embedder = embedder
        self._provision_schema = (
            settings.app_env != "production" or settings.runtime_role == "migration"
            if provision_schema is None
            else provision_schema
        )
        if settings.qdrant_url:
            self.client = QdrantClient(
                url=settings.qdrant_url,
                api_key=settings.qdrant_api_key.get_secret_value()
                if settings.qdrant_api_key
                else None,
                timeout=10,
                trust_env=False,
            )
        elif settings.app_env == "test":
            self.client = QdrantClient(":memory:")
        else:
            self.client = QdrantClient(path=str(settings.qdrant_path))
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        if self.client.collection_exists(self.settings.qdrant_collection):
            information = self.client.get_collection(self.settings.qdrant_collection)
            vectors = information.config.params.vectors
            expected = {"text": self.embedder.text_size, "visual": self.embedder.visual_size}
            validate_named_vector_schema(vectors, expected)
            marker = self.client.retrieve(
                collection_name=self.settings.qdrant_collection,
                ids=[SCHEMA_POINT_ID],
                with_payload=True,
                with_vectors=False,
            )
            if not marker:
                # The only safe markerless state is a collection create that committed before
                # initial provisioning wrote its marker. Never infer ownership from
                # dimensions alone.
                point_count = self.client.count(
                    collection_name=self.settings.qdrant_collection,
                    exact=True,
                ).count
                if (
                    isinstance(point_count, bool)
                    or not isinstance(point_count, int)
                    or point_count != 0
                ):
                    raise RuntimeError(
                        "Qdrant collection is non-empty but has no embedding fingerprint marker; "
                        "create and migrate a versioned collection"
                    )
                if not getattr(self, "_provision_schema", True):
                    raise RuntimeError(
                        "Qdrant schema marker is missing; run `crisisweave migrate` "
                        "with the migration role"
                    )
                self._ensure_payload_indexes(information)
                self._write_schema_marker()
                return
            marker_payload = getattr(marker[0], "payload", None)
            if (
                not isinstance(marker_payload, dict)
                or marker_payload.get("_crisisweave_schema") is not True
            ):
                raise RuntimeError(
                    "Qdrant schema marker conflict; create and migrate a versioned collection"
                )
            if marker_payload.get("embedding_fingerprint") != self.embedder.fingerprint:
                raise RuntimeError(
                    "Qdrant embedding fingerprint mismatch; create and migrate a "
                    "versioned collection"
                )
            self._ensure_payload_indexes(information)
            return
        if not self._provision_schema:
            raise RuntimeError(
                "Qdrant collection is unavailable; run `crisisweave migrate` "
                "with the migration role"
            )
        self.client.create_collection(
            collection_name=self.settings.qdrant_collection,
            vectors_config={
                "text": models.VectorParams(
                    size=self.embedder.text_size, distance=models.Distance.COSINE
                ),
                "visual": models.VectorParams(
                    size=self.embedder.visual_size, distance=models.Distance.COSINE
                ),
            },
            on_disk_payload=self.settings.app_env != "test",
        )
        if self.settings.qdrant_url:
            for field in REQUIRED_PAYLOAD_INDEXES:
                self.client.create_payload_index(
                    collection_name=self.settings.qdrant_collection,
                    field_name=field,
                    field_schema=models.PayloadSchemaType.KEYWORD,
                    wait=True,
                )

        self._write_schema_marker()

    def _write_schema_marker(self) -> None:
        self.client.upsert(
            collection_name=self.settings.qdrant_collection,
            points=[
                models.PointStruct(
                    id=SCHEMA_POINT_ID,
                    vector={
                        "text": [1.0, *([0.0] * (self.embedder.text_size - 1))],
                        "visual": [1.0, *([0.0] * (self.embedder.visual_size - 1))],
                    },
                    payload={
                        "_crisisweave_schema": True,
                        "embedding_fingerprint": self.embedder.fingerprint,
                    },
                )
            ],
            wait=True,
        )

    def _ensure_payload_indexes(self, information: object) -> None:
        if not self.settings.qdrant_url:
            return
        missing = validate_payload_indexes(information)
        if missing and not getattr(self, "_provision_schema", True):
            fields = ", ".join(sorted(missing))
            raise RuntimeError(
                f"Qdrant payload indexes are missing ({fields}); run `crisisweave migrate` "
                "with the migration role"
            )
        for field in missing:
            self.client.create_payload_index(
                collection_name=self.settings.qdrant_collection,
                field_name=field,
                field_schema=models.PayloadSchemaType.KEYWORD,
                wait=True,
            )
        refreshed = self.client.get_collection(self.settings.qdrant_collection)
        still_missing = validate_payload_indexes(refreshed)
        if still_missing:
            fields = ", ".join(sorted(still_missing))
            raise RuntimeError(f"Qdrant payload indexes are unavailable: {fields}")

    def index(
        self,
        chunks: Iterable[Chunk],
        *,
        deadline: float | None = None,
        visual_vectors: dict[str, list[float]] | None = None,
    ) -> None:
        points: list[models.PointStruct] = []
        for chunk in chunks:
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("Vector indexing exceeded the ingestion execution budget")
            text = chunk.text or chunk.source_name
            vectors: dict[str, models.Vector] = {"text": self.embedder.embed_text_document(text)}
            if chunk.modality in VISUAL_MODALITIES and chunk.artifact_path:
                if visual_vectors is None:
                    vectors["visual"] = self.embedder.embed_visual_chunk(chunk)
                else:
                    try:
                        vectors["visual"] = visual_vectors[chunk.id]
                    except KeyError as exc:
                        raise RuntimeError(
                            "The isolated parser omitted a required visual vector"
                        ) from exc
            payload = qdrant_filter_payload(chunk)
            points.append(models.PointStruct(id=chunk.id, vector=vectors, payload=payload))
        for offset in range(0, len(points), 64):
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("Vector indexing exceeded the ingestion execution budget")
            self.client.upsert(
                collection_name=self.settings.qdrant_collection,
                points=points[offset : offset + 64],
                wait=True,
            )

    @staticmethod
    def _score(value: float) -> float:
        return max(0.0, min(1.0, (float(value) + 1.0) / 2.0))

    def search(
        self,
        tenant_id: str,
        query: str,
        limit: int,
        modalities: list[Modality] | None = None,
        excluded_document_ids: set[str] | None = None,
    ) -> list[VectorHit]:
        must: list[models.Condition] = [
            models.FieldCondition(key="tenant_id", match=models.MatchValue(value=tenant_id))
        ]
        if modalities:
            must.append(
                models.FieldCondition(
                    key="modality",
                    match=models.MatchAny(any=[modality.value for modality in modalities]),
                )
            )
        must_not: list[models.Condition] = []
        if excluded_document_ids:
            must_not.append(
                models.FieldCondition(
                    key="document_id",
                    match=models.MatchAny(any=sorted(excluded_document_ids)),
                )
            )
        query_filter = models.Filter(must=must, must_not=must_not or None)
        candidates: dict[str, float] = {}
        requests = [("text", self.embedder.embed_text_query(query))]
        if not modalities or any(modality in VISUAL_MODALITIES for modality in modalities):
            requests.append(("visual", self.embedder.embed_visual_text(query)))
        for vector_name, vector in requests:
            result = self.client.query_points(
                collection_name=self.settings.qdrant_collection,
                query=vector,
                using=vector_name,
                query_filter=query_filter,
                limit=limit,
                with_payload=False,
                with_vectors=False,
            )
            for point in result.points:
                point_id = str(point.id)
                score = self._score(point.score)
                previous = candidates.get(point_id)
                if previous is None or score > previous:
                    candidates[point_id] = score
        return [
            VectorHit(id=point_id, score=score)
            for point_id, score in sorted(
                candidates.items(), key=lambda item: item[1], reverse=True
            )[:limit]
        ]

    def delete_document(self, tenant_id: str, document_id: str) -> None:
        self.client.delete(
            collection_name=self.settings.qdrant_collection,
            points_selector=models.FilterSelector(
                filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="tenant_id", match=models.MatchValue(value=tenant_id)
                        ),
                        models.FieldCondition(
                            key="document_id", match=models.MatchValue(value=document_id)
                        ),
                    ]
                )
            ),
            wait=True,
        )

    def healthcheck(self) -> bool:
        information = self.client.get_collection(self.settings.qdrant_collection)
        if not collection_is_ready(information):
            return False
        return not (self.settings.qdrant_url and validate_payload_indexes(information))

    def close(self) -> None:
        self.client.close()
