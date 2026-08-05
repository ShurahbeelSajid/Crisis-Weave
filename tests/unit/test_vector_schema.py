from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from qdrant_client import models

from crisisweave.embeddings import HashEmbedder
from crisisweave.models import Chunk, Modality
from crisisweave.vector_store import (
    SCHEMA_POINT_ID,
    EvidenceIndex,
    collection_is_ready,
    qdrant_filter_payload,
    validate_named_vector_schema,
    validate_payload_indexes,
)


def _existing_collection_index(
    settings,
    *,
    marker_payload: dict[str, object] | None,
    point_count: int = 0,
    text_size: int | None = None,
    include_extra_vector: bool = False,
) -> tuple[EvidenceIndex, Mock, HashEmbedder]:
    embedder = HashEmbedder(settings.text_vector_size, settings.visual_vector_size)
    vectors = {
        "text": models.VectorParams(
            size=text_size or embedder.text_size,
            distance=models.Distance.COSINE,
        ),
        "visual": models.VectorParams(
            size=embedder.visual_size,
            distance=models.Distance.COSINE,
        ),
    }
    if include_extra_vector:
        vectors["legacy"] = models.VectorParams(
            size=embedder.text_size,
            distance=models.Distance.COSINE,
        )
    information = SimpleNamespace(config=SimpleNamespace(params=SimpleNamespace(vectors=vectors)))
    client = Mock()
    client.collection_exists.return_value = True
    client.get_collection.return_value = information
    client.retrieve.return_value = (
        [] if marker_payload is None else [SimpleNamespace(payload=marker_payload)]
    )
    client.count.return_value = SimpleNamespace(count=point_count)
    index = object.__new__(EvidenceIndex)
    index.settings = settings
    index.embedder = embedder
    index.client = client
    return index, client, embedder


def test_existing_qdrant_schema_must_match_model_dimensions() -> None:
    vectors = {
        "text": models.VectorParams(size=384, distance=models.Distance.COSINE),
        "visual": models.VectorParams(size=512, distance=models.Distance.COSINE),
    }
    validate_named_vector_schema(vectors, {"text": 384, "visual": 512})
    with pytest.raises(RuntimeError, match="text"):
        validate_named_vector_schema(vectors, {"text": 768, "visual": 512})
    with pytest.raises(RuntimeError, match="visual"):
        validate_named_vector_schema({"text": vectors["text"]}, {"text": 384, "visual": 512})
    with pytest.raises(RuntimeError, match="text"):
        validate_named_vector_schema(
            {
                **vectors,
                "text": models.VectorParams(size=384, distance=models.Distance.DOT),
            },
            {"text": 384, "visual": 512},
        )
    with pytest.raises(RuntimeError, match="unexpected named vectors"):
        validate_named_vector_schema(
            {**vectors, "legacy": vectors["text"]},
            {"text": 384, "visual": 512},
        )


def test_remote_qdrant_client_ignores_ambient_proxy_environment(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class ClientProbe:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("crisisweave.vector_store.QdrantClient", ClientProbe)
    monkeypatch.setattr(EvidenceIndex, "_ensure_collection", lambda _self: None)
    configured = settings.model_copy(update={"qdrant_url": "https://qdrant.invalid"})

    EvidenceIndex(
        configured,
        HashEmbedder(configured.text_vector_size, configured.visual_vector_size),
    )

    assert captured["trust_env"] is False


def test_existing_collection_rejects_same_dimension_different_embedding(settings) -> None:
    embedder = HashEmbedder(settings.text_vector_size, settings.visual_vector_size)
    index = EvidenceIndex(settings, embedder)
    try:
        embedder.fingerprint = "f" * 64
        with pytest.raises(RuntimeError, match="fingerprint"):
            index._ensure_collection()  # noqa: SLF001 - startup compatibility gate
    finally:
        index.close()


def test_empty_matching_collection_without_marker_is_recovered(settings) -> None:
    index, client, embedder = _existing_collection_index(
        settings,
        marker_payload=None,
    )

    index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    client.count.assert_called_once_with(
        collection_name=settings.qdrant_collection,
        exact=True,
    )
    client.create_collection.assert_not_called()
    client.upsert.assert_called_once()
    marker = client.upsert.call_args.kwargs["points"][0]
    assert marker.id == SCHEMA_POINT_ID
    assert marker.payload == {
        "_crisisweave_schema": True,
        "embedding_fingerprint": embedder.fingerprint,
    }
    assert client.upsert.call_args.kwargs["wait"] is True


def test_recovery_restores_external_payload_indexes_before_marker(settings) -> None:
    configured = settings.model_copy(update={"qdrant_url": "https://qdrant.invalid"})
    index, client, _ = _existing_collection_index(
        configured,
        marker_payload=None,
    )
    initial = client.get_collection.return_value
    initial.payload_schema = {}
    keyword = SimpleNamespace(data_type=models.PayloadSchemaType.KEYWORD)
    refreshed = SimpleNamespace(
        config=initial.config,
        payload_schema={field: keyword for field in ("tenant_id", "document_id", "modality")},
    )
    client.get_collection.side_effect = [initial, refreshed]

    index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    created_fields = {
        call.kwargs["field_name"] for call in client.create_payload_index.call_args_list
    }
    assert created_fields == {"tenant_id", "document_id", "modality"}
    method_names = [call[0] for call in client.method_calls]
    assert max(
        position for position, name in enumerate(method_names) if name == "create_payload_index"
    ) < method_names.index("upsert")


def test_matching_marker_uses_existing_collection_without_recovery(settings) -> None:
    embedder = HashEmbedder(settings.text_vector_size, settings.visual_vector_size)
    index, client, _ = _existing_collection_index(
        settings,
        marker_payload={
            "_crisisweave_schema": True,
            "embedding_fingerprint": embedder.fingerprint,
        },
        point_count=12,
    )

    index._ensure_collection()  # noqa: SLF001 - exercises startup compatibility gate

    client.count.assert_not_called()
    client.upsert.assert_not_called()


def test_production_runtime_never_provisions_qdrant_schema(settings) -> None:
    configured = settings.model_copy(
        update={"app_env": "production", "qdrant_url": "https://qdrant.invalid"}
    )
    index, client, _ = _existing_collection_index(configured, marker_payload=None)
    index._provision_schema = False  # noqa: SLF001 - explicit production contract

    with pytest.raises(RuntimeError, match="run `crisisweave migrate`"):
        index._ensure_collection()  # noqa: SLF001
    client.create_collection.assert_not_called()
    client.create_payload_index.assert_not_called()
    client.upsert.assert_not_called()

    client.collection_exists.return_value = False
    with pytest.raises(RuntimeError, match="run `crisisweave migrate`"):
        index._ensure_collection()  # noqa: SLF001
    client.create_collection.assert_not_called()


def test_production_runtime_rejects_missing_payload_indexes_without_creating_them(
    settings,
) -> None:
    configured = settings.model_copy(
        update={"app_env": "production", "qdrant_url": "https://qdrant.invalid"}
    )
    embedder = HashEmbedder(configured.text_vector_size, configured.visual_vector_size)
    index, client, _ = _existing_collection_index(
        configured,
        marker_payload={
            "_crisisweave_schema": True,
            "embedding_fingerprint": embedder.fingerprint,
        },
    )
    client.get_collection.return_value.payload_schema = {}
    index._provision_schema = False  # noqa: SLF001 - explicit production contract

    with pytest.raises(RuntimeError, match="payload indexes are missing"):
        index._ensure_collection()  # noqa: SLF001
    client.create_payload_index.assert_not_called()


def test_nonempty_collection_without_marker_is_never_adopted(settings) -> None:
    index, client, _ = _existing_collection_index(
        settings,
        marker_payload=None,
        point_count=1,
    )

    with pytest.raises(RuntimeError, match="non-empty.*fingerprint marker"):
        index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    client.upsert.assert_not_called()


def test_mismatched_empty_collection_without_marker_is_never_adopted(settings) -> None:
    index, client, _ = _existing_collection_index(
        settings,
        marker_payload=None,
        text_size=settings.text_vector_size + 1,
    )

    with pytest.raises(RuntimeError, match="vector schema mismatch"):
        index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    client.count.assert_not_called()
    client.upsert.assert_not_called()


def test_empty_collection_with_extra_vector_is_never_adopted(settings) -> None:
    index, client, _ = _existing_collection_index(
        settings,
        marker_payload=None,
        include_extra_vector=True,
    )

    with pytest.raises(RuntimeError, match="unexpected named vectors"):
        index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    client.count.assert_not_called()
    client.upsert.assert_not_called()


@pytest.mark.parametrize(
    "marker_payload",
    [
        {"_crisisweave_schema": True, "embedding_fingerprint": "conflict"},
        {"_crisisweave_schema": False, "embedding_fingerprint": "conflict"},
        {},
    ],
)
def test_conflicting_marker_is_never_replaced(
    settings,
    marker_payload: dict[str, object],
) -> None:
    index, client, _ = _existing_collection_index(
        settings,
        marker_payload=marker_payload,
    )

    with pytest.raises(RuntimeError, match="fingerprint mismatch|schema marker conflict"):
        index._ensure_collection()  # noqa: SLF001 - exercises startup recovery

    client.count.assert_not_called()
    client.upsert.assert_not_called()


def test_local_development_index_reopens_without_server_payload_indexes(
    settings,
) -> None:
    configured = settings.model_copy(update={"app_env": "development"})
    configured.ensure_directories()
    embedder = HashEmbedder(configured.text_vector_size, configured.visual_vector_size)
    first = EvidenceIndex(configured, embedder)
    first.close()
    second = EvidenceIndex(configured, embedder)
    try:
        assert second.healthcheck()
    finally:
        second.close()


@pytest.mark.parametrize(
    ("status", "optimizer", "expected"),
    [
        (models.CollectionStatus.GREEN, "ok", True),
        (models.CollectionStatus.YELLOW, "ok", True),
        (models.CollectionStatus.RED, "ok", False),
        (models.CollectionStatus.GREEN, SimpleNamespace(error="failed"), False),
    ],
)
def test_qdrant_readiness_rejects_degraded_collection(
    status: models.CollectionStatus,
    optimizer: object,
    expected: bool,
) -> None:
    information = SimpleNamespace(status=status, optimizer_status=optimizer)
    assert collection_is_ready(information) is expected


def test_qdrant_payload_indexes_are_mandatory() -> None:
    keyword = SimpleNamespace(data_type=models.PayloadSchemaType.KEYWORD)
    complete = SimpleNamespace(
        payload_schema={
            "tenant_id": keyword,
            "document_id": keyword,
            "modality": keyword,
        }
    )
    assert validate_payload_indexes(complete) == set()
    incomplete = SimpleNamespace(payload_schema={"tenant_id": keyword})
    assert validate_payload_indexes(incomplete) == {"document_id", "modality"}


def test_external_qdrant_payload_excludes_evidence_and_internal_paths() -> None:
    chunk = Chunk(
        id="chunk-id",
        tenant_id="a" * 32,
        document_id="document-id",
        source_name="sensitive-name.pdf",
        source_uri="https://example.invalid/private",
        modality=Modality.PDF_PAGE,
        text="sensitive evidence text",
        artifact_path="/data/artifacts/internal.jpg",
        metadata={"secret": "value"},
    )
    assert qdrant_filter_payload(chunk) == {
        "tenant_id": "a" * 32,
        "document_id": "document-id",
        "modality": "pdf_page",
    }
