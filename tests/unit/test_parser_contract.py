from __future__ import annotations

import math
import uuid

import pytest

from crisisweave.ingestion import validate_remote_visual_vectors
from crisisweave.models import Chunk, Modality


def _visual_chunk() -> Chunk:
    return Chunk(
        id=str(uuid.uuid4()),
        tenant_id="a" * 32,
        document_id=str(uuid.uuid4()),
        source_name="evidence.png",
        modality=Modality.IMAGE,
        artifact_path="image.jpg",
    )


def _payload(chunk: Chunk, size: int = 4) -> dict[str, object]:
    return {
        "embedding_fingerprint": "f" * 64,
        "visual_vector_size": size,
        "visual_vectors": {chunk.id: [1.0, *([0.0] * (size - 1))]},
    }


def test_remote_visual_vector_contract_accepts_only_exact_normalized_mapping() -> None:
    chunk = _visual_chunk()
    result = validate_remote_visual_vectors(
        _payload(chunk),
        [chunk],
        expected_fingerprint="f" * 64,
        expected_size=4,
    )
    assert result == {chunk.id: [1.0, 0.0, 0.0, 0.0]}


@pytest.mark.parametrize(
    "mutation",
    [
        "fingerprint",
        "size",
        "missing",
        "extra",
        "bool",
        "string",
        "nan",
        "inf",
        "zero",
        "non_normalized",
        "huge_integer",
    ],
)
def test_remote_visual_vector_contract_rejects_malformed_vectors(mutation: str) -> None:
    chunk = _visual_chunk()
    payload = _payload(chunk)
    vectors = payload["visual_vectors"]
    assert isinstance(vectors, dict)
    if mutation == "fingerprint":
        payload["embedding_fingerprint"] = "0" * 64
    elif mutation == "size":
        payload["visual_vector_size"] = 3
    elif mutation == "missing":
        vectors.clear()
    elif mutation == "extra":
        vectors["extra"] = [1.0, 0.0, 0.0, 0.0]
    elif mutation == "bool":
        vectors[chunk.id] = [True, 0.0, 0.0, 0.0]
    elif mutation == "string":
        vectors[chunk.id] = ["1", 0.0, 0.0, 0.0]
    elif mutation == "nan":
        vectors[chunk.id] = [math.nan, 0.0, 0.0, 0.0]
    elif mutation == "inf":
        vectors[chunk.id] = [math.inf, 0.0, 0.0, 0.0]
    elif mutation == "zero":
        vectors[chunk.id] = [0.0, 0.0, 0.0, 0.0]
    elif mutation == "huge_integer":
        vectors[chunk.id] = [10**400, 0.0, 0.0, 0.0]
    else:
        vectors[chunk.id] = [0.5, 0.0, 0.0, 0.0]
    with pytest.raises(ValueError):
        validate_remote_visual_vectors(
            payload,
            [chunk],
            expected_fingerprint="f" * 64,
            expected_size=4,
        )
