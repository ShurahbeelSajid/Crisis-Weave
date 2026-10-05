from __future__ import annotations

import io

from fastapi.testclient import TestClient
from PIL import Image

from crisisweave.api import create_app


def test_image_region_provenance_survives_ingestion_retrieval_and_public_projection(
    settings,
) -> None:
    content = io.BytesIO()
    Image.new("RGB", (40, 20), "orange").save(content, format="PNG")
    headers = {"X-API-Key": "test-alpha-key"}

    with TestClient(create_app(settings)) as client:
        uploaded = client.post(
            "/v1/documents",
            headers=headers,
            files={"file": ("region-scene.png", content.getvalue(), "image/png")},
        )
        assert uploaded.status_code == 201, uploaded.text

        queried = client.post(
            "/v1/query",
            headers=headers,
            json={
                "query": "Find the visual evidence file region-scene.png.",
                "top_k": 5,
                "include_modalities": ["image"],
            },
        )
        assert queried.status_code == 200

    payload = queried.json()
    evidence = next(
        item for item in payload["evidence"] if item["source_name"] == "region-scene.png"
    )
    citation = next(
        item for item in payload["citations"] if item["source_name"] == "region-scene.png"
    )
    for item in (evidence, citation):
        assert item["regions"] == [
            {
                "kind": "image_bbox",
                "bbox": {"x_min": 0.0, "y_min": 0.0, "x_max": 1.0, "y_max": 1.0},
                "label": "entire normalized image",
                "source": "derived_provenance",
            }
        ]
        assert "artifact_path" not in item
    assert any("does not assert claim-level" in item for item in payload["warnings"])
