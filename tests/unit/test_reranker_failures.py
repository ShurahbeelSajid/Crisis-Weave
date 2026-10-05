from __future__ import annotations

import math

import pytest

from crisisweave.models import Evidence, Modality
from crisisweave.reranking import CrossEncoderReranker


class _Scores:
    def __init__(self, values: list[float]) -> None:
        self.values = values

    def predict(self, _pairs: object, **_kwargs: object) -> list[float]:
        return self.values


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -float("inf")])
def test_cross_encoder_rejects_nonfinite_scores(score: float) -> None:
    reranker = object.__new__(CrossEncoderReranker)
    reranker._model = _Scores([score])  # noqa: SLF001
    evidence = [
        Evidence(
            id="e1",
            document_id="d1",
            source_name="source",
            modality=Modality.TEXT,
            text="wildfire smoke",
            score=0.8,
        )
    ]
    with pytest.raises(RuntimeError, match="non-finite"):
        reranker.rerank("wildfire", evidence, 1)


@pytest.mark.parametrize("score", [1e308, -1e308])
def test_cross_encoder_sigmoid_is_stable_for_extreme_finite_scores(score: float) -> None:
    reranker = object.__new__(CrossEncoderReranker)
    reranker._model = _Scores([score])  # noqa: SLF001
    evidence = [
        Evidence(
            id="e1",
            document_id="d1",
            source_name="source",
            modality=Modality.TEXT,
            text="wildfire smoke",
            score=0.8,
        )
    ]
    result = reranker.rerank("wildfire", evidence, 1)
    assert result[0].rerank_score is not None
    assert math.isfinite(result[0].rerank_score)


def test_cross_encoder_requests_raw_logits_before_applying_sigmoid() -> None:
    class CapturingScores(_Scores):
        activation: object | None = None

        def predict(self, _pairs: object, **kwargs: object) -> list[float]:
            self.activation = kwargs.get("activation_fn")
            return self.values

    model = CapturingScores([0.0])
    reranker = object.__new__(CrossEncoderReranker)
    reranker._model = model  # noqa: SLF001
    reranker._raw_activation = object()  # noqa: SLF001
    evidence = [
        Evidence(
            id="e1",
            document_id="d1",
            source_name="source",
            modality=Modality.TEXT,
            text="wildfire smoke",
            score=0.8,
        )
    ]
    reranker.rerank("wildfire", evidence, 1)
    assert model.activation is reranker._raw_activation  # noqa: SLF001
