"""Small reranking adapters that keep final context diverse and bounded."""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Protocol

from crisisweave.config import Settings
from crisisweave.extractive import is_provenance_only
from crisisweave.models import Evidence, Modality


class Reranker(Protocol):
    def rerank(self, query: str, evidence: list[Evidence], limit: int) -> list[Evidence]: ...


def _tokens(value: str) -> set[str]:
    return {
        token.casefold()
        for token in re.findall(r"[^\W_]+", value, flags=re.UNICODE)
        if len(token) > 2
    }


class LexicalReranker:
    def rerank(self, query: str, evidence: list[Evidence], limit: int) -> list[Evidence]:
        query_tokens = _tokens(query)
        ranked: list[Evidence] = []
        for item in evidence:
            item_tokens = _tokens(item.text)
            overlap = len(query_tokens & item_tokens) / max(1, len(query_tokens))
            # Hash-vector scores are useful for candidate generation, but exact query
            # coverage is the stronger signal in the dependency-free local runtime.
            score = 0.2 * item.score + 0.8 * overlap
            if "how many" in query.casefold() and re.search(
                r"\b\d[\d,.]*\s+(?:billion|hundred|million|people|persons|thousand)\b",
                item.text,
                flags=re.IGNORECASE,
            ):
                score += 0.12
            if is_provenance_only(item):
                score *= 0.05
            if item.metadata.get("prompt_injection_suspected"):
                score *= 0.75
            ranked.append(item.model_copy(update={"rerank_score": max(0.0, min(1.0, score))}))
        ranked.sort(key=lambda item: item.rerank_score or 0.0, reverse=True)
        return _diversify(ranked, limit)


class CrossEncoderReranker:
    def __init__(self, settings: Settings) -> None:
        try:
            from sentence_transformers import CrossEncoder
            from torch import nn
        except ImportError as exc:
            raise RuntimeError("Install the 'ml' extra for cross-encoder reranking") from exc
        self._model = CrossEncoder(
            settings.reranker_model,
            trust_remote_code=False,
            local_files_only=settings.model_local_files_only,
        )
        self._raw_activation = nn.Identity()

    def rerank(self, query: str, evidence: list[Evidence], limit: int) -> list[Evidence]:
        if not evidence:
            return []
        pairs = [(query, item.text) for item in evidence]
        raw_activation = getattr(self, "_raw_activation", None)
        if raw_activation is None:
            # Test doubles and older serialized instances take this compatibility path.
            scores = self._model.predict(pairs)
        else:
            scores = self._model.predict(pairs, activation_fn=raw_activation)
        ranked = []
        for item, raw_score in zip(evidence, scores, strict=True):
            numeric_score = float(raw_score)
            if not math.isfinite(numeric_score):
                raise RuntimeError("Cross-encoder returned a non-finite score")
            if numeric_score >= 0:
                cross_score = 1.0 / (1.0 + math.exp(-min(numeric_score, 700.0)))
            else:
                exponent = math.exp(max(numeric_score, -700.0))
                cross_score = exponent / (1.0 + exponent)
            visual_without_ocr = item.modality in {
                Modality.IMAGE,
                Modality.PDF_PAGE,
                Modality.VIDEO_FRAME,
            } and not (
                item.metadata.get("ocr_available", False)
                or item.metadata.get("text_available", False)
            )
            if visual_without_ocr:
                normalized = 0.35 * cross_score + 0.65 * item.score
            else:
                normalized = 0.7 * cross_score + 0.3 * item.score
            if item.metadata.get("prompt_injection_suspected"):
                normalized *= 0.75
            ranked.append(item.model_copy(update={"rerank_score": normalized}))
        ranked.sort(key=lambda item: item.rerank_score or 0.0, reverse=True)
        return _diversify(ranked, limit)


def _diversify(ranked: list[Evidence], limit: int) -> list[Evidence]:
    if len({item.document_id for item in ranked}) <= 1:
        return ranked[:limit]
    per_document: defaultdict[str, int] = defaultdict(int)
    result: list[Evidence] = []
    for item in ranked:
        if per_document[item.document_id] >= 3:
            continue
        per_document[item.document_id] += 1
        result.append(item)
        if len(result) >= limit:
            break
    return result


def build_reranker(settings: Settings) -> Reranker:
    if settings.reranker_provider == "cross_encoder":
        return CrossEncoderReranker(settings)
    return LexicalReranker()
