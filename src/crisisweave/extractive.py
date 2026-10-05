"""Deterministic, citation-safe synthesis for the zero-model local runtime."""

from __future__ import annotations

import re
from dataclasses import dataclass

from crisisweave.models import Evidence, Modality

CANONICAL_ABSTENTION = "I do not have enough authorized evidence to answer this question."

_VISUAL_MODALITIES = {Modality.IMAGE, Modality.PDF_PAGE, Modality.VIDEO_FRAME}
_PLACEHOLDER_PATTERNS = (
    re.compile(r"^Rendered page \d+ from .+$", re.IGNORECASE),
    re.compile(r"^Visual evidence from .+$", re.IGNORECASE),
    re.compile(r"^Video frame at \d+(?:\.\d+)? seconds$", re.IGNORECASE),
)
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
_NARRATIVE_START = re.compile(
    r"\b(?:According to|Based on|Compared (?:to|with)|In (?:19|20)\d{2},|It is|"
    r"Regarding|The economic ripple)\b",
    re.IGNORECASE,
)
_FOCUSED_CLAUSE_END = re.compile(
    r",\s+(?:followed by|resulting in|whereas|while)\b",
    re.IGNORECASE,
)
_QUESTION_STOPWORDS = {
    "a",
    "about",
    "according",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "could",
    "did",
    "do",
    "does",
    "for",
    "from",
    "give",
    "how",
    "in",
    "is",
    "it",
    "me",
    "of",
    "on",
    "or",
    "report",
    "say",
    "show",
    "the",
    "this",
    "to",
    "was",
    "were",
    "what",
    "when",
    "where",
    "which",
    "who",
    "with",
}
_CONCEPT_ALIASES = {
    "big": "large",
    "greatest": "large",
    "highest": "large",
    "largest": "large",
    "maximum": "large",
    "most": "large",
    "people": "population",
    "persons": "population",
    "percentage": "proportion",
    "percent": "proportion",
    "share": "proportion",
    "toll": "count",
    "total": "count",
}
_COMPARATIVE_TERMS = {"highest", "largest", "maximum", "most", "share", "proportion"}
_NUMERIC_TERMS = {
    "amount",
    "count",
    "how many",
    "percent",
    "percentage",
    "proportion",
    "rate",
    "share",
    "total",
}
_BROAD_QUERY_TERMS = {
    "describe",
    "evidence",
    "happened",
    "recorded",
    "summarize",
    "summary",
}


@dataclass(frozen=True)
class _Candidate:
    label: int
    position: int
    text: str
    score: float


def _stem(token: str) -> str:
    value = token.casefold()
    for suffix in ("ingly", "edly", "ation", "ments", "ment", "ing", "ies", "ed", "es", "s"):
        if value.endswith(suffix) and len(value) - len(suffix) >= 4:
            if suffix == "ies":
                return f"{value[:-3]}y"
            return value[: -len(suffix)]
    return value


def _concepts(value: str) -> set[str]:
    concepts: set[str] = set()
    for raw_token in _TOKEN_RE.findall(value):
        token = _stem(raw_token)
        if len(token) < 2 or token in _QUESTION_STOPWORDS:
            continue
        concepts.add(_CONCEPT_ALIASES.get(token, token))
    return concepts


def is_provenance_only(item: Evidence) -> bool:
    """Recognize both new metadata and placeholders stored by older releases."""

    if item.metadata.get("prompt_injection_suspected"):
        return True
    if item.metadata.get("content_kind") == "provenance_only":
        return True
    if item.modality in _VISUAL_MODALITIES and item.metadata.get("text_available") is False:
        return True
    normalized = re.sub(r"\s+", " ", item.text).strip()
    return any(pattern.fullmatch(normalized) for pattern in _PLACEHOLDER_PATTERNS)


def eligible_evidence(evidence: list[Evidence]) -> list[Evidence]:
    return [item for item in evidence if item.text.strip() and not is_provenance_only(item)]


def requires_pixel_interpretation(query: str) -> bool:
    """Detect questions whose answer requires inspecting pixels, not OCR text."""

    lowered = re.sub(r"\s+", " ", query.casefold())
    explicit_phrases = (
        "bounding box",
        "burn scar",
        "in the image",
        "in the photo",
        "in the picture",
        "satellite image",
        "satellite imagery",
        "upper left",
        "upper right",
        "lower left",
        "lower right",
        "what color",
        "which area",
        "which region",
    )
    if any(phrase in lowered for phrase in explicit_phrases):
        return True
    visual_nouns = {"aerial", "frame", "image", "imagery", "map", "photo", "picture", "video"}
    observation_terms = {
        "appears",
        "color",
        "depict",
        "location",
        "object",
        "shape",
        "visible",
        "where",
    }
    tokens = set(_TOKEN_RE.findall(lowered))
    return bool(tokens & visual_nouns and tokens & observation_terms)


def _analytics_result_answer(evidence: list[Evidence]) -> str | None:
    for label, item in enumerate(evidence, start=1):
        if (
            item.modality is not Modality.TABLE
            or item.metadata.get("generated_by") != "validated_read_only_sql"
            or item.metadata.get("prompt_injection_suspected")
        ):
            continue
        match = re.search(
            r"\bRows:\s*(?P<rows>.+?)(?:\s+Validated aggregate\b|$)",
            item.text,
            flags=re.DOTALL,
        )
        if not match:
            continue
        rows = re.sub(r"\s+", " ", match.group("rows")).strip()
        if not rows or rows == "[]":
            continue
        return (
            "Here is the strongest evidence available:"
            f"\n- Validated analytics rows: {rows} [E{label}]."
            "\nThis is an evidence summary, not operational emergency guidance."
        )
    return None


def _provenance_lookup_answer(query: str, evidence: list[Evidence]) -> str | None:
    lowered = query.casefold()
    lookup_intent = any(
        term in lowered
        for term in ("citation", "file", "find", "locate", "source", "visual evidence")
    )
    if not lookup_intent:
        return None
    for label, item in enumerate(evidence, start=1):
        if item.metadata.get("prompt_injection_suspected") or not item.text.strip():
            continue
        source_match = item.source_name.casefold() in lowered
        placeholder_match = any(
            pattern.fullmatch(re.sub(r"\s+", " ", item.text).strip())
            for pattern in _PLACEHOLDER_PATTERNS
        )
        if not source_match or not placeholder_match:
            continue
        statement = re.sub(r"\s+", " ", item.text).strip().rstrip(".!?")
        return (
            "Here is the strongest evidence available:"
            f"\n- {statement} [E{label}]."
            "\nThis is an evidence summary, not operational emergency guidance."
        )
    return None


def _sentences(text: str) -> list[str]:
    # Repair only line-wrap hyphenation commonly produced by OCR; no factual text is generated.
    normalized = re.sub(r"(?<=\w)-\s+(?=\w)", "", text)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if not normalized:
        return []
    initial = [item.strip() for item in _SENTENCE_BOUNDARY.split(normalized) if item.strip()]
    result: list[str] = []
    for item in initial:
        if len(item) <= 700:
            result.append(item)
            continue
        clauses = [part.strip() for part in re.split(r"(?<=;)\s+", item) if part.strip()]
        if len(clauses) > 1 and all(len(part) <= 700 for part in clauses):
            result.extend(clauses)
            continue
        words = item.split()
        for start in range(0, len(words), 80):
            result.append(" ".join(words[start : start + 80]))
    return result


def _narrative_variants(sentence: str) -> list[str]:
    variants = [sentence]
    broken_prefix = re.match(r"^[a-z]{1,15},\s+(?P<remainder>[A-Z].+)$", sentence)
    if broken_prefix:
        variants.append(broken_prefix.group("remainder"))
    for match in _NARRATIVE_START.finditer(sentence):
        suffix = sentence[match.start() :].strip()
        if match.start() >= 3 and len(suffix) >= 40:
            variants.append(suffix)
    for variant in list(variants):
        clause_end = _FOCUSED_CLAUSE_END.search(variant)
        if clause_end and clause_end.start() >= 40:
            variants.append(variant[: clause_end.start()].strip())
    return variants[-6:]


def _score_candidate(
    query: str,
    query_concepts: set[str],
    text: str,
    retrieval_score: float,
) -> float:
    candidate_concepts = _concepts(text)
    overlap = len(query_concepts & candidate_concepts)
    coverage = overlap / max(1, len(query_concepts))
    specificity = overlap / max(3, min(12, len(candidate_concepts)))
    lowered_query = query.casefold()
    lowered_text = text.casefold()
    score = 0.72 * coverage + 0.12 * specificity + 0.16 * retrieval_score
    if any(term in lowered_query for term in _COMPARATIVE_TERMS) and (
        any(term in lowered_text for term in _COMPARATIVE_TERMS) or "leading" in lowered_text
    ):
        score += 0.12
    if any(term in lowered_query for term in _NUMERIC_TERMS) and re.search(r"\d", text):
        score += 0.08
    if "how many" in lowered_query:
        if re.search(
            r"\b\d[\d,.]*\s+(?:billion|hundred|million|people|persons|thousand)\b",
            lowered_text,
        ):
            score += 0.14
        elif re.search(r"\d[\d,.]*\s*%", lowered_text):
            score -= 0.08
    if len(text) > 160 and re.search(r"\b(?:figure|table)\s+\d+\b", lowered_text):
        # Captions and chart-label dumps are useful retrieval context but make poor
        # standalone answers when a grammatical narrative sentence is available.
        score -= 0.20
    significant_phrases = [
        phrase
        for phrase in re.findall(r"[a-z0-9]+(?:\s+[a-z0-9]+){1,3}", lowered_query)
        if len(_concepts(phrase)) >= 2
    ]
    if any(phrase in lowered_text for phrase in significant_phrases):
        score += 0.08
    return score


def _candidate_passages(query: str, evidence: list[Evidence]) -> list[_Candidate]:
    query_concepts = _concepts(query)
    if not query_concepts:
        return []
    candidates: list[_Candidate] = []
    for label, item in enumerate(evidence, start=1):
        retrieval_score = item.rerank_score if item.rerank_score is not None else item.score
        for position, sentence in enumerate(_sentences(item.text)):
            for variant in _narrative_variants(sentence):
                score = _score_candidate(query, query_concepts, variant, retrieval_score)
                candidates.append(
                    _Candidate(label=label, position=position, text=variant, score=score)
                )
    return sorted(candidates, key=lambda item: (item.score, -len(item.text)), reverse=True)


def _select_candidates(query: str, candidates: list[_Candidate]) -> list[_Candidate]:
    if not candidates or candidates[0].score < 0.34:
        return []
    top = candidates[0]
    query_concepts = _concepts(query)
    if len(query_concepts) >= 3 and len(query_concepts & _concepts(top.text)) < 2:
        return []
    selected = [top]
    broad_query = any(term in query.casefold() for term in _BROAD_QUERY_TERMS)
    if not broad_query:
        return selected
    for candidate in candidates[1:]:
        if len(selected) >= 3:
            break
        selected_texts = {item.text.casefold() for item in selected}
        if candidate.text.casefold() in selected_texts or any(
            candidate.text.casefold() in text or text in candidate.text.casefold()
            for text in selected_texts
        ):
            continue
        adjacent = candidate.label == top.label and abs(candidate.position - top.position) == 1
        threshold = 0.12 if adjacent else max(0.38, top.score * 0.78)
        if candidate.score >= threshold:
            selected.append(candidate)
    return sorted(selected, key=lambda item: (item.label, item.position))


def extractive_answer(query: str, evidence: list[Evidence]) -> str:
    """Return only query-matched source statements, each with its real evidence label."""

    if requires_pixel_interpretation(query):
        return CANONICAL_ABSTENTION
    analytics_answer = _analytics_result_answer(evidence)
    if analytics_answer is not None:
        return analytics_answer
    provenance_answer = _provenance_lookup_answer(query, evidence)
    if provenance_answer is not None:
        return provenance_answer
    usable = eligible_evidence(evidence)
    if not usable:
        return CANONICAL_ABSTENTION
    selected = _select_candidates(query, _candidate_passages(query, usable))
    if not selected:
        return CANONICAL_ABSTENTION

    # Labels must refer to the original context order expected by the output verifier.
    original_labels = {item.id: index for index, item in enumerate(evidence, start=1)}
    usable_labels = {index: original_labels[item.id] for index, item in enumerate(usable, start=1)}
    lines = ["Here is the strongest evidence available:"]
    for item in selected:
        statement = re.sub(r"\[[eE](?:[1-9]|[12]\d|30)\]", "[source label]", item.text)
        statement = statement.strip().rstrip(".!?").strip()
        if statement:
            statement = f"{statement[:1].upper()}{statement[1:]}"
            lines.append(f"\n- {statement} [E{usable_labels[item.label]}].")
    if len(lines) == 1:
        return CANONICAL_ABSTENTION
    lines.append("\nThis is an evidence summary, not operational emergency guidance.")
    return "".join(lines)
