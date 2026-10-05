"""A bounded LangGraph where model proposals never bypass deterministic policy."""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, NotRequired, TypedDict

from langgraph.graph import END, START, StateGraph

from crisisweave.config import Settings
from crisisweave.execution import BlockingRunner
from crisisweave.llm import ModelGateway, Plan, PlannedTool
from crisisweave.models import (
    Citation,
    Concordance,
    ConflictSignal,
    ConflictStatus,
    Evidence,
    EvidenceView,
    Modality,
    QueryRequest,
    QueryResponse,
    QueryUsageSummary,
    Route,
    SourceFreshness,
    SourceFreshnessStatus,
    ToolTrace,
    source_time_from_metadata,
)
from crisisweave.observability import capture_operation_usage, observe_stage
from crisisweave.reranking import Reranker
from crisisweave.security import SecurityError, assess_prompt
from crisisweave.storage import MetadataStoreProtocol
from crisisweave.vector_store import EvidenceIndex
from crisisweave.web_search import WebSearch

_CANONICAL_ABSTENTION = "I do not have enough authorized evidence to answer this question."


def _observed_retrieval_tools(tools: Iterable[PlannedTool]) -> Iterator[PlannedTool]:
    """Keep one low-cardinality retrieval span open for each complete tool iteration."""

    for tool in tools:
        with observe_stage("retrieval"):
            yield tool


class AgentState(TypedDict):
    tenant_id: str
    request: QueryRequest
    started_at: float
    query: NotRequired[str]
    plan: NotRequired[Plan]
    evidence: NotRequired[list[Evidence]]
    analytics: NotRequired[list[dict[str, Any]]]
    traces: NotRequired[list[ToolTrace]]
    routes: NotRequired[list[Route]]
    warnings: NotRequired[list[str]]
    answer: NotRequired[str]
    pixel_labels: NotRequired[set[int]]
    citations: NotRequired[list[Citation]]
    concordance: NotRequired[Concordance]
    claim_evidence_conflict: NotRequired[ConflictSignal]
    cross_source_conflict: NotRequired[ConflictSignal]
    source_freshness: NotRequired[SourceFreshness]
    blocked: NotRequired[bool]


class CrisisAgent:
    def __init__(
        self,
        settings: Settings,
        store: MetadataStoreProtocol,
        index: EvidenceIndex,
        reranker: Reranker,
        model: ModelGateway,
        web: WebSearch,
        blocking_runner: BlockingRunner | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.index = index
        self.reranker = reranker
        self.model = model
        self.web = web
        self.blocking_runner = blocking_runner
        self.graph = self._build_graph()

    def _build_graph(self) -> Any:
        workflow = StateGraph(AgentState)
        workflow.add_node("guard", self._guard)
        workflow.add_node("blocked", self._blocked)
        workflow.add_node("route", self._route)
        workflow.add_node("execute", self._execute)
        workflow.add_node("rerank", self._rerank)
        workflow.add_node("synthesize", self._synthesize)
        workflow.add_node("verify", self._verify)
        workflow.add_edge(START, "guard")
        workflow.add_conditional_edges(
            "guard",
            lambda state: "blocked" if state.get("blocked") else "route",
            {"blocked": "blocked", "route": "route"},
        )
        workflow.add_edge("blocked", END)
        workflow.add_edge("route", "execute")
        workflow.add_edge("execute", "rerank")
        workflow.add_edge("rerank", "synthesize")
        workflow.add_edge("synthesize", "verify")
        workflow.add_edge("verify", END)
        return workflow.compile()

    async def _blocking(self, function: Any, *args: Any) -> Any:
        runner = getattr(self, "blocking_runner", None)
        if runner is None:
            return await asyncio.to_thread(function, *args)
        return await runner.run(function, *args)

    async def _guard(self, state: AgentState) -> dict[str, Any]:
        assessment = assess_prompt(state["request"].query)
        if assessment.suspicious and self.settings.strict_prompt_guard:
            return {
                "query": assessment.sanitized,
                "blocked": True,
                "warnings": ["The request matched the direct prompt-injection policy"],
            }
        return {
            "query": assessment.sanitized,
            "blocked": False,
            "warnings": ["Suspicious prompt pattern observed"] if assessment.suspicious else [],
        }

    async def _blocked(self, state: AgentState) -> dict[str, Any]:
        return {
            "answer": (
                "I cannot process instructions that attempt to override system or tool policy."
            ),
            "routes": [],
            "evidence": [],
            "analytics": [],
            "traces": [],
            "citations": [],
            "concordance": Concordance(
                score=0.0,
                source_count=0,
                modality_count=0,
                rationale="No tools ran because the input policy blocked the request.",
            ),
        }

    async def _route(self, state: AgentState) -> dict[str, Any]:
        plan = await self.model.plan(state["query"], state["request"].allow_web)
        return {"plan": plan, "warnings": [*state.get("warnings", []), *plan.warnings]}

    async def _execute(self, state: AgentState) -> dict[str, Any]:
        evidence: list[Evidence] = []
        analytics: list[dict[str, Any]] = []
        traces: list[ToolTrace] = []
        routes: list[Route] = []
        warnings = list(state.get("warnings", []))
        plan = state["plan"]
        for tool in _observed_retrieval_tools(plan.tools[: self.settings.max_tool_calls]):
            started = time.perf_counter()
            count = 0
            status = "ok"
            summary = (tool.query or tool.sql)[:160]
            try:
                if tool.route == Route.VECTOR:
                    requested_modalities = state["request"].include_modalities
                    modalities = (
                        requested_modalities
                        if requested_modalities is not None
                        else tool.modalities
                    )
                    excluded_document_ids = await self._blocking(
                        self.store.non_ready_document_ids,
                        state["tenant_id"],
                    )
                    hits = await self._blocking(
                        self.index.search,
                        state["tenant_id"],
                        tool.query or state["query"],
                        self.settings.retrieval_candidate_count,
                        modalities,
                        excluded_document_ids,
                    )
                    authoritative_chunks = await self._blocking(
                        self.store.get_chunks,
                        state["tenant_id"],
                        [item.id for item in hits],
                    )
                    scores = {item.id: item.score for item in hits}
                    found = [
                        Evidence.model_validate(
                            {**item.model_dump(mode="python"), "score": scores[item.id]}
                        )
                        for item in authoritative_chunks
                        if item.id in scores
                    ]
                    ready_ids = await self._blocking(
                        self.store.ready_document_ids,
                        state["tenant_id"],
                        {item.document_id for item in found},
                    )
                    found = [item for item in found if item.document_id in ready_ids]
                    evidence.extend(found)
                    count = len(found)
                elif tool.route == Route.SQL:
                    if (
                        state["request"].include_modalities is not None
                        and Modality.TABLE not in state["request"].include_modalities
                    ):
                        raise SecurityError(
                            "SQL table evidence is outside the requested modalities"
                        )
                    analytics_result = await self._blocking(
                        self.store.execute_safe_analytics_with_sources,
                        state["tenant_id"],
                        tool.sql,
                        100,
                        10,
                    )
                    safe_sql = analytics_result.sql
                    rows = analytics_result.rows
                    sources = analytics_result.sources
                    source_total = analytics_result.source_count
                    source_count_exact = analytics_result.source_count_exact
                    analytics.append({"sql": safe_sql, "rows": rows})
                    source_scope = (
                        str(source_total) if source_count_exact else f"at least {source_total}"
                    )
                    for source in sources if rows else []:
                        source_content = json.dumps(
                            analytics_result.source_rows.get(source.id, []),
                            ensure_ascii=False,
                            default=str,
                        )
                        assessment = assess_prompt(source_content)
                        evidence_id = str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                f"{state['tenant_id']}:{safe_sql}:{source_content}:{source.id}",
                            )
                        )
                        evidence.append(
                            Evidence(
                                id=evidence_id,
                                tenant_id=state["tenant_id"],
                                document_id=source.id,
                                source_name=source.filename,
                                source_uri=source.source_uri,
                                modality=Modality.TABLE,
                                text=(
                                    f"Rows: {assessment.sanitized[:6000]}\n"
                                    f"Validated aggregate across {source_scope} authorized "
                                    f"structured source(s); {source.filename} contributed to "
                                    f"the returned rows. SQL: {safe_sql}"
                                ),
                                score=1.0,
                                metadata={
                                    "generated_by": "validated_read_only_sql",
                                    "contributing_source_count": (
                                        source_total if source_count_exact else None
                                    ),
                                    "contributing_source_count_lower_bound": (
                                        None if source_count_exact else source_total
                                    ),
                                    "source_count_exact": source_count_exact,
                                    "prompt_injection_suspected": assessment.suspicious,
                                },
                            )
                        )
                    if not source_count_exact:
                        warnings.append(
                            "Analytics provenance was bounded; its source count is a lower bound."
                        )
                    elif source_total > len(sources):
                        warnings.append(
                            "Analytics provenance citations were capped at 10 contributing sources."
                        )
                    count = len(rows)
                elif tool.route == Route.WEB:
                    if not state["request"].allow_web:
                        raise SecurityError("Web search was not authorized by the request")
                    if self.settings.web_search_provider == "disabled":
                        raise SecurityError("Web search is not configured")
                    if (
                        state["request"].include_modalities is not None
                        and Modality.WEB not in state["request"].include_modalities
                    ):
                        raise SecurityError("Web evidence is outside the requested modalities")
                    found = await self.web.search(state["tenant_id"], tool.query, 5)
                    evidence.extend(found)
                    count = len(found)
                if tool.route not in routes:
                    routes.append(tool.route)
            except SecurityError as exc:
                status = "rejected"
                warnings.append(f"{tool.route.value} tool rejected: {str(exc)[:180]}")
            except Exception as exc:
                status = "error"
                warnings.append(f"{tool.route.value} tool unavailable ({type(exc).__name__})")
            duration_ms = (time.perf_counter() - started) * 1000
            traces.append(
                ToolTrace(
                    tool=tool.route,
                    input_summary=summary,
                    result_count=count,
                    duration_ms=duration_ms,
                    status=status,
                )
            )
        return {
            "evidence": _deduplicate(evidence),
            "analytics": analytics,
            "traces": traces,
            "routes": routes,
            "warnings": warnings,
        }

    async def _rerank(self, state: AgentState) -> dict[str, Any]:
        with observe_stage("reranking"):
            return await self._rerank_unobserved(state)

    async def _rerank_unobserved(self, state: AgentState) -> dict[str, Any]:
        warnings = list(state.get("warnings", []))
        try:
            reranked = await self._blocking(
                self.reranker.rerank,
                state["query"],
                state.get("evidence", []),
                state["request"].top_k,
            )
        except Exception as exc:
            reranked = sorted(state.get("evidence", []), key=lambda item: item.score, reverse=True)[
                : state["request"].top_k
            ]
            warnings.append(f"Reranker unavailable; retrieval order used ({type(exc).__name__})")
        if any(item.metadata.get("prompt_injection_suspected") for item in reranked):
            warnings.append("One or more evidence units matched the indirect-injection detector")
        return {"evidence": reranked, "warnings": warnings}

    async def _synthesize(self, state: AgentState) -> dict[str, Any]:
        evidence = state.get("evidence", [])
        if not evidence:
            return {
                "answer": _CANONICAL_ABSTENTION,
                "evidence": [],
                "pixel_labels": set(),
                "warnings": [
                    *state.get("warnings", []),
                    "Synthesis abstained because no evidence was available",
                ],
            }
        context_evidence = self.model.select_context(evidence)
        if not context_evidence:
            return {
                "answer": _CANONICAL_ABSTENTION,
                "evidence": [],
                "pixel_labels": set(),
                "warnings": [
                    *state.get("warnings", []),
                    "Synthesis abstained because no evidence was available",
                ],
            }
        answer, warnings, pixel_labels = await self.model.answer(
            state["query"], context_evidence, state.get("analytics", [])
        )
        return {
            "answer": answer,
            "evidence": context_evidence,
            "pixel_labels": pixel_labels,
            "warnings": [*state.get("warnings", []), *warnings],
        }

    async def _verify(self, state: AgentState) -> dict[str, Any]:
        evidence = state.get("evidence", [])
        allowed = {index: item for index, item in enumerate(evidence, start=1)}
        answer = state["answer"]
        citation_tokens = set(re.findall(r"\[[eE][^\]\r\n]*\]", answer))
        canonical_tokens = {
            token for token in citation_tokens if re.fullmatch(r"\[E(?:[1-9]|[12]\d|30)\]", token)
        }
        noncanonical_tokens = citation_tokens - canonical_tokens
        for token in noncanonical_tokens:
            answer = answer.replace(token, "[unsupported citation removed]")
        requested_labels = {int(value) for value in re.findall(r"\[E([1-9]|[12]\d|30)\]", answer)}
        invalid = requested_labels - set(allowed)
        warnings = list(state.get("warnings", []))
        pixel_labels = set(state.get("pixel_labels", set()))
        for label in invalid:
            answer = answer.replace(f"[E{label}]", "[unsupported citation removed]")
        if invalid or noncanonical_tokens:
            warnings.append("Unsupported model citation labels were removed")
        valid_labels = requested_labels & set(allowed)
        claim_evidence_conflict = _claim_evidence_conflict_signal(answer, allowed)
        cross_source_conflict = _cross_source_conflict_signal(evidence)
        if evidence and not valid_labels and answer != _CANONICAL_ABSTENTION:
            answer = (
                "I found potentially relevant evidence, but the generated draft did not provide a "
                "valid supporting citation, so I am withholding the answer."
            )
            warnings.append("Uncited model draft was withheld by the output verifier")
        elif valid_labels:
            unsupported_claims = _unsupported_claims(answer, allowed, pixel_labels)
            if unsupported_claims:
                answer = (
                    "I found potentially relevant evidence, but one or more generated claims were "
                    "not sufficiently tied to their cited evidence, so I am withholding the answer."
                )
                valid_labels = set()
                warnings.append("Weakly supported or uncited claims were withheld by the verifier")
        citations: list[Citation] = []
        for label in sorted(valid_labels):
            item = allowed[label]
            source_time = source_time_from_metadata(item.metadata)
            citations.append(
                Citation(
                    evidence_id=item.id,
                    label=f"E{label}",
                    source_name=item.source_name,
                    source_uri=item.source_uri,
                    page=item.page,
                    timestamp_seconds=item.timestamp_seconds,
                    source_observed_at=source_time[0] if source_time else None,
                    source_time_kind=source_time[1] if source_time else None,
                    regions=item.regions,
                )
            )
        if any(
            label in pixel_labels and allowed[label].modality in _VISUAL_CITATION_MODALITIES
            for label in valid_labels
        ):
            warnings.append(
                "Visual claim support is tied to cited pixels and requires "
                "vision-quality validation"
            )
        elif any(allowed[label].modality in _VISUAL_CITATION_MODALITIES for label in valid_labels):
            warnings.append(
                "Visual citations were grounded only in extracted text; cited pixels "
                "were not supplied to the answer model"
            )
        if any(allowed[label].regions for label in valid_labels):
            warnings.append(
                "Citation regions are source locators; the API does not assert claim-level "
                "visual entailment"
            )
        concordance = _concordance(evidence, state.get("routes", []))
        return {
            "answer": answer,
            "citations": citations,
            "concordance": concordance,
            "claim_evidence_conflict": claim_evidence_conflict,
            "cross_source_conflict": cross_source_conflict,
            "source_freshness": _source_freshness(
                evidence,
                getattr(getattr(self, "settings", None), "max_source_age_days", 30),
            ),
            "warnings": list(dict.fromkeys(warnings)),
        }

    async def ask(self, tenant_id: str, request: QueryRequest) -> QueryResponse:
        with (
            observe_stage("query"),
            capture_operation_usage(
                "query",
                compute_cost_per_hour=self.settings.query_compute_cost_per_hour_usd,
            ) as usage,
        ):
            response = await self._ask_unobserved(tenant_id, request)
        return response.model_copy(
            update={
                "usage": QueryUsageSummary(
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    model_cost_usd=usage.model_cost_usd,
                    compute_cost_usd=usage.compute_cost_usd,
                    total_cost_usd=usage.total_cost_usd,
                )
            }
        )

    async def _ask_unobserved(self, tenant_id: str, request: QueryRequest) -> QueryResponse:
        started = time.perf_counter()
        state = await self.graph.ainvoke(
            {"tenant_id": tenant_id, "request": request, "started_at": started}
        )
        duration_ms = (time.perf_counter() - started) * 1000
        response = QueryResponse(
            answer=state["answer"],
            routes=state.get("routes", []),
            citations=state.get("citations", []),
            evidence=[EvidenceView.from_internal(item) for item in state.get("evidence", [])],
            tool_trace=state.get("traces", []),
            concordance=state["concordance"],
            claim_evidence_conflict=state.get(
                "claim_evidence_conflict",
                ConflictSignal(),
            ),
            cross_source_conflict=state.get("cross_source_conflict", ConflictSignal()),
            source_freshness=state.get("source_freshness", SourceFreshness()),
            warnings=state.get("warnings", []),
        )
        try:
            await self._blocking(
                self.store.record_query_audit,
                tenant_id,
                request.query,
                [route.value for route in response.routes],
                len(response.citations),
                duration_ms,
                response.warnings,
            )
        except Exception as exc:
            response = response.model_copy(
                update={
                    "warnings": [
                        *response.warnings,
                        f"Audit persistence unavailable ({type(exc).__name__})",
                    ]
                }
            )
        return response


def _deduplicate(evidence: list[Evidence]) -> list[Evidence]:
    selected: dict[str, Evidence] = {}
    for item in evidence:
        prior = selected.get(item.id)
        if prior is None or item.score > prior.score:
            selected[item.id] = item
    return list(selected.values())


def _concordance(evidence: list[Evidence], routes: list[Route]) -> Concordance:
    sources = {item.source_name for item in evidence}
    modalities = {item.modality for item in evidence}
    average_score = (
        sum(item.rerank_score if item.rerank_score is not None else item.score for item in evidence)
        / len(evidence)
        if evidence
        else 0.0
    )
    score = (
        0.35 * min(1.0, len(sources) / 3)
        + 0.25 * min(1.0, len(modalities) / 3)
        + 0.25 * average_score
        + 0.15 * min(1.0, len(routes) / 2)
    )
    score = 0.0 if not evidence else round(max(0.0, min(1.0, score)), 3)
    if not evidence:
        rationale = "No supporting evidence was retrieved."
    elif len(sources) == 1:
        rationale = "Evidence came from one source; independent corroboration is still needed."
    else:
        rationale = (
            f"Evidence spans {len(sources)} sources and {len(modalities)} modalities; "
            "the score measures diversity and retrieval strength, not factual certainty."
        )
    return Concordance(
        score=score,
        source_count=len(sources),
        modality_count=len(modalities),
        rationale=rationale,
    )


_CLAIM_STOPWORDS = {
    "and",
    "are",
    "but",
    "for",
    "from",
    "has",
    "have",
    "into",
    "not",
    "that",
    "the",
    "their",
    "this",
    "was",
    "were",
    "with",
}
_VISUAL_CITATION_MODALITIES = {
    Modality.IMAGE,
    Modality.PDF_PAGE,
    Modality.VIDEO_FRAME,
}
_NEGATION_TOKENS = {
    "absent",
    "absence",
    "cannot",
    "closed",
    "denied",
    "denies",
    "deny",
    "invisible",
    "lack",
    "lacked",
    "lacks",
    "neither",
    "never",
    "no",
    "none",
    "not",
    "shut",
    "undetected",
    "without",
    "zero",
}
_ANTONYM_GROUPS = (
    (
        {
            "grew",
            "grow",
            "growing",
            "higher",
            "increase",
            "increased",
            "increases",
            "increasing",
            "rise",
            "risen",
            "rises",
            "rising",
            "rose",
        },
        {
            "decline",
            "declined",
            "declines",
            "declining",
            "decrease",
            "decreased",
            "decreases",
            "decreasing",
            "drop",
            "dropped",
            "drops",
            "fall",
            "fallen",
            "falling",
            "fell",
            "lower",
        },
    ),
    ({"above", "more"}, {"below", "fewer", "less"}),
    ({"after", "later"}, {"before", "earlier"}),
)
_CLAUSE_BOUNDARY = re.compile(
    r"(?:\r?\n+|(?<=[.!?;])\s+|\s+(?:but|however|whereas)\s+)", re.IGNORECASE
)
_CITATION_ONLY = re.compile(r"(?:\[E(?:[1-9]|[12]\d|30)\][\s,;:.!?-]*)+")
_REMOVED_CITATIONS_ONLY = re.compile(r"(?:\[unsupported citation removed\][\s,;:.!?-]*)+")
_NUMERIC_FACT = re.compile(
    r"(?<!\w)"
    r"(?P<sign_before>[+\-\N{MINUS SIGN}])?\s*"
    r"(?P<currency>[$\N{POUND SIGN}\N{EURO SIGN}\N{YEN SIGN}]|USD\b|GBP\b|EUR\b|JPY\b)?\s*"
    r"(?P<sign_after>[+\-\N{MINUS SIGN}])?\s*"
    r"(?P<number>(?:\d(?:\d|,(?=\d))*(?:\.\d+)?|\.\d+)(?:e[+\-]?\d+)?)"
    r"(?P<percent>\s*(?:%|percent\b))?"
    r"(?:\s+(?P<unit>[A-Za-z][A-Za-z-]{0,31}))?"
    r"(?![\w,])",
    re.IGNORECASE,
)
_MAX_NUMERIC_LITERAL_LENGTH = 64
_MAX_ABSOLUTE_DECIMAL_EXPONENT = 10_000
_CURRENCY_ALIASES = {
    "$": "USD",
    "\N{POUND SIGN}": "GBP",
    "\N{EURO SIGN}": "EUR",
    "\N{YEN SIGN}": "JPY",
}
_CURRENCY_UNIT_ALIASES = {
    "dollar": "USD",
    "dollars": "USD",
    "pound": "GBP",
    "pounds": "GBP",
    "euro": "EUR",
    "euros": "EUR",
    "yen": "JPY",
}

NumericFact = tuple[Decimal, bool, str | None, str | None]


def _claim_tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) >= 3 and token not in _CLAIM_STOPWORDS
    }


def _polarity_words(value: str) -> list[str]:
    normalized = re.sub(r"n['\N{RIGHT SINGLE QUOTATION MARK}]t\b", " not", value.lower())
    return re.findall(r"[a-z0-9]+", normalized)


def _localized_negation(value: str, focus_tokens: set[str]) -> bool | None:
    """Return negated/positive polarity, or None when deterministic scope is ambiguous."""
    words = _polarity_words(value)
    focus_positions = [index for index, word in enumerate(words) if word in focus_tokens]
    if not focus_positions:
        return None
    relevant_negations = {
        index
        for index, word in enumerate(words)
        if word in _NEGATION_TOKENS and min(abs(index - focus) for focus in focus_positions) <= 4
    }
    if len(relevant_negations) > 1:
        return None
    return bool(relevant_negations)


def _antonym_conflict(claim_words: set[str], support_words: set[str]) -> bool:
    for positive, negative in _ANTONYM_GROUPS:
        claim_positive = bool(claim_words & positive)
        claim_negative = bool(claim_words & negative)
        support_positive = bool(support_words & positive)
        support_negative = bool(support_words & negative)
        if (claim_positive and claim_negative) or (support_positive and support_negative):
            return True
        if (claim_positive and support_negative) or (claim_negative and support_positive):
            return True
    return False


def _polarity_conflicts(claim: str, support_values: list[str]) -> bool:
    """Fail closed on opposing or mixed polarity in lexically relevant support clauses."""
    focus_tokens = _claim_tokens(claim)
    claim_polarity = _localized_negation(claim, focus_tokens)
    if claim_polarity is None:
        return True
    claim_words = set(_polarity_words(claim))
    support_polarities: set[bool] = set()
    matched_clause = False
    for support in support_values:
        for clause in _CLAUSE_BOUNDARY.split(support):
            clause_tokens = _claim_tokens(clause)
            shared_tokens = focus_tokens & clause_tokens
            if not shared_tokens:
                continue
            matched_clause = True
            support_words = set(_polarity_words(clause))
            if _antonym_conflict(claim_words, support_words):
                return True
            support_polarity = _localized_negation(clause, shared_tokens)
            if support_polarity is None:
                return True
            support_polarities.add(support_polarity)
    if not matched_clause:
        return False
    if len(support_polarities) != 1:
        return True
    return next(iter(support_polarities)) != claim_polarity


def _numeric_facts(value: str) -> tuple[set[NumericFact], bool]:
    """Return bounded canonical facts and whether malformed numeric input was seen."""
    facts: set[NumericFact] = set()
    malformed = False
    for match in _NUMERIC_FACT.finditer(value):
        literal = match.group("number")
        if len(literal) > _MAX_NUMERIC_LITERAL_LENGTH:
            malformed = True
            continue
        mantissa, exponent_marker, exponent = literal.lower().partition("e")
        if "," in mantissa and not re.fullmatch(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?", mantissa):
            malformed = True
            continue
        if exponent_marker and (
            len(exponent.lstrip("+-")) > 5 or abs(int(exponent)) > _MAX_ABSOLUTE_DECIMAL_EXPONENT
        ):
            malformed = True
            continue
        signs = [sign for sign in (match.group("sign_before"), match.group("sign_after")) if sign]
        if len(signs) > 1:
            malformed = True
            continue
        try:
            number = Decimal(literal.replace(",", ""))
        except InvalidOperation:
            malformed = True
            continue
        if signs and signs[0] in {"-", "\N{MINUS SIGN}"}:
            number = -number
        currency = match.group("currency")
        if currency:
            currency = _CURRENCY_ALIASES.get(currency, currency.upper())
        unit = match.group("unit")
        if unit:
            unit = unit.casefold()
            suffix_currency = _CURRENCY_UNIT_ALIASES.get(unit)
            if suffix_currency:
                if currency is not None and currency != suffix_currency:
                    malformed = True
                    continue
                currency = suffix_currency
                unit = None
        facts.add(
            (
                number,
                bool(match.group("percent")),
                currency,
                unit,
            )
        )
    return facts, malformed


def _numeric_fact_supported(claim: NumericFact, support: set[NumericFact]) -> bool:
    claim_value, claim_percent, claim_currency, claim_unit = claim
    return any(
        claim_value == support_value
        and claim_percent == support_percent
        and (claim_currency is None or claim_currency == support_currency)
        and (claim_unit is None or claim_unit == support_unit)
        for support_value, support_percent, support_currency, support_unit in support
    )


def _explicit_evidence_conflict(claim: str, evidence: Evidence) -> bool:
    """Detect only concrete cited-claim conflicts; ambiguity remains non-detected."""

    claim_tokens = _claim_tokens(claim)
    support_tokens = _claim_tokens(evidence.text)
    shared_tokens = claim_tokens & support_tokens
    if not shared_tokens:
        return False
    claim_words = set(_polarity_words(claim))
    support_words = set(_polarity_words(evidence.text))
    if _antonym_conflict(claim_words, support_words):
        return True
    claim_polarity = _localized_negation(claim, shared_tokens)
    support_polarity = _localized_negation(evidence.text, shared_tokens)
    if (
        claim_polarity is not None
        and support_polarity is not None
        and claim_polarity != support_polarity
    ):
        return True
    claim_numbers, malformed = _numeric_facts(claim)
    support_numbers, _ = _numeric_facts(evidence.text)
    if malformed or not claim_numbers or not support_numbers:
        return False
    for claim_number in claim_numbers:
        comparable = {item for item in support_numbers if item[1:] == claim_number[1:]}
        if comparable and not _numeric_fact_supported(claim_number, comparable):
            return True
    return False


def _claim_evidence_conflict_signal(
    answer: str,
    evidence: dict[int, Evidence],
) -> ConflictSignal:
    assessed = 0
    conflicts = 0
    for segment in re.split(r"(?<=[.!?])\s+|\n+", answer):
        cleaned = segment.strip(" -*\t")
        labels = {int(value) for value in re.findall(r"\[E([1-9]|[12]\d|30)\]", cleaned)}
        claim = re.sub(r"\[E(?:[1-9]|[12]\d|30)\]", "", cleaned).strip()
        if not labels or not _claim_tokens(claim):
            continue
        assessed += 1
        if any(
            label in evidence and _explicit_evidence_conflict(claim, evidence[label])
            for label in labels
        ):
            conflicts += 1
    if assessed == 0:
        return ConflictSignal()
    score = round(conflicts / assessed, 3)
    return ConflictSignal(
        status=(ConflictStatus.DETECTED if conflicts else ConflictStatus.NOT_DETECTED),
        score=score,
        method="deterministic_claim_evidence_conflict_v1",
    )


def _cross_source_conflict_signal(evidence: list[Evidence]) -> ConflictSignal:
    assessed = 0
    conflicts = 0
    for index, left in enumerate(evidence):
        for right in evidence[index + 1 :]:
            if left.source_name == right.source_name:
                continue
            shared_tokens = _claim_tokens(left.text) & _claim_tokens(right.text)
            # A conservative overlap floor avoids comparing unrelated numbers or
            # polarity words that happen to occur in the same disaster collection.
            if len(shared_tokens) < 3:
                continue
            assessed += 1
            if _explicit_evidence_conflict(left.text, right):
                conflicts += 1
    if assessed == 0:
        return ConflictSignal()
    score = round(conflicts / assessed, 3)
    return ConflictSignal(
        status=(ConflictStatus.DETECTED if conflicts else ConflictStatus.NOT_DETECTED),
        score=score,
        method="conservative_cross_source_lexical_conflict_v1",
    )


def _source_freshness(
    evidence: list[Evidence],
    max_age_days: int,
) -> SourceFreshness:
    now = datetime.now(UTC)
    ages: list[float] = []
    unknown = 0
    for item in evidence:
        source_time = source_time_from_metadata(item.metadata)
        if source_time is None or source_time[0] > now:
            unknown += 1
            continue
        ages.append(max(0.0, (now - source_time[0]).total_seconds() / 86400))
    if not ages:
        return SourceFreshness(
            status=SourceFreshnessStatus.UNKNOWN,
            unknown_source_count=unknown,
        )
    oldest = max(ages)
    if oldest > max_age_days:
        freshness_status = SourceFreshnessStatus.STALE
    elif unknown:
        freshness_status = SourceFreshnessStatus.PARTIAL
    else:
        freshness_status = SourceFreshnessStatus.FRESH
    return SourceFreshness(
        status=freshness_status,
        known_source_count=len(ages),
        unknown_source_count=unknown,
        oldest_source_age_days=oldest,
    )


def _evidence_supports_claim(
    claim: str,
    claim_tokens: set[str],
    evidence: Evidence,
    pixels_supplied: bool,
) -> bool:
    support_text = evidence.text
    if _polarity_conflicts(claim, [support_text]):
        return False
    claim_numbers, malformed_claim_number = _numeric_facts(claim)
    support_numbers, _ = _numeric_facts(support_text)
    if malformed_claim_number or any(
        not _numeric_fact_supported(number, support_numbers) for number in claim_numbers
    ):
        return False
    support_tokens = _claim_tokens(support_text)
    overlap = len(claim_tokens & support_tokens) / max(1, min(len(claim_tokens), 8))
    has_visual_support = evidence.modality in _VISUAL_CITATION_MODALITIES and pixels_supplied
    # Pixel-derived claims cannot be evaluated with text overlap alone, but a visual
    # citation must still pass deterministic numeric and contradiction checks when its
    # OCR/caption text supplies those facts.
    return has_visual_support or overlap >= 0.15


def _unsupported_claims(
    answer: str,
    evidence: dict[int, Evidence],
    pixel_labels: set[int],
) -> list[str]:
    unsupported: list[str] = []
    for segment in re.split(r"(?<=[.!?])\s+|\n+", answer):
        cleaned = segment.strip(" -*\t")
        if (
            not cleaned
            or _CITATION_ONLY.fullmatch(cleaned)
            or _REMOVED_CITATIONS_ONLY.fullmatch(cleaned)
            or cleaned
            in {
                "Here is the strongest evidence available:",
                "This is an evidence summary, not operational emergency guidance.",
            }
        ):
            continue
        labels = {int(value) for value in re.findall(r"\[E([1-9]|[12]\d|30)\]", cleaned)}
        claim = re.sub(r"\[E(?:[1-9]|[12]\d|30)\]", "", cleaned).strip()
        claim_tokens = _claim_tokens(claim)
        if len(claim) < 20 and not claim_tokens:
            continue
        if not labels or not claim_tokens:
            unsupported.append(cleaned)
            continue
        # Every retained label must independently support the claim. Concatenating cited
        # evidence would let one valid source launder an unrelated or opposing citation.
        if any(
            label not in evidence
            or not _evidence_supports_claim(
                claim,
                claim_tokens,
                evidence[label],
                label in pixel_labels,
            )
            for label in labels
        ):
            unsupported.append(cleaned)
    return unsupported
