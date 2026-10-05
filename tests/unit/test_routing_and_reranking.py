from __future__ import annotations

import pytest
from pydantic import ValidationError

from crisisweave.llm import heuristic_plan
from crisisweave.models import Evidence, Modality, QueryRequest, Route
from crisisweave.reranking import LexicalReranker


def test_heuristic_router_uses_hybrid_tools() -> None:
    plan = heuristic_plan("What is the latest total property damage by state?", allow_web=True)
    assert [tool.route for tool in plan.tools] == [Route.VECTOR, Route.SQL, Route.WEB]


def test_web_route_requires_explicit_permission() -> None:
    plan = heuristic_plan("What is the latest official update?", allow_web=False)
    assert Route.WEB not in [tool.route for tool in plan.tools]


def test_heuristic_average_injuries_uses_average_not_total() -> None:
    plan = heuristic_plan("What are the average injuries by state?", allow_web=False)
    sql_tools = [tool for tool in plan.tools if tool.route == Route.SQL]

    assert len(sql_tools) == 1
    assert "AVG(injuries_direct)" in (sql_tools[0].sql or "")
    assert "SUM(" not in (sql_tools[0].sql or "")


def test_heuristic_ambiguous_average_avoids_inventing_a_metric() -> None:
    plan = heuristic_plan("What is the average by state?", allow_web=False)

    assert Route.SQL not in [tool.route for tool in plan.tools]


def test_heuristic_highest_magnitude_uses_maximum() -> None:
    plan = heuristic_plan("What was the highest magnitude by state?", allow_web=False)
    sql_tools = [tool for tool in plan.tools if tool.route == Route.SQL]

    assert len(sql_tools) == 1
    assert "MAX(magnitude) AS highest_magnitude" in (sql_tools[0].sql or "")
    assert "ORDER BY 2 DESC" in (sql_tools[0].sql or "")


def test_heuristic_lowest_injuries_uses_minimum_and_ascending_order() -> None:
    plan = heuristic_plan("What were the lowest injuries by state?", allow_web=False)
    sql_tools = [tool for tool in plan.tools if tool.route == Route.SQL]

    assert len(sql_tools) == 1
    assert "MIN(injuries_direct) AS lowest_direct_injuries" in (sql_tools[0].sql or "")
    assert "ORDER BY 2 ASC" in (sql_tools[0].sql or "")


def test_empty_modality_filter_is_rejected() -> None:
    with pytest.raises(ValidationError):
        QueryRequest(query="valid question", include_modalities=[])


def test_reranker_limits_document_dominance() -> None:
    evidence = [
        Evidence(
            id=str(index),
            document_id="same" if index < 4 else "other",
            source_name="source",
            modality=Modality.TEXT,
            text="wildfire smoke damage" if index < 4 else "unrelated",
            score=0.9,
        )
        for index in range(5)
    ]
    result = LexicalReranker().rerank("wildfire damage", evidence, 5)
    assert sum(item.document_id == "same" for item in result) == 3


def test_reranker_does_not_discard_context_when_library_has_one_document() -> None:
    evidence = [
        Evidence(
            id=str(index),
            document_id="only-document",
            source_name="report.pdf",
            modality=Modality.PDF_PAGE,
            text=f"Natural disaster evidence page {index}",
            score=0.7,
        )
        for index in range(8)
    ]

    result = LexicalReranker().rerank("natural disaster evidence", evidence, 6)

    assert len(result) == 6
    assert {item.document_id for item in result} == {"only-document"}
