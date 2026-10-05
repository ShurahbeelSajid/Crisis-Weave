from __future__ import annotations

import asyncio

import pytest

from crisisweave.agent import CrisisAgent
from crisisweave.llm import extractive_answer
from crisisweave.models import Evidence, Modality, QueryRequest, Route


def test_uncited_model_draft_is_withheld() -> None:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="report.pdf",
            modality=Modality.TEXT,
            text="The report describes smoke.",
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001 - direct policy-node regression test
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "answer": "A major unsupported claim.",
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert "withholding" in result["answer"]
    assert result["citations"] == []


def test_abstention_phrase_does_not_exempt_an_appended_uncited_claim() -> None:
    result = _verify_text_claim(
        "The report recorded 2 deaths.",
        ("I do not have enough authorized evidence to answer this question, but 900 people died."),
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


def test_exact_canonical_abstention_is_retained_without_a_citation() -> None:
    result = _verify_text_claim(
        "The report recorded 2 deaths.",
        "I do not have enough authorized evidence to answer this question.",
    )

    assert result["answer"] == ("I do not have enough authorized evidence to answer this question.")
    assert result["citations"] == []


def test_unknown_model_citation_is_removed() -> None:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="report.pdf",
            modality=Modality.TEXT,
            text="The report describes smoke.",
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "answer": "The report describes smoke [E1]. [E999]",
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert "[E999]" not in result["answer"]
    assert [citation.label for citation in result["citations"]] == ["E1"]


def test_no_evidence_synthesis_abstains_without_calling_model() -> None:
    agent = object.__new__(CrisisAgent)
    result = asyncio.run(
        agent._synthesize(  # noqa: SLF001 - direct policy-node regression test
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "query": "What happened?",
                "evidence": [],
                "analytics": [],
                "warnings": [],
            }
        )
    )
    assert "not have enough authorized evidence" in result["answer"]


def test_extractive_multisentence_answer_cites_every_statement() -> None:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="field-report.txt",
            modality=Modality.TEXT,
            text="Call sign ORCHID-FALCON-731 was recorded. Containment was 37 percent.",
            score=0.9,
        )
    ]
    answer = extractive_answer("What was recorded?", evidence, [])

    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What was recorded?"),
                "started_at": 0.0,
                "answer": answer,
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )

    assert "withholding" not in str(result["answer"])
    assert "ORCHID-FALCON-731" in str(result["answer"])
    assert "37 percent" in str(result["answer"])
    assert [item.label for item in result["citations"]] == ["E1"]


def test_citation_label_does_not_launder_an_unsupported_numeric_claim() -> None:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="report.pdf",
            modality=Modality.TEXT,
            text="The report recorded 2 damaged structures.",
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="How many structures?"),
                "started_at": 0.0,
                "answer": "The report recorded 900 damaged structures [E1].",
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert "withholding" in result["answer"]
    assert result["citations"] == []


def test_leading_citation_does_not_launder_an_unsupported_numeric_claim() -> None:
    result = _verify_text_claim(
        "The report recorded 2 damaged structures.",
        "[E1] The report recorded 900 damaged structures.",
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


@pytest.mark.parametrize(
    ("support", "claim"),
    [
        ("Damage totaled 1500.0 dollars.", "Damage totaled $1,500 [E1]."),
        ("Damage totaled 1500.00 dollars.", "Damage totaled 1500 [E1]."),
        (
            "The net change was -1500.0 units.",
            "The net change was \N{MINUS SIGN}1,500 units [E1].",
        ),
        ("The affected share was 12.50 percent.", "The affected share was 12.5% [E1]."),
        ("Damage totaled 1500 units.", "Damage totaled 1.5e3 units [E1]."),
        ("The ratio was 0.50.", "The ratio was .5 [E1]."),
        ("Damage totaled USD 1500.", "Damage totaled $1,500 [E1]."),
    ],
)
def test_equivalent_numeric_formats_are_retained(support: str, claim: str) -> None:
    result = _verify_text_claim(support, claim)

    assert result["answer"] == claim
    assert [item.label for item in result["citations"]] == ["E1"]


@pytest.mark.parametrize(
    ("support", "claim"),
    [
        ("Damage totaled 1500.0 dollars.", "Damage totaled $1,501 [E1]."),
        ("The net change was -1500 units.", "The net change was +1,500 units [E1]."),
        ("The affected share was 12.5 percent.", "The affected share was 12.5 [E1]."),
        (
            "Damage totaled $1,500.",
            "Damage totaled \N{EURO SIGN}1,500 [E1].",
        ),
        ("Damage totaled 1500 people.", "Damage totaled $1,500 [E1]."),
        ("Damage totaled 1500 units.", "Damage totaled 1500 people [E1]."),
        ("Damage totaled 1500.", "Damage totaled 1500 structures [E1]."),
        ("Damage totaled 1500 units.", "Damage totaled 9e9 units [E1]."),
        ("The ratio was 5.", "The ratio was .5 [E1]."),
    ],
)
def test_changed_numeric_facts_are_withheld(support: str, claim: str) -> None:
    result = _verify_text_claim(support, claim)

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


def test_oversized_numeric_literal_fails_closed() -> None:
    huge = "9" * 5000
    result = _verify_text_claim(
        "Damage totaled 9 units.",
        f"Damage totaled {huge} units [E1].",
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


def test_noncanonical_citation_forms_are_removed_without_integer_parsing() -> None:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="report.pdf",
            modality=Modality.TEXT,
            text="The report describes smoke.",
            score=0.9,
        )
    ]
    huge = "9" * 5000
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "answer": f"The report describes smoke [E1]. [E01] [e1] [E 1] [E{huge}]",
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert "[E01]" not in result["answer"]
    assert "[e1]" not in result["answer"]
    assert huge not in result["answer"]
    assert [item.label for item in result["citations"]] == ["E1"]


def _verify_text_claim(support: str, answer: str) -> dict[str, object]:
    return _verify_multi_source_claim([support], answer)


def _verify_multi_source_claim(support_values: list[str], answer: str) -> dict[str, object]:
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id=f"evidence-{index}",
            document_id=f"document-{index}",
            source_name=f"report-{index}.txt",
            modality=Modality.TEXT,
            text=support,
            score=0.9,
        )
        for index, support in enumerate(support_values, start=1)
    ]
    return asyncio.run(
        agent._verify(  # noqa: SLF001 - direct policy-node regression test
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "answer": answer,
                "evidence": evidence,
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )


@pytest.mark.parametrize(
    "second_source",
    [
        "A budget appendix listed 2 unrelated grants.",
        "The fire did not destroy 2 homes.",
    ],
)
def test_each_citation_must_independently_support_the_claim(
    second_source: str,
) -> None:
    result = _verify_multi_source_claim(
        ["The fire destroyed 2 homes.", second_source],
        "The fire destroyed 2 homes [E1][E2].",
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


def test_multiple_independently_supporting_citations_are_retained() -> None:
    result = _verify_multi_source_claim(
        [
            "The fire destroyed 2 homes.",
            "A second assessment confirmed the fire destroyed 2 homes.",
        ],
        "The fire destroyed 2 homes [E1][E2].",
    )

    assert result["answer"] == "The fire destroyed 2 homes [E1][E2]."
    assert [item.label for item in result["citations"]] == ["E1", "E2"]


@pytest.mark.parametrize(
    ("support", "claim"),
    [
        ("The fire did not spread.", "The fire spread [E1]."),
        ("The report recorded no deaths.", "The report recorded deaths [E1]."),
        ("The fire spread.", "The fire did not spread [E1]."),
        ("The report recorded deaths.", "The report recorded no deaths [E1]."),
        ("Damage decreased during the period.", "Damage increased during the period [E1]."),
        ("Damage increased during the period.", "Damage decreased during the period [E1]."),
    ],
)
def test_opposing_polarity_or_antonym_is_withheld(support: str, claim: str) -> None:
    result = _verify_text_claim(support, claim)

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


@pytest.mark.parametrize(
    ("support", "claim"),
    [
        ("The fire did not spread.", "The fire did not spread [E1]."),
        ("The report recorded no deaths.", "The report recorded no deaths [E1]."),
        ("Damage increased during the period.", "Damage increased during the period [E1]."),
    ],
)
def test_matching_polarity_is_retained(support: str, claim: str) -> None:
    result = _verify_text_claim(support, claim)

    assert result["answer"] == claim
    assert [item.label for item in result["citations"]] == ["E1"]


def test_mixed_support_polarity_fails_closed() -> None:
    result = _verify_text_claim(
        "The fire spread. However, a later note says the fire did not spread.",
        "The fire spread [E1].",
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


def test_visual_claim_is_not_rejected_by_text_only_overlap_check(tmp_path) -> None:
    artifact = tmp_path / "image.jpg"
    artifact.write_bytes(b"pixels")
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="scene.jpg",
            modality=Modality.IMAGE,
            text="Visual evidence from scene.jpg",
            artifact_path=str(artifact),
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What is visible?"),
                "started_at": 0.0,
                "answer": "Orange flames are visible [E1].",
                "evidence": evidence,
                "pixel_labels": {1},
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )
    assert result["citations"]
    assert "withholding" not in result["answer"]
    assert any("pixels" in warning for warning in result["warnings"])


def test_visual_artifact_path_alone_does_not_authorize_pixel_claims(tmp_path) -> None:
    artifact = tmp_path / "image.jpg"
    artifact.write_bytes(b"pixels")
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="scene.jpg",
            modality=Modality.IMAGE,
            text="Visual evidence from scene.jpg",
            artifact_path=str(artifact),
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What is visible?"),
                "started_at": 0.0,
                "answer": "Orange flames are visible [E1].",
                "evidence": evidence,
                "pixel_labels": set(),
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []


@pytest.mark.parametrize(
    ("support", "claim"),
    [
        ("The report recorded no deaths.", "The report recorded 100 deaths [E1]."),
        ("The fire did not spread.", "The fire spread [E1]."),
    ],
)
def test_visual_label_does_not_bypass_numeric_or_polarity_checks(
    tmp_path, support: str, claim: str
) -> None:
    artifact = tmp_path / "image.jpg"
    artifact.write_bytes(b"pixels")
    agent = object.__new__(CrisisAgent)
    evidence = [
        Evidence(
            id="evidence-1",
            document_id="document-1",
            source_name="scene.jpg",
            modality=Modality.IMAGE,
            text=support,
            artifact_path=str(artifact),
            score=0.9,
        )
    ]
    result = asyncio.run(
        agent._verify(  # noqa: SLF001
            {
                "tenant_id": "tenant",
                "request": QueryRequest(query="What happened?"),
                "started_at": 0.0,
                "answer": claim,
                "evidence": evidence,
                "pixel_labels": {1},
                "routes": [Route.VECTOR],
                "warnings": [],
            }
        )
    )

    assert "withholding" in str(result["answer"])
    assert result["citations"] == []
