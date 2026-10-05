from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from crisisweave.agent import (
    _claim_evidence_conflict_signal,
    _cross_source_conflict_signal,
)
from crisisweave.auth import IdentityType, Permission, Principal, tenant_identifier
from crisisweave.config import Settings
from crisisweave.governance import OversightAssessment, OversightService, SQLiteGovernanceRepository
from crisisweave.models import (
    Citation,
    Concordance,
    ConflictSignal,
    ConflictStatus,
    Evidence,
    Modality,
    QueryResponse,
    ReviewDecision,
    ReviewStatus,
    RiskLevel,
    Route,
    SourceFreshness,
    SourceFreshnessStatus,
)


def principal(subject: str, *, identity_type: IdentityType = IdentityType.USER) -> Principal:
    return Principal(
        tenant_id=tenant_identifier("alpha"),
        tenant_label="alpha",
        subject_id=subject,
        identity_type=identity_type,
        roles=frozenset({"reviewer"}),
        permissions=frozenset({Permission.REVIEW_READ, Permission.REVIEW_DECIDE}),
        auth_method="oidc" if identity_type == IdentityType.USER else "api_key",
    )


def response(
    *,
    confidence: float = 0.9,
    citation: Citation | None = None,
    claim_evidence_conflict: ConflictSignal | None = None,
    cross_source_conflict: ConflictSignal | None = None,
    source_freshness: SourceFreshness | None = None,
) -> QueryResponse:
    return QueryResponse(
        answer="The evidence-supported answer.",
        routes=[Route.VECTOR],
        citations=[citation] if citation else [],
        concordance=Concordance(
            score=confidence,
            source_count=1,
            modality_count=1,
            rationale="Sources agree.",
        ),
        claim_evidence_conflict=claim_evidence_conflict or ConflictSignal(),
        cross_source_conflict=cross_source_conflict or ConflictSignal(),
        source_freshness=source_freshness or SourceFreshness(),
    )


def test_identity_audit_is_hash_chained_and_immutable(tmp_path) -> None:
    repository = SQLiteGovernanceRepository(Settings(_env_file=None, data_dir=tmp_path))
    tenant_id = tenant_identifier("alpha")
    try:
        first = repository.record_identity_event(
            tenant_id=tenant_id,
            subject_id="user-1",
            identity_type="user",
            auth_method="oidc",
            event_type="request.completed",
            outcome="success",
            request_id="request-1",
        )
        second = repository.record_identity_event(
            tenant_id=tenant_id,
            subject_id="user-1",
            identity_type="user",
            auth_method="oidc",
            event_type="authorization.denied",
            outcome="denied",
            request_id="request-2",
        )
        assert second.previous_hash == first.event_hash
        assert len(second.event_hash) == 64
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            repository._connection.execute(  # noqa: SLF001
                "UPDATE identity_events SET outcome = 'failed' WHERE id = ?", [first.id]
            )
    finally:
        repository.close()


def test_review_workflow_enforces_maker_checker_and_terminal_state(tmp_path) -> None:
    repository = SQLiteGovernanceRepository(Settings(_env_file=None, data_dir=tmp_path))
    requester = principal("requester")
    reviewer = principal("reviewer")
    assessment = OversightAssessment(
        requires_review=True,
        risk_level=RiskLevel.HIGH,
        reasons=("high_risk_subject",),
        confidence=0.8,
        oldest_source_age_days=1.0,
        contradiction_score=0.2,
    )
    try:
        review = repository.create_review(
            tenant_id=requester.tenant_id,
            query="Should the town evacuate now?",
            requester=requester,
            response=response(),
            assessment=assessment,
        )
        assert review.status == ReviewStatus.PENDING
        assert (
            repository.decide_review(
                requester.tenant_id,
                review.id,
                reviewer=requester,
                decision=ReviewDecision.APPROVE,
                reason="Self approval is forbidden.",
            )
            is None
        )
        decided = repository.decide_review(
            requester.tenant_id,
            review.id,
            reviewer=reviewer,
            decision=ReviewDecision.APPROVE,
            reason="Independent source review completed.",
        )
        assert decided is not None
        assert decided.status == ReviewStatus.APPROVED
        assert decided.reviewed_by == "reviewer"
        assert (
            repository.decide_review(
                requester.tenant_id,
                review.id,
                reviewer=principal("reviewer-2"),
                decision=ReviewDecision.REJECT,
                reason="Too late.",
            )
            is None
        )
    finally:
        repository.close()


def test_oversight_escalates_risk_confidence_contradiction_and_staleness(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path,
        oversight_enabled=True,
        minimum_answer_confidence=0.7,
        contradiction_escalation_threshold=0.3,
        max_source_age_days=30,
    )
    metadata: Any = SimpleNamespace(
        get_chunks=lambda _tenant, _ids: [],
        get_document=lambda _tenant, _document: None,
    )
    repository = SQLiteGovernanceRepository(settings)
    service = OversightService(settings, metadata, repository)
    try:
        assessment = service.assess(
            tenant_identifier("alpha"),
            "Should we order an evacuation?",
            response(
                confidence=0.5,
                citation=Citation(
                    evidence_id="evidence-1",
                    label="[1]",
                    source_name="report.pdf",
                ),
                cross_source_conflict=ConflictSignal(
                    status=ConflictStatus.DETECTED,
                    score=0.5,
                    method="conservative_cross_source_lexical_conflict_v1",
                ),
                source_freshness=SourceFreshness(
                    status=SourceFreshnessStatus.STALE,
                    known_source_count=1,
                    oldest_source_age_days=60,
                ),
            ),
        )
        assert assessment.requires_review
        assert assessment.risk_level == RiskLevel.HIGH
        assert set(assessment.reasons) == {
            "high_risk_subject",
            "confidence_below_threshold",
            "contradictory_evidence",
            "source_freshness_exceeded",
        }
    finally:
        repository.close()


@pytest.mark.parametrize(
    "query",
    [
        "¿Debemos ordenar una evacuación?",
        "क्या निकासी का आदेश देना चाहिए?",
        "هل يجب إصدار أمر إخلاء؟",
        "Devemos ordenar uma evacuação?",
    ],
)
def test_oversight_classifies_configured_multilingual_high_risk_terms(tmp_path, query: str) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path, oversight_enabled=True)
    metadata: Any = SimpleNamespace(get_chunks=lambda *_args: [], get_document=lambda *_args: None)
    repository = SQLiteGovernanceRepository(settings)
    try:
        assessment = OversightService(settings, metadata, repository).assess(
            tenant_identifier("alpha"),
            query,
            response(
                confidence=0.9,
                source_freshness=SourceFreshness(
                    status=SourceFreshnessStatus.FRESH,
                    known_source_count=1,
                    oldest_source_age_days=1,
                ),
            ),
        )
        assert assessment.risk_level == RiskLevel.HIGH
        assert "high_risk_subject" in assessment.reasons
    finally:
        repository.close()


def test_low_concordance_is_not_mislabeled_as_contradiction(tmp_path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path, oversight_enabled=True)
    metadata: Any = SimpleNamespace(get_chunks=lambda *_args: [], get_document=lambda *_args: None)
    repository = SQLiteGovernanceRepository(settings)
    try:
        assessment = OversightService(settings, metadata, repository).assess(
            tenant_identifier("alpha"),
            "Summarize the current evidence",
            response(
                confidence=0.2,
                source_freshness=SourceFreshness(
                    status=SourceFreshnessStatus.FRESH,
                    known_source_count=1,
                    oldest_source_age_days=1,
                ),
            ),
        )
        assert "confidence_below_threshold" in assessment.reasons
        assert "contradictory_evidence" not in assessment.reasons
        assert assessment.contradiction_score is None
    finally:
        repository.close()


def test_unknown_freshness_is_exposed_without_forcing_routine_review(tmp_path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path, oversight_enabled=True)
    metadata: Any = SimpleNamespace(get_chunks=lambda *_args: [], get_document=lambda *_args: None)
    repository = SQLiteGovernanceRepository(settings)
    try:
        assessment = OversightService(settings, metadata, repository).assess(
            tenant_identifier("alpha"),
            "Summarize the historical incident record",
            response(confidence=0.9),
        )
        assert assessment.source_freshness.status == SourceFreshnessStatus.UNKNOWN
        assert "source_freshness_unknown" not in assessment.reasons
        assert not assessment.requires_review
    finally:
        repository.close()


def test_deterministic_citation_conflict_signal_detects_opposing_polarity() -> None:
    evidence = Evidence(
        id="evidence-1",
        document_id="document-1",
        source_name="incident-report.txt",
        modality=Modality.TEXT,
        text="The evacuation order was not issued by the incident commander.",
        score=1.0,
    )

    signal = _claim_evidence_conflict_signal(
        "The evacuation order was issued by the incident commander [E1].",
        {1: evidence},
    )

    assert signal.status == ConflictStatus.DETECTED
    assert signal.score == 1.0


def test_cross_source_conflict_requires_conservative_shared_context() -> None:
    shared = {
        "id": "evidence",
        "document_id": "document",
        "modality": Modality.TEXT,
        "score": 1.0,
    }
    left = Evidence(
        **shared,
        source_name="agency-a.txt",
        text="The county evacuation order was issued by the incident commander.",
    )
    right = Evidence(
        **{**shared, "id": "evidence-2", "document_id": "document-2"},
        source_name="agency-b.txt",
        text="The county evacuation order was not issued by the incident commander.",
    )

    signal = _cross_source_conflict_signal([left, right])

    assert signal.status == ConflictStatus.DETECTED
    assert signal.score == 1.0
