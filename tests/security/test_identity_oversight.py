from __future__ import annotations

from fastapi.testclient import TestClient

from crisisweave.api import create_app
from crisisweave.auth import (
    AuthenticationError,
    IdentityType,
    Permission,
    Principal,
    tenant_identifier,
)
from crisisweave.config import Settings
from crisisweave.governance import OversightAssessment
from crisisweave.models import Concordance, QueryResponse, RiskLevel, Route


class HumanReviewerVerifier:
    def verify(self, token: str) -> Principal:
        if token == "service-reviewer-token":
            return Principal(
                tenant_id=tenant_identifier("alpha"),
                tenant_label="alpha",
                subject_id="review-service",
                identity_type=IdentityType.SERVICE,
                roles=frozenset({"reviewer"}),
                permissions=frozenset(
                    {
                        Permission.QUERY,
                        Permission.EVIDENCE_READ,
                        Permission.REVIEW_READ,
                        Permission.REVIEW_DECIDE,
                    }
                ),
                auth_method="oidc",
                credential_id="key-1",
            )
        if token == "requester-token":
            return Principal(
                tenant_id=tenant_identifier("alpha"),
                tenant_label="alpha",
                subject_id="requesting-analyst",
                identity_type=IdentityType.USER,
                roles=frozenset({"viewer"}),
                permissions=frozenset({Permission.QUERY, Permission.EVIDENCE_READ}),
                auth_method="oidc",
                credential_id="key-1",
            )
        if token != "human-reviewer-token":
            raise AuthenticationError("invalid token")
        return Principal(
            tenant_id=tenant_identifier("alpha"),
            tenant_label="alpha",
            subject_id="human-reviewer",
            identity_type=IdentityType.USER,
            roles=frozenset({"reviewer"}),
            permissions=frozenset(
                {
                    Permission.QUERY,
                    Permission.EVIDENCE_READ,
                    Permission.REVIEW_READ,
                    Permission.REVIEW_DECIDE,
                }
            ),
            auth_method="oidc",
            credential_id="key-1",
        )


def _settings(tmp_path) -> Settings:  # type: ignore[no-untyped-def]
    return Settings(
        _env_file=None,
        app_env="test",
        data_dir=tmp_path,
        auth_mode="hybrid",
        oidc_issuer_url="https://identity.example.test",
        oidc_audience="crisisweave-api",
        oidc_jwks_url="https://identity.example.test/jwks.json",
        api_keys=(
            "alpha@viewer=viewer-key,alpha@reviewer=reviewer-key,"
            "alpha@auditor=auditor-key,alpha@revoked=revoked-key,"
            "beta@reviewer=beta-reviewer-key"
        ),
        service_key_role_bindings=(
            "alpha@viewer=viewer,alpha@reviewer=reviewer,alpha@auditor=auditor,"
            "alpha@revoked=operator,beta@reviewer=reviewer"
        ),
        revoked_service_key_ids="alpha@revoked",
        metrics_api_key="metrics-only-key",
    )


def _candidate() -> QueryResponse:
    return QueryResponse(
        answer="Evacuate only after the incident commander confirms the order.",
        routes=[Route.VECTOR],
        concordance=Concordance(
            score=0.8,
            source_count=2,
            modality_count=1,
            rationale="Two independent sources agree.",
        ),
    )


def test_rbac_revocation_human_review_and_tenant_isolation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(_settings(tmp_path), token_verifier=HumanReviewerVerifier())
    with TestClient(app) as client:
        assert client.get("/v1/documents", headers={"X-API-Key": "viewer-key"}).status_code == 200
        denied_upload = client.post(
            "/v1/documents",
            headers={"X-API-Key": "viewer-key"},
            files={"file": ("note.txt", b"incident evidence", "text/plain")},
        )
        assert denied_upload.status_code == 403
        assert client.get("/v1/documents", headers={"X-API-Key": "revoked-key"}).status_code == 401

        requester = Principal(
            tenant_id=tenant_identifier("alpha"),
            tenant_label="alpha",
            subject_id="requesting-analyst",
            identity_type=IdentityType.USER,
            roles=frozenset({"viewer"}),
            permissions=frozenset({Permission.QUERY, Permission.EVIDENCE_READ}),
            auth_method="oidc",
        )
        review = app.state.governance.create_review(
            tenant_id=requester.tenant_id,
            query="Should responders issue an evacuation order?",
            requester=requester,
            response=_candidate(),
            assessment=OversightAssessment(
                requires_review=True,
                risk_level=RiskLevel.HIGH,
                reasons=("high_risk_subject",),
                confidence=0.8,
                oldest_source_age_days=1.0,
                contradiction_score=0.2,
            ),
        )

        service_decision = client.post(
            f"/v1/reviews/{review.id}/decision",
            headers={"X-API-Key": "reviewer-key"},
            json={"decision": "approve", "reason": "Reviewed by service"},
        )
        assert service_decision.status_code == 403
        oidc_service_decision = client.post(
            f"/v1/reviews/{review.id}/decision",
            headers={"Authorization": "Bearer service-reviewer-token"},
            json={"decision": "approve", "reason": "Reviewed by OIDC service"},
        )
        assert oidc_service_decision.status_code == 403

        cross_tenant = client.get(
            f"/v1/reviews/{review.id}",
            headers={"X-API-Key": "beta-reviewer-key"},
        )
        assert cross_tenant.status_code == 404

        approved = client.post(
            f"/v1/reviews/{review.id}/decision",
            headers={"Authorization": "Bearer human-reviewer-token"},
            json={
                "decision": "approve",
                "reason": "Independent evidence and source freshness verified.",
            },
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"

        unrelated_result = client.get(
            f"/v1/reviews/{review.id}/result",
            headers={"X-API-Key": "viewer-key"},
        )
        assert unrelated_result.status_code == 404

        result = client.get(
            f"/v1/reviews/{review.id}/result",
            headers={"Authorization": "Bearer requester-token"},
        )
        assert result.status_code == 200
        assert result.json()["answer"] == _candidate().answer

        audit = client.get(
            "/v1/audit/identity-events",
            headers={"X-API-Key": "auditor-key"},
        )
        assert audit.status_code == 200
        assert any(item["event_type"] == "review.approved" for item in audit.json())


def test_metrics_accepts_only_one_constant_time_header_or_bearer_key(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(_settings(tmp_path), token_verifier=HumanReviewerVerifier())
    with TestClient(app) as client:
        assert (
            client.get("/metrics", headers={"Authorization": "Bearer metrics-only-key"}).status_code
            == 200
        )
        assert (
            client.get("/metrics", headers={"X-Metrics-Key": "metrics-only-key"}).status_code == 200
        )
        assert (
            client.get(
                "/metrics",
                headers={
                    "Authorization": "Bearer metrics-only-key",
                    "X-Metrics-Key": "metrics-only-key",
                },
            ).status_code
            == 401
        )
        assert (
            client.get("/metrics", headers={"Authorization": "Bearer wrong-key"}).status_code == 401
        )
