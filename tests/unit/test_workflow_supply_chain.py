from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
PRE_COMMIT_CONFIG = REPOSITORY_ROOT / ".pre-commit-config.yaml"
REMOTE_ACTION = re.compile(
    r"^\s*(?:-\s*)?uses:\s+"
    r"(?P<action>[^@\s]+)@(?P<reference>[0-9a-f]{40})"
    r"\s+#\s+(?P<version>v?\d+(?:\.\d+){1,2})\s*$"
)
PRE_COMMIT_REVISION = re.compile(r"^\s*rev:\s+[0-9a-f]{40}\s+#\s+v?\d+(?:\.\d+){1,2}\s*$")


def test_every_remote_action_is_commit_pinned_with_a_version_comment() -> None:
    action_count = 0

    for workflow in WORKFLOW_DIRECTORY.glob("*.y*ml"):
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if "uses:" not in line or "uses: ./" in line:
                continue
            action_count += 1
            assert REMOTE_ACTION.fullmatch(line), (
                f"{workflow.relative_to(REPOSITORY_ROOT)}:{line_number} must use a "
                "40-character commit SHA and retain its release-version comment"
            )

    assert action_count > 0


def test_checkout_does_not_persist_the_workflow_token() -> None:
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8") for path in WORKFLOW_DIRECTORY.glob("*.y*ml")
    )

    assert workflow_text.count("uses: actions/checkout@") == workflow_text.count(
        "persist-credentials: false"
    )


def test_pre_commit_hooks_are_commit_pinned_with_version_comments() -> None:
    revisions = [
        line
        for line in PRE_COMMIT_CONFIG.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("rev:")
    ]

    assert revisions
    assert all(PRE_COMMIT_REVISION.fullmatch(line) for line in revisions)


def test_clamav_release_image_is_built_inspected_and_scanned() -> None:
    workflow = (WORKFLOW_DIRECTORY / "ci.yml").read_text(encoding="utf-8")

    assert "docker build --target clamav-runtime" in workflow
    assert "docker run --rm --entrypoint clamconf" in workflow
    assert '"${CLAMAV_IMAGE}")" = "clamav"' in workflow
    assert "Scan ClamAV image for high-severity vulnerabilities" in workflow
    assert "image-ref: ${{ env.CLAMAV_IMAGE }}" in workflow
    assert 'exit-code: "1"' in workflow


def test_promotion_is_manual_digest_bound_and_non_certifying() -> None:
    workflow = (WORKFLOW_DIRECTORY / "promote.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "\n  pull_request:" not in workflow
    assert 'if [[ "${GITHUB_REF_TYPE}" != "tag" ]]' in workflow
    assert "environment: production-promotion" in workflow
    assert "permissions: {}" in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "artifact-metadata: write" in workflow
    assert "APPROVED_REGISTRY_REPOSITORY: ${{ vars.PROMOTION_REGISTRY_REPOSITORY }}" in workflow
    assert "must exactly match the protected promotion target" in workflow
    assert "production_certified: false" in workflow


def test_promotion_builds_verifies_and_scans_the_exact_model_bundle_digest() -> None:
    workflow = (WORKFLOW_DIRECTORY / "promote.yml").read_text(encoding="utf-8")

    for required_input in (
        "registry_repository",
        "python_base_image",
        "text_revision",
        "visual_revision",
        "reranker_revision",
        "whisper_revision",
        "ui_image",
        "otel_image",
        "kubernetes_release_tree",
    ):
        assert re.search(rf"^      {required_input}:$", workflow, re.MULTILINE)

    assert "--target model-bundle" in workflow
    assert "--provenance=mode=max" in workflow
    assert 'image_ref="${REGISTRY_REPOSITORY}@${digest}"' in workflow
    assert "--network none \\\n" in workflow
    assert "{{json .Config.Entrypoint}}" in workflow
    assert "model bundle verified and executable" in workflow
    assert workflow.count("image-ref: ${{ steps.subject.outputs.image_ref }}") == 2
    assert "format: cyclonedx" in workflow
    assert "severity: CRITICAL,HIGH" in workflow
    assert 'exit-code: "1"' in workflow


def test_promotion_signs_attests_and_validates_the_rendered_release() -> None:
    workflow = (WORKFLOW_DIRECTORY / "promote.yml").read_text(encoding="utf-8")

    assert 'cosign sign --yes "${IMAGE_REF}"' in workflow
    assert "--certificate-oidc-issuer" in workflow
    assert workflow.count("uses: actions/attest@") == 2
    assert workflow.count("subject-digest: ${{ steps.subject.outputs.digest }}") == 2
    assert "sbom-path: crisisweave-model-bundle.cdx.json" in workflow
    assert "push-to-registry: true" in workflow
    assert 'scripts/validate_kubernetes_release.py "${rendered}" --rendered' in workflow
    assert '"crisisweave-parser": api_image' in workflow
    assert "is not bound to its reviewed exact image digest" in workflow
    assert "PROMOTION_REGISTRY_PASSWORD: ${{ secrets.PROMOTION_REGISTRY_PASSWORD }}" in workflow
    assert "Authenticate to GHCR with the ephemeral workflow token" in workflow
    assert "COSIGN_PRIVATE_KEY" not in workflow
