from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.validate_kubernetes_release import KubernetesReleaseError, validate_tree

ROOT = Path(__file__).parents[2] / "deploy" / "kubernetes" / "base"


def _copy_tree(tmp_path: Path) -> Path:
    target = tmp_path / "base"
    target.mkdir()
    for source in ROOT.glob("*.yaml"):
        (target / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _replace(root: Path, filename: str, old: str, new: str) -> None:
    path = root / filename
    content = path.read_text(encoding="utf-8")
    assert old in content
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def _edit_documents(
    root: Path, filename: str, edit: Callable[[list[dict[str, Any]]], None]
) -> None:
    path = root / filename
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    edit(documents)
    path.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")


def _render_tree(tmp_path: Path, cidrs: str = "10.0.0.0/24,2001:db8::/64") -> Path:
    root = _copy_tree(tmp_path)
    (root / "migration.yaml").unlink()
    (root / "kustomization.yaml").unlink()
    replacements = {
        "REPLACE_WITH_IMMUTABLE_API_IMAGE": ("registry.example/crisisweave-api@sha256:" + "a" * 64),
        "REPLACE_WITH_IMMUTABLE_UI_IMAGE": ("registry.example/crisisweave-ui@sha256:" + "b" * 64),
        "REPLACE_WITH_IMMUTABLE_OTEL_IMAGE": (
            "registry.example/crisisweave-otel@sha256:" + "c" * 64
        ),
        "REPLACE_WITH_INGRESS_PROXY_CIDRS": cidrs,
    }
    for path in root.glob("*.yaml"):
        content = path.read_text(encoding="utf-8")
        for old, new in replacements.items():
            content = content.replace(old, new)
        path.write_text(content, encoding="utf-8")
    return root


def test_kubernetes_base_contains_required_fail_closed_controls() -> None:
    validate_tree(ROOT, rendered=False)


@pytest.mark.parametrize("filename", ["parser.yaml", "mesh-security.yaml"])
def test_kubernetes_base_requires_parser_and_mesh_manifests(tmp_path: Path, filename: str) -> None:
    root = _copy_tree(tmp_path)
    (root / filename).unlink()
    with pytest.raises(KubernetesReleaseError, match="missing Kubernetes manifest"):
        validate_tree(root, rendered=False)


def test_rendered_release_rejects_placeholders() -> None:
    with pytest.raises(KubernetesReleaseError, match="immutable SHA-256"):
        validate_tree(ROOT, rendered=True)


@pytest.mark.parametrize(
    ("filename", "old", "new", "message"),
    [
        (
            "api.yaml",
            "allowPrivilegeEscalation: false",
            "allowPrivilegeEscalation: true",
            "privilege escalation",
        ),
        (
            "namespace.yaml",
            "kind: Namespace",
            "kind: Secret",
            "literal Kubernetes Secrets",
        ),
        (
            "namespace.yaml",
            "istio-injection: enabled",
            "istio-injection: disabled",
            "Istio injection",
        ),
        (
            "mesh-security.yaml",
            "mode: STRICT",
            "mode: PERMISSIVE",
            "STRICT mTLS",
        ),
        (
            "ui.yaml",
            "value: forwarded_bearer",
            "value: api_key",
            "forwarded bearer",
        ),
        (
            "api.yaml",
            "name: CRISISWEAVE_OTEL_EXPORTER_CA_FILE",
            "name: SSL_CERT_FILE",
            "TLS trust store",
        ),
        (
            "worker.yaml",
            "name: crisisweave-worker-config",
            "name: crisisweave-api-config",
            "configuration boundary",
        ),
        (
            "runtime-config.yaml",
            "  CRISISWEAVE_DATA_DIR: /data",
            "  CRISISWEAVE_DATA_DIR: /data\n  CRISISWEAVE_AUTH_MODE: oidc",
            "role-specific identity",
        ),
        (
            "runtime-config.yaml",
            '  CRISISWEAVE_INGESTION_LIFECYCLE_RETENTION_DAYS: "14"',
            '  CRISISWEAVE_INGESTION_LIFECYCLE_RETENTION_DAYS: "1"',
            "common production runtime controls",
        ),
        (
            "parser.yaml",
            'reloader.stakater.com/auto: "true"',
            'reloader.stakater.com/auto: "false"',
            "roll pods",
        ),
        (
            "network-policies.yaml",
            "name: parser-egress",
            "name: parser-unrestricted",
            "NetworkPolicy/parser-egress",
        ),
        (
            "worker.yaml",
            "containerPort: 9100",
            "containerPort: 9101",
            "metrics port",
        ),
        (
            "slos.yaml",
            "      path: /metrics\n      interval: 30s\n      scrapeTimeout: 10s\n---",
            "      path: /internal\n      interval: 30s\n      scrapeTimeout: 10s\n---",
            "ServiceMonitor endpoint",
        ),
    ],
)
def test_kubernetes_release_rejects_security_regressions(
    tmp_path: Path, filename: str, old: str, new: str, message: str
) -> None:
    root = _copy_tree(tmp_path)
    _replace(root, filename, old, new)
    with pytest.raises(KubernetesReleaseError, match=message):
        validate_tree(root, rendered=False)


def test_worker_cannot_reintroduce_parser_sidecar(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def add_sidecar(documents: list[dict[str, Any]]) -> None:
        deployment = documents[0]
        deployment["spec"]["template"]["spec"]["containers"].append({"name": "parser"})

    _edit_documents(root, "worker.yaml", add_sidecar)
    with pytest.raises(KubernetesReleaseError, match="separate Deployment"):
        validate_tree(root, rendered=False)


def test_parser_cannot_mount_shared_persistent_storage(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def add_claim(documents: list[dict[str, Any]]) -> None:
        deployment = documents[0]
        volumes = deployment["spec"]["template"]["spec"]["volumes"]
        volumes[0] = {
            "name": "parser-jobs",
            "persistentVolumeClaim": {"claimName": "shared-parser-jobs"},
        }

    _edit_documents(root, "parser.yaml", add_claim)
    with pytest.raises(KubernetesReleaseError, match="must not share a persistent volume"):
        validate_tree(root, rendered=False)


def test_parser_cannot_mount_worker_data(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _replace(root, "parser.yaml", "mountPath: /tmp", "mountPath: /data")
    with pytest.raises(KubernetesReleaseError, match="must not mount worker data"):
        validate_tree(root, rendered=False)


def test_parser_secret_must_be_one_explicit_key_reference(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def add_env_from(documents: list[dict[str, Any]]) -> None:
        parser = documents[0]["spec"]["template"]["spec"]["containers"][0]
        parser["envFrom"] = [{"secretRef": {"name": "crisisweave-parser-runtime"}}]

    _edit_documents(root, "parser.yaml", add_env_from)
    with pytest.raises(KubernetesReleaseError, match="explicit secretKeyRef"):
        validate_tree(root, rendered=False)


def test_parser_cannot_reference_worker_secret(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _replace(
        root,
        "parser.yaml",
        "name: crisisweave-parser-runtime",
        "name: crisisweave-worker-runtime",
    )
    with pytest.raises(KubernetesReleaseError, match="Secret boundary"):
        validate_tree(root, rendered=False)


def test_worker_metrics_probes_are_mandatory(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _replace(root, "worker.yaml", "port: metrics", "port: parser")
    with pytest.raises(KubernetesReleaseError, match="startupProbe"):
        validate_tree(root, rendered=False)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "crisisweave_query_end_to_end_duration_seconds_bucket",
            "crisisweave_pipeline_stage_duration_seconds_bucket",
        ),
        (
            "crisisweave:slo_ingestion_end_to_end_seconds:p99_30m",
            "crisisweave:slo_ingestion_end_to_end_seconds:p90_30m",
        ),
        ("CrisisWeaveDeadLetterPresent", "CrisisWeaveDeadLetterMissing"),
        (
            "crisisweave_ingestion_job_metric_refresh_failures_total",
            "crisisweave_ingestion_jobs_total",
        ),
        (
            "crisisweave_ingestion_lifecycle_outbox_oldest_pending_seconds",
            "crisisweave_ingestion_lifecycle_outbox_missing_seconds",
        ),
    ],
)
def test_kubernetes_release_rejects_broken_end_to_end_slos(
    tmp_path: Path, old: str, new: str
) -> None:
    root = _copy_tree(tmp_path)
    _replace(root, "slos.yaml", old, new)
    with pytest.raises(KubernetesReleaseError, match="Prometheus SLO"):
        validate_tree(root, rendered=False)


def test_api_metrics_scrape_must_use_its_operator_secret(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _replace(root, "slos.yaml", "CRISISWEAVE_METRICS_API_KEY", "CRISISWEAVE_API_KEYS")
    with pytest.raises(KubernetesReleaseError, match="ServiceMonitor authorization"):
        validate_tree(root, rendered=False)


def test_kubernetes_release_does_not_accept_required_values_in_comments(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    path = root / "ui.yaml"
    content = path.read_text(encoding="utf-8")
    content = content.replace("value: forwarded_bearer", "value: api_key", 1)
    path.write_text(f"{content}\n# value: forwarded_bearer\n", encoding="utf-8")
    with pytest.raises(KubernetesReleaseError, match="forwarded bearer"):
        validate_tree(root, rendered=False)


def test_rendered_steady_state_accepts_digests_and_excludes_migration(
    tmp_path: Path,
) -> None:
    validate_tree(_render_tree(tmp_path), rendered=True)


@pytest.mark.parametrize("cidrs", ["0.0.0.0/0", "::/0", "10.0.0.0/24,::/0"])
def test_rendered_release_rejects_universal_proxy_trust(tmp_path: Path, cidrs: str) -> None:
    with pytest.raises(KubernetesReleaseError, match="reject /0"):
        validate_tree(_render_tree(tmp_path, cidrs), rendered=True)


def test_rendered_release_rejects_invalid_proxy_cidr(tmp_path: Path) -> None:
    with pytest.raises(KubernetesReleaseError, match="CIDRs are invalid"):
        validate_tree(_render_tree(tmp_path, "not-a-network"), rendered=True)


def test_raw_release_rejects_silently_hard_coded_proxy_cidr(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _replace(
        root,
        "runtime-config.yaml",
        "REPLACE_WITH_INGRESS_PROXY_CIDRS",
        "10.0.0.0/24",
    )
    with pytest.raises(KubernetesReleaseError, match="explicit placeholder"):
        validate_tree(root, rendered=False)
