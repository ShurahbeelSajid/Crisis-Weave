"""Fail closed on unsafe or unrendered CrisisWeave Kubernetes releases."""

from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

IMAGE_LINE = re.compile(r"^\s*image:\s*(\S+)\s*$", re.MULTILINE)
DIGEST_IMAGE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,255}@sha256:(?!0{64})[a-f0-9]{64}")
RAW_IMAGE = re.compile(r"REPLACE_WITH_IMMUTABLE_(?:API|UI|OTEL)_IMAGE")
ALL_INTERFACES = str(ipaddress.IPv4Address(0))
REQUIRED_FILES = {
    "api.yaml",
    "external-secrets.yaml",
    "kustomization.yaml",
    "mesh-security.yaml",
    "migration.yaml",
    "namespace.yaml",
    "network-policies.yaml",
    "parser.yaml",
    "runtime-config.yaml",
    "serviceaccounts.yaml",
    "slos.yaml",
    "telemetry.yaml",
    "ui.yaml",
    "worker.yaml",
}
EXPECTED_DEPLOYMENTS = {
    "crisisweave-api": (3, "crisisweave-api", "api"),
    "crisisweave-worker": (2, "crisisweave-worker", "worker"),
    "crisisweave-parser": (2, "crisisweave-parser", "parser"),
    "crisisweave-ui": (2, "crisisweave-ui", "ui"),
    "crisisweave-otel": (2, "crisisweave-telemetry", "collector"),
}


class KubernetesReleaseError(ValueError):
    """Raised when the release tree weakens a mandatory production invariant."""


def _load_documents(paths: list[Path]) -> dict[tuple[str, str], dict[str, Any]]:
    documents: dict[tuple[str, str], dict[str, Any]] = {}
    for path in paths:
        try:
            loaded = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise KubernetesReleaseError(f"invalid YAML in {path.name}") from exc
        for position, document in enumerate(loaded, start=1):
            if not isinstance(document, dict):
                raise KubernetesReleaseError(
                    f"manifest {path.name} document {position} must be a mapping"
                )
            kind = document.get("kind")
            metadata = document.get("metadata")
            name = metadata.get("name") if isinstance(metadata, dict) else None
            if kind == "Kustomization" and path.name == "kustomization.yaml" and name is None:
                name = "kustomization"
            if not isinstance(kind, str) or not isinstance(name, str) or not name:
                raise KubernetesReleaseError(
                    f"manifest {path.name} document {position} needs kind and metadata.name"
                )
            key = (kind, name)
            if key in documents:
                raise KubernetesReleaseError(f"duplicate manifest identity: {kind}/{name}")
            documents[key] = document
    return documents


def _required_manifest(
    documents: dict[tuple[str, str], dict[str, Any]], kind: str, name: str
) -> dict[str, Any]:
    try:
        return documents[(kind, name)]
    except KeyError as exc:
        raise KubernetesReleaseError(f"mandatory manifest is missing: {kind}/{name}") from exc


def _pod_spec(workload: dict[str, Any]) -> dict[str, Any]:
    template = workload.get("spec", {}).get("template", {})
    pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
    if not isinstance(pod_spec, dict):
        raise KubernetesReleaseError("workload pod spec must be a mapping")
    return pod_spec


def _container(workload: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item
        for item in _pod_spec(workload).get("containers", [])
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        workload_name = workload.get("metadata", {}).get("name", "unknown")
        raise KubernetesReleaseError(f"{workload_name} must contain exactly one {name} container")
    return matches[0]


def _environment(container: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in container.get("env", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise KubernetesReleaseError(f"{label} has a malformed environment entry")
        name = item["name"]
        if name in result:
            raise KubernetesReleaseError(f"{label} defines duplicate environment variable {name}")
        result[name] = item
    return result


def _environment_values(container: dict[str, Any], label: str) -> dict[str, Any]:
    return {name: item.get("value") for name, item in _environment(container, label).items()}


def _environment_from(container: dict[str, Any], label: str) -> tuple[set[str], set[str]]:
    config_maps: set[str] = set()
    secrets: set[str] = set()
    for item in container.get("envFrom", []):
        if not isinstance(item, dict):
            raise KubernetesReleaseError(f"{label} has a malformed envFrom entry")
        if set(item) == {"configMapRef"}:
            name = item["configMapRef"].get("name")
            if not isinstance(name, str) or not name:
                raise KubernetesReleaseError(f"{label} has a malformed ConfigMap reference")
            config_maps.add(name)
        elif set(item) == {"secretRef"}:
            name = item["secretRef"].get("name")
            if not isinstance(name, str) or not name:
                raise KubernetesReleaseError(f"{label} has a malformed Secret reference")
            secrets.add(name)
        else:
            raise KubernetesReleaseError(f"{label} has an unsupported envFrom source")
    return config_maps, secrets


def _require_environment_from(
    container: dict[str, Any],
    *,
    label: str,
    config_maps: set[str],
    secrets: set[str],
) -> None:
    actual_config_maps, actual_secrets = _environment_from(container, label)
    if actual_config_maps != config_maps or actual_secrets != secrets:
        raise KubernetesReleaseError(f"{label} crosses its role-specific configuration boundary")


def _pod_secret_references(pod_spec: dict[str, Any], label: str) -> set[str]:
    references: set[str] = set()
    containers = [*pod_spec.get("initContainers", []), *pod_spec.get("containers", [])]
    for container in containers:
        if not isinstance(container, dict):
            raise KubernetesReleaseError(f"{label} contains a malformed container")
        _, env_from_secrets = _environment_from(container, label)
        references.update(env_from_secrets)
        for item in _environment(container, label).values():
            value_from = item.get("valueFrom", {})
            if not isinstance(value_from, dict) or "secretKeyRef" not in value_from:
                continue
            secret_name = value_from["secretKeyRef"].get("name")
            if not isinstance(secret_name, str) or not secret_name:
                raise KubernetesReleaseError(f"{label} has a malformed secretKeyRef")
            references.add(secret_name)
    for volume in pod_spec.get("volumes", []):
        if not isinstance(volume, dict) or "secret" not in volume:
            continue
        secret_name = volume["secret"].get("secretName")
        if not isinstance(secret_name, str) or not secret_name:
            raise KubernetesReleaseError(f"{label} has a malformed Secret volume")
        references.add(secret_name)
    return references


def _validate_workloads(
    documents: dict[tuple[str, str], dict[str, Any]], *, rendered: bool
) -> None:
    workloads = [_required_manifest(documents, "Deployment", name) for name in EXPECTED_DEPLOYMENTS]
    if not rendered:
        workloads.append(_required_manifest(documents, "Job", "crisisweave-migrate"))

    for name, (minimum, service_account, expected_container) in EXPECTED_DEPLOYMENTS.items():
        deployment = _required_manifest(documents, "Deployment", name)
        replicas = deployment.get("spec", {}).get("replicas")
        if not isinstance(replicas, int) or replicas < minimum:
            raise KubernetesReleaseError(f"{name} has insufficient baseline replicas")
        pod_spec = _pod_spec(deployment)
        container_names = {
            item.get("name") for item in pod_spec.get("containers", []) if isinstance(item, dict)
        }
        if container_names != {expected_container}:
            raise KubernetesReleaseError(
                f"{name} must isolate its {expected_container} process in a separate Deployment"
            )
        if pod_spec.get("serviceAccountName") != service_account:
            raise KubernetesReleaseError(f"{name} must use its dedicated service account")
        account = _required_manifest(documents, "ServiceAccount", service_account)
        if account.get("automountServiceAccountToken") is not False:
            raise KubernetesReleaseError(f"{service_account} must disable token automounting")
        if not any(
            item.get("topologyKey") == "topology.kubernetes.io/zone"
            for item in pod_spec.get("topologySpreadConstraints", [])
            if isinstance(item, dict)
        ):
            raise KubernetesReleaseError(f"{name} must spread replicas across zones")

    for workload in workloads:
        name = workload["metadata"]["name"]
        pod_spec = _pod_spec(workload)
        if not pod_spec.get("serviceAccountName") or (
            pod_spec.get("automountServiceAccountToken") is not False
        ):
            raise KubernetesReleaseError(f"{name} must use a tokenless dedicated service account")
        security = pod_spec.get("securityContext", {})
        if (
            security.get("runAsNonRoot") is not True
            or security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
        ):
            raise KubernetesReleaseError(f"{name} pod security context is incomplete")
        if any(pod_spec.get(item) is True for item in ("hostNetwork", "hostPID", "hostIPC")):
            raise KubernetesReleaseError(f"{name} requests a host namespace")
        for volume in pod_spec.get("volumes", []):
            if isinstance(volume, dict) and "hostPath" in volume:
                raise KubernetesReleaseError(f"{name} uses a hostPath volume")
        containers = [*pod_spec.get("initContainers", []), *pod_spec.get("containers", [])]
        if not containers:
            raise KubernetesReleaseError(f"{name} has no containers")
        for container in containers:
            container_name = container.get("name", "unnamed")
            context = container.get("securityContext", {})
            dropped = context.get("capabilities", {}).get("drop", [])
            if (
                context.get("allowPrivilegeEscalation") is not False
                or context.get("readOnlyRootFilesystem") is not True
                or "ALL" not in dropped
            ):
                raise KubernetesReleaseError(
                    f"{name}/{container_name} container security context is incomplete"
                )
            resources = container.get("resources", {})
            if not resources.get("requests") or not resources.get("limits"):
                raise KubernetesReleaseError(f"{name}/{container_name} needs resource bounds")
            image = container.get("image")
            if not isinstance(image, str):
                raise KubernetesReleaseError(f"{name}/{container_name} has no image")
            if rendered and not DIGEST_IMAGE.fullmatch(image):
                raise KubernetesReleaseError("rendered images must use immutable SHA-256 digests")

    api = _required_manifest(documents, "Deployment", "crisisweave-api")
    worker = _required_manifest(documents, "Deployment", "crisisweave-worker")
    parser = _required_manifest(documents, "Deployment", "crisisweave-parser")
    ui = _required_manifest(documents, "Deployment", "crisisweave-ui")
    otel = _required_manifest(documents, "Deployment", "crisisweave-otel")
    api_image = _container(api, "api")["image"]
    reviewed_model_images = {
        api_image,
        _container(worker, "worker")["image"],
        _container(parser, "parser")["image"],
        *(item.get("image") for item in _pod_spec(api).get("initContainers", [])),
    }
    if reviewed_model_images != {api_image}:
        raise KubernetesReleaseError("API, worker and parser must use one reviewed model image")
    ui_image = _container(ui, "ui")["image"]
    otel_image = _container(otel, "collector")["image"]
    if len({api_image, ui_image, otel_image}) != 3:
        raise KubernetesReleaseError("API, UI and telemetry images must use distinct artifacts")

    for name, (minimum, _, _) in EXPECTED_DEPLOYMENTS.items():
        pdb = _required_manifest(documents, "PodDisruptionBudget", name)
        spec = pdb.get("spec", {})
        if "minAvailable" not in spec and "maxUnavailable" not in spec:
            raise KubernetesReleaseError(f"{name} disruption budget is empty")
        if name == "crisisweave-otel":
            continue
        hpa = _required_manifest(documents, "HorizontalPodAutoscaler", name)
        hpa_spec = hpa.get("spec", {})
        if (
            hpa_spec.get("scaleTargetRef", {}).get("name") != name
            or hpa_spec.get("minReplicas", 0) < minimum
            or hpa_spec.get("maxReplicas", 0) <= hpa_spec.get("minReplicas", 0)
            or not hpa_spec.get("metrics")
        ):
            raise KubernetesReleaseError(f"{name} autoscaling policy is incomplete")


def _validate_external_secrets(
    documents: dict[tuple[str, str], dict[str, Any]], *, rendered: bool
) -> None:
    secret_names = ["api", "worker", "parser", "telemetry"]
    if not rendered:
        secret_names.append("migration")
    for name in secret_names:
        external_secret = _required_manifest(documents, "ExternalSecret", f"crisisweave-{name}")
        spec = external_secret.get("spec", {})
        if spec.get("secretStoreRef") != {
            "kind": "ClusterSecretStore",
            "name": "crisisweave-secret-store",
        }:
            raise KubernetesReleaseError(f"crisisweave-{name} must use the central secret store")
        if spec.get("target", {}).get("name") != f"crisisweave-{name}-runtime":
            raise KubernetesReleaseError(f"crisisweave-{name} has an unsafe target Secret")
        if spec.get("target", {}).get("creationPolicy") != "Owner":
            raise KubernetesReleaseError(f"crisisweave-{name} must own its generated Secret")

    if rendered:
        if ("ExternalSecret", "crisisweave-migration") in documents or (
            "Job",
            "crisisweave-migrate",
        ) in documents:
            raise KubernetesReleaseError("migration credentials must be absent from steady state")
    else:
        migration_secret = _required_manifest(documents, "ExternalSecret", "crisisweave-migration")
        if migration_secret.get("spec", {}).get("refreshPolicy") != "CreatedOnce":
            raise KubernetesReleaseError("migration credentials must use one-shot owner lifecycle")
        kustomization = _required_manifest(documents, "Kustomization", "kustomization")
        resources = set(kustomization.get("resources", []))
        required_resources = REQUIRED_FILES - {"kustomization.yaml", "migration.yaml"}
        if not required_resources.issubset(resources) or "migration.yaml" in resources:
            raise KubernetesReleaseError(
                "steady-state kustomization must include every control but exclude migration"
            )

    for deployment_name in (
        "crisisweave-api",
        "crisisweave-worker",
        "crisisweave-parser",
        "crisisweave-otel",
    ):
        deployment = _required_manifest(documents, "Deployment", deployment_name)
        annotations = (
            deployment.get("spec", {})
            .get("template", {})
            .get("metadata", {})
            .get("annotations", {})
        )
        if annotations.get("reloader.stakater.com/auto") != "true":
            raise KubernetesReleaseError(
                f"{deployment_name} must roll pods after generated Secret rotation"
            )


def _validate_forwarded_cidrs(value: Any, *, rendered: bool) -> None:
    if not rendered:
        if value != "REPLACE_WITH_INGRESS_PROXY_CIDRS":
            raise KubernetesReleaseError("raw API proxy CIDRs must remain an explicit placeholder")
        return
    if not isinstance(value, str) or not value.strip() or "REPLACE_WITH_" in value:
        raise KubernetesReleaseError("rendered API proxy CIDRs are missing")
    for item in value.split(","):
        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError as exc:
            raise KubernetesReleaseError("rendered API proxy CIDRs are invalid") from exc
        if network.prefixlen == 0:
            raise KubernetesReleaseError("rendered API proxy CIDRs must reject /0 trust ranges")


def _validate_role_configuration(
    documents: dict[tuple[str, str], dict[str, Any]], *, rendered: bool
) -> None:
    runtime = _required_manifest(documents, "ConfigMap", "crisisweave-runtime").get("data", {})
    expected_runtime = {
        "CRISISWEAVE_APP_ENV": "production",
        "CRISISWEAVE_DATABASE_BACKEND": "postgresql",
        "CRISISWEAVE_OBJECT_STORE_BACKEND": "s3",
        "CRISISWEAVE_POSTGRES_RLS_ENABLED": "true",
        "CRISISWEAVE_TELEMETRY_ENABLED": "true",
        "CRISISWEAVE_INGESTION_LIFECYCLE_RETENTION_DAYS": "14",
    }
    if any(runtime.get(key) != value for key, value in expected_runtime.items()):
        raise KubernetesReleaseError("common production runtime controls are incomplete")
    if {
        "CRISISWEAVE_AUTH_MODE",
        "CRISISWEAVE_API_KEYS",
        "CRISISWEAVE_TRUST_PROXY_HEADERS",
        "CRISISWEAVE_OVERSIGHT_ENABLED",
        "CRISISWEAVE_OIDC_ALLOW_PRIVATE_JWKS",
    } & set(runtime):
        raise KubernetesReleaseError(
            "common runtime must not contain role-specific identity controls"
        )

    api_config = _required_manifest(documents, "ConfigMap", "crisisweave-api-config").get(
        "data", {}
    )
    api_expected = {
        "CRISISWEAVE_AUTH_MODE": "oidc",
        "CRISISWEAVE_TRUST_PROXY_HEADERS": "true",
        "CRISISWEAVE_OIDC_ALLOW_PRIVATE_JWKS": "true",
        "CRISISWEAVE_OVERSIGHT_ENABLED": "true",
    }
    if any(api_config.get(key) != value for key, value in api_expected.items()):
        raise KubernetesReleaseError("API role security controls are incomplete")
    _validate_forwarded_cidrs(api_config.get("CRISISWEAVE_FORWARDED_ALLOW_IPS"), rendered=rendered)

    worker_config = _required_manifest(documents, "ConfigMap", "crisisweave-worker-config").get(
        "data", {}
    )
    worker_expected = {
        "CRISISWEAVE_AUTH_MODE": "api_key",
        "CRISISWEAVE_API_KEYS": "",
        "CRISISWEAVE_TRUST_PROXY_HEADERS": "false",
        "CRISISWEAVE_LLM_PROVIDER": "disabled",
        "CRISISWEAVE_PROVIDER_CANARY_ON_STARTUP": "false",
        "CRISISWEAVE_WORKER_METRICS_HOST": ALL_INTERFACES,
        "CRISISWEAVE_WORKER_METRICS_PORT": "9100",
    }
    if any(worker_config.get(key) != value for key, value in worker_expected.items()):
        raise KubernetesReleaseError("worker role security or metrics controls are incomplete")

    migration_config = _required_manifest(
        documents, "ConfigMap", "crisisweave-migration-config"
    ).get("data", {})
    migration_expected = {
        "CRISISWEAVE_AUTH_MODE": "api_key",
        "CRISISWEAVE_API_KEYS": "",
        "CRISISWEAVE_TRUST_PROXY_HEADERS": "false",
        "CRISISWEAVE_LLM_PROVIDER": "disabled",
        "CRISISWEAVE_PROVIDER_CANARY_ON_STARTUP": "false",
        "CRISISWEAVE_WORKER_METRICS_PORT": "0",
    }
    if any(migration_config.get(key) != value for key, value in migration_expected.items()):
        raise KubernetesReleaseError("migration role security controls are incomplete")

    api = _required_manifest(documents, "Deployment", "crisisweave-api")
    for container in [
        *_pod_spec(api).get("initContainers", []),
        _container(api, "api"),
    ]:
        _require_environment_from(
            container,
            label="crisisweave-api",
            config_maps={"crisisweave-runtime", "crisisweave-api-config"},
            secrets={"crisisweave-api-runtime"},
        )
        values = _environment_values(container, "crisisweave-api")
        if any(
            values.get(key) != value
            for key, value in {
                "CRISISWEAVE_RUNTIME_ROLE": "api",
                "CRISISWEAVE_AUTH_MODE": "oidc",
                "CRISISWEAVE_TRUST_PROXY_HEADERS": "true",
                "CRISISWEAVE_OVERSIGHT_ENABLED": "true",
                "CRISISWEAVE_POSTGRES_RLS_ENABLED": "true",
            }.items()
        ):
            raise KubernetesReleaseError("API critical environment overrides are incomplete")

    worker = _required_manifest(documents, "Deployment", "crisisweave-worker")
    worker_container = _container(worker, "worker")
    _require_environment_from(
        worker_container,
        label="crisisweave-worker",
        config_maps={"crisisweave-runtime", "crisisweave-worker-config"},
        secrets={"crisisweave-worker-runtime"},
    )
    worker_values = _environment_values(worker_container, "crisisweave-worker")
    worker_overrides = {
        "CRISISWEAVE_RUNTIME_ROLE": "ingestion_worker",
        "CRISISWEAVE_AUTH_MODE": "api_key",
        "CRISISWEAVE_API_KEYS": "",
        "CRISISWEAVE_TRUST_PROXY_HEADERS": "false",
        "CRISISWEAVE_PROVIDER_CANARY_ON_STARTUP": "false",
        "CRISISWEAVE_POSTGRES_RLS_ENABLED": "true",
        "CRISISWEAVE_PARSER_SERVICE_URL": "http://crisisweave-parser:8001",
        "CRISISWEAVE_WORKER_METRICS_HOST": ALL_INTERFACES,
        "CRISISWEAVE_WORKER_METRICS_PORT": "9100",
    }
    if any(worker_values.get(key) != value for key, value in worker_overrides.items()):
        raise KubernetesReleaseError("worker critical environment overrides are incomplete")

    if not rendered:
        migration = _required_manifest(documents, "Job", "crisisweave-migrate")
        migration_container = _container(migration, "migration")
        _require_environment_from(
            migration_container,
            label="crisisweave-migration",
            config_maps={"crisisweave-runtime", "crisisweave-migration-config"},
            secrets={"crisisweave-migration-runtime"},
        )
        migration_values = _environment_values(migration_container, "crisisweave-migration")
        if any(
            migration_values.get(key) != value
            for key, value in {
                "CRISISWEAVE_RUNTIME_ROLE": "migration",
                "CRISISWEAVE_AUTH_MODE": "api_key",
                "CRISISWEAVE_API_KEYS": "",
                "CRISISWEAVE_TRUST_PROXY_HEADERS": "false",
                "CRISISWEAVE_PROVIDER_CANARY_ON_STARTUP": "false",
                "CRISISWEAVE_POSTGRES_RLS_ENABLED": "true",
            }.items()
        ):
            raise KubernetesReleaseError("migration critical environment overrides are incomplete")

    expected_secret_sets = {
        "crisisweave-api": {"crisisweave-api-runtime"},
        "crisisweave-worker": {"crisisweave-worker-runtime"},
        "crisisweave-parser": {"crisisweave-parser-runtime"},
        "crisisweave-ui": set(),
    }
    for name, expected_secrets in expected_secret_sets.items():
        pod_spec = _pod_spec(_required_manifest(documents, "Deployment", name))
        if _pod_secret_references(pod_spec, name) != expected_secrets:
            raise KubernetesReleaseError(f"{name} crosses its workload Secret boundary")

    parser = _required_manifest(documents, "Deployment", "crisisweave-parser")
    parser_container = _container(parser, "parser")
    parser_config_maps, parser_env_from_secrets = _environment_from(
        parser_container, "crisisweave-parser"
    )
    if parser_config_maps or parser_env_from_secrets:
        raise KubernetesReleaseError("parser secrets must use explicit secretKeyRef entries only")
    parser_environment = _environment(parser_container, "crisisweave-parser")
    parser_secret_entries = {
        name: item.get("valueFrom", {}).get("secretKeyRef")
        for name, item in parser_environment.items()
        if isinstance(item.get("valueFrom"), dict) and "secretKeyRef" in item.get("valueFrom", {})
    }
    if parser_secret_entries != {
        "CRISISWEAVE_PARSER_SERVICE_TOKEN": {
            "name": "crisisweave-parser-runtime",
            "key": "CRISISWEAVE_PARSER_SERVICE_TOKEN",
        }
    }:
        raise KubernetesReleaseError("parser must receive only its service token by secretKeyRef")

    for deployment_name, container_name in (
        ("crisisweave-api", "api"),
        ("crisisweave-worker", "worker"),
        ("crisisweave-parser", "parser"),
    ):
        deployment = _required_manifest(documents, "Deployment", deployment_name)
        values = _environment_values(_container(deployment, container_name), deployment_name)
        if values.get("CRISISWEAVE_OTEL_EXPORTER_CA_FILE") != "/otel-ca/ca.crt":
            raise KubernetesReleaseError(f"{deployment_name} must use the dedicated OTLP CA")

    ui_values = _environment_values(
        _container(_required_manifest(documents, "Deployment", "crisisweave-ui"), "ui"),
        "crisisweave-ui",
    )
    if ui_values.get("CRISISWEAVE_UI_AUTH_MODE") != "forwarded_bearer":
        raise KubernetesReleaseError("production UI must use ingress-forwarded bearer identity")


def _validate_parser_isolation(documents: dict[tuple[str, str], dict[str, Any]]) -> None:
    worker = _required_manifest(documents, "Deployment", "crisisweave-worker")
    parser = _required_manifest(documents, "Deployment", "crisisweave-parser")
    for deployment, role in ((worker, "worker"), (parser, "parser")):
        pod_spec = _pod_spec(deployment)
        for volume in pod_spec.get("volumes", []):
            if not isinstance(volume, dict):
                raise KubernetesReleaseError(f"{role} has a malformed volume")
            if "persistentVolumeClaim" in volume:
                raise KubernetesReleaseError("worker and parser must not share a persistent volume")
            source_types = set(volume) - {"name"}
            if not source_types.issubset({"emptyDir", "configMap"}):
                raise KubernetesReleaseError(
                    f"{role} volumes must be pod-local scratch or public configuration"
                )
        for container in pod_spec.get("containers", []):
            for mount in container.get("volumeMounts", []):
                mount_name = str(mount.get("name", "")).casefold()
                mount_path = str(mount.get("mountPath", "")).casefold()
                if "parser-job" in mount_name or "parser-job" in mount_path:
                    raise KubernetesReleaseError("shared parser-job volumes are forbidden")
                if role == "parser" and mount_path == "/data":
                    raise KubernetesReleaseError("parser must not mount worker data storage")


def _validate_worker_metrics(documents: dict[tuple[str, str], dict[str, Any]]) -> None:
    worker = _required_manifest(documents, "Deployment", "crisisweave-worker")
    container = _container(worker, "worker")
    ports = {
        item.get("name"): item.get("containerPort")
        for item in container.get("ports", [])
        if isinstance(item, dict)
    }
    if ports.get("metrics") != 9100:
        raise KubernetesReleaseError("worker must expose its metrics port")
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        probe = container.get(probe_name, {})
        if probe.get("tcpSocket", {}).get("port") != "metrics":
            raise KubernetesReleaseError(f"worker {probe_name} must check the metrics server")

    service = _required_manifest(documents, "Service", "crisisweave-worker-metrics")
    if (
        service.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        != "crisisweave-worker"
        or service.get("spec", {}).get("selector", {}).get("app.kubernetes.io/name")
        != "crisisweave-worker"
    ):
        raise KubernetesReleaseError("worker metrics Service must select worker pods")
    service_ports = service.get("spec", {}).get("ports", [])
    if not any(
        item.get("name") == "metrics"
        and item.get("port") == 9100
        and item.get("targetPort") == "metrics"
        for item in service_ports
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("worker metrics Service port is incomplete")

    monitor = _required_manifest(documents, "ServiceMonitor", "crisisweave-worker")
    if (
        monitor.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
        .get("app.kubernetes.io/name")
        != "crisisweave-worker"
    ):
        raise KubernetesReleaseError("worker ServiceMonitor must select the metrics Service")
    endpoints = monitor.get("spec", {}).get("endpoints", [])
    if not any(
        item.get("port") == "metrics" and item.get("path") == "/metrics"
        for item in endpoints
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("worker ServiceMonitor endpoint is incomplete")


def _validate_slo_rules(documents: dict[tuple[str, str], dict[str, Any]]) -> None:
    api_monitor = _required_manifest(documents, "ServiceMonitor", "crisisweave-api")
    if (
        api_monitor.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
        .get("app.kubernetes.io/name")
        != "crisisweave-api"
    ):
        raise KubernetesReleaseError("API ServiceMonitor must select the API metrics Service")
    api_endpoints = api_monitor.get("spec", {}).get("endpoints", [])
    expected_authorization = {
        "type": "Bearer",
        "credentials": {
            "name": "crisisweave-api-runtime",
            "key": "CRISISWEAVE_METRICS_API_KEY",
        },
    }
    if not any(
        item.get("port") == "http"
        and item.get("path") == "/metrics"
        and item.get("authorization") == expected_authorization
        for item in api_endpoints
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("API ServiceMonitor authorization is incomplete")

    prometheus_rule = _required_manifest(documents, "PrometheusRule", "crisisweave-slos")
    groups = prometheus_rule.get("spec", {}).get("groups", [])
    rules = [
        rule
        for group in groups
        if isinstance(group, dict)
        for rule in group.get("rules", [])
        if isinstance(rule, dict)
    ]
    records = {
        rule["record"]: rule.get("expr") for rule in rules if isinstance(rule.get("record"), str)
    }
    alerts = {rule["alert"]: rule for rule in rules if isinstance(rule.get("alert"), str)}

    def histogram_expression(quantile: str, metric: str, selector: str, window: str) -> str:
        return (
            f"histogram_quantile({quantile}, sum by (le) "
            f"(rate({metric}_bucket{{{selector}}}[{window}])))"
        )

    expected_records = {
        "crisisweave:slo_query_end_to_end_seconds:p50_5m": histogram_expression(
            "0.50",
            "crisisweave_query_end_to_end_duration_seconds",
            'status_class="2xx"',
            "5m",
        ),
        "crisisweave:slo_query_end_to_end_seconds:p95_5m": histogram_expression(
            "0.95",
            "crisisweave_query_end_to_end_duration_seconds",
            'status_class="2xx"',
            "5m",
        ),
        "crisisweave:slo_query_end_to_end_seconds:p99_5m": histogram_expression(
            "0.99",
            "crisisweave_query_end_to_end_duration_seconds",
            'status_class="2xx"',
            "5m",
        ),
        "crisisweave:slo_ingestion_end_to_end_seconds:p50_30m": histogram_expression(
            "0.50",
            "crisisweave_ingestion_job_end_to_end_seconds",
            'status="succeeded"',
            "30m",
        ),
        "crisisweave:slo_ingestion_end_to_end_seconds:p95_30m": histogram_expression(
            "0.95",
            "crisisweave_ingestion_job_end_to_end_seconds",
            'status="succeeded"',
            "30m",
        ),
        "crisisweave:slo_ingestion_end_to_end_seconds:p99_30m": histogram_expression(
            "0.99",
            "crisisweave_ingestion_job_end_to_end_seconds",
            'status="succeeded"',
            "30m",
        ),
        "crisisweave:slo_pipeline_error_ratio:rate5m": (
            'sum(rate(crisisweave_pipeline_operations_total{status="error"}[5m])) / '
            "clamp_min(sum(rate(crisisweave_pipeline_operations_total[5m])), 0.000001)"
        ),
    }
    if any(records.get(name) != expression for name, expression in expected_records.items()):
        raise KubernetesReleaseError("Prometheus SLO recording rules are incomplete")

    expected_alerts = {
        "CrisisWeaveQueryLatencySLOBreach": (
            "crisisweave:slo_query_end_to_end_seconds:p95_5m > 10"
        ),
        "CrisisWeaveIngestionLatencySLOBreach": (
            "crisisweave:slo_ingestion_end_to_end_seconds:p95_30m > 600"
        ),
        "CrisisWeavePipelineErrorBudgetBurn": (
            "crisisweave:slo_pipeline_error_ratio:rate5m > 0.01"
        ),
        "CrisisWeaveDeadLetterPresent": (
            'max(crisisweave_ingestion_jobs{status="dead_letter"}) > 0'
        ),
        "CrisisWeaveQueueMetricsStale": (
            "increase(crisisweave_ingestion_job_metric_refresh_failures_total[10m]) > 0"
        ),
        "CrisisWeaveLifecycleOutboxStale": (
            "max(crisisweave_ingestion_lifecycle_outbox_oldest_pending_seconds) > 300"
        ),
    }
    for name, expression in expected_alerts.items():
        rule = alerts.get(name, {})
        if (
            rule.get("expr") != expression
            or not isinstance(rule.get("for"), str)
            or rule.get("labels", {}).get("severity") not in {"warning", "critical"}
            or not isinstance(rule.get("annotations", {}).get("summary"), str)
        ):
            raise KubernetesReleaseError("Prometheus SLO alert rules are incomplete")


def _validate_mesh_and_networking(documents: dict[tuple[str, str], dict[str, Any]]) -> None:
    namespace = _required_manifest(documents, "Namespace", "crisisweave")
    labels = namespace.get("metadata", {}).get("labels", {})
    if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        raise KubernetesReleaseError("restricted Pod Security enforcement is required")
    if labels.get("istio-injection") != "enabled":
        raise KubernetesReleaseError("the CrisisWeave namespace must enable Istio injection")
    peer_auth = _required_manifest(documents, "PeerAuthentication", "crisisweave-strict-mtls")
    if peer_auth.get("apiVersion") != "security.istio.io/v1" or peer_auth.get("spec") != {
        "mtls": {"mode": "STRICT"}
    }:
        raise KubernetesReleaseError("namespace-wide Istio STRICT mTLS is required")

    default_deny = _required_manifest(documents, "NetworkPolicy", "default-deny")
    deny_spec = default_deny.get("spec", {})
    if (
        deny_spec.get("podSelector") != {}
        or set(deny_spec.get("policyTypes", [])) != {"Ingress", "Egress"}
        or "ingress" in deny_spec
        or "egress" in deny_spec
    ):
        raise KubernetesReleaseError("default-deny must select every pod and allow no traffic")

    for name, egress_class in (
        ("api-egress", "api"),
        ("worker-egress", "worker"),
        ("parser-egress", "parser"),
        ("migration-egress", "migration"),
        ("telemetry-egress", "telemetry"),
        ("ui-egress", "ui"),
    ):
        policy = _required_manifest(documents, "NetworkPolicy", name)
        spec = policy.get("spec", {})
        if (
            spec.get("podSelector", {}).get("matchLabels", {}).get("crisisweave.io/egress-class")
            != egress_class
            or "Egress" not in spec.get("policyTypes", [])
            or not spec.get("egress")
        ):
            raise KubernetesReleaseError(f"{name} does not constrain the intended workload")

    parser_egress = _required_manifest(documents, "NetworkPolicy", "parser-egress")
    parser_rules = parser_egress.get("spec", {}).get("egress", [])
    if parser_rules != [
        {
            "to": [
                {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "crisisweave-otel"}}}
            ],
            "ports": [{"protocol": "TCP", "port": 4318}],
        }
    ]:
        raise KubernetesReleaseError("parser egress must be limited to the telemetry collector")

    parser_ingress = _required_manifest(documents, "NetworkPolicy", "parser-ingress")
    parser_ingress_rules = parser_ingress.get("spec", {}).get("ingress", [])
    if not any(
        {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "crisisweave-worker"}}}
        in item.get("from", [])
        and {"protocol": "TCP", "port": 8001} in item.get("ports", [])
        for item in parser_ingress_rules
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("parser ingress must accept only the worker transport")

    worker_egress = _required_manifest(documents, "NetworkPolicy", "worker-egress")
    if not any(
        {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "crisisweave-parser"}}}
        in item.get("to", [])
        and {"protocol": "TCP", "port": 8001} in item.get("ports", [])
        for item in worker_egress.get("spec", {}).get("egress", [])
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("worker egress must explicitly target the parser Service")

    metrics_ingress = _required_manifest(documents, "NetworkPolicy", "worker-metrics-ingress")
    if not any(
        {"protocol": "TCP", "port": 9100} in item.get("ports", [])
        for item in metrics_ingress.get("spec", {}).get("ingress", [])
        if isinstance(item, dict)
    ):
        raise KubernetesReleaseError("monitoring ingress to worker metrics is missing")


def _validate_structured_controls(
    documents: dict[tuple[str, str], dict[str, Any]], *, rendered: bool
) -> None:
    if any(kind == "Secret" for kind, _ in documents):
        raise KubernetesReleaseError("literal Kubernetes Secrets are forbidden")
    _validate_workloads(documents, rendered=rendered)
    _validate_external_secrets(documents, rendered=rendered)
    _validate_role_configuration(documents, rendered=rendered)
    _validate_parser_isolation(documents)
    _validate_worker_metrics(documents)
    _validate_slo_rules(documents)
    _validate_mesh_and_networking(documents)


def validate_tree(root: Path, *, rendered: bool) -> None:
    if not root.is_dir():
        raise KubernetesReleaseError("Kubernetes manifest directory does not exist")
    paths = sorted(root.glob("*.yaml"))
    missing = REQUIRED_FILES - {path.name for path in paths}
    if not rendered and missing:
        raise KubernetesReleaseError(f"missing Kubernetes manifest: {sorted(missing)[0]}")
    if not paths:
        raise KubernetesReleaseError("Kubernetes manifest directory is empty")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    documents = _load_documents(paths)
    lowered = combined.casefold()
    forbidden = {
        "kind: secret\n": "literal Kubernetes Secrets are forbidden",
        "hostnetwork: true": "host networking is forbidden",
        "hostpid: true": "host PID access is forbidden",
        "hostipc: true": "host IPC access is forbidden",
        "privileged: true": "privileged containers are forbidden",
        "allowprivilegeescalation: true": "privilege escalation is forbidden",
        "hostpath:": "hostPath volumes are forbidden",
        "imagepullpolicy: always": "mutable image pulls are forbidden",
        ":latest": "latest image tags are forbidden",
        "ssl_cert_file": "workloads must not replace the process-wide TLS trust store",
    }
    for token, message in forbidden.items():
        if token in lowered:
            raise KubernetesReleaseError(message)

    images = IMAGE_LINE.findall(combined)
    minimum_images = 6 if rendered else 7
    if len(images) < minimum_images:
        raise KubernetesReleaseError("the release must contain every workload image")
    for image in images:
        if rendered:
            if not DIGEST_IMAGE.fullmatch(image):
                raise KubernetesReleaseError("rendered images must use immutable SHA-256 digests")
        elif not (RAW_IMAGE.fullmatch(image) or DIGEST_IMAGE.fullmatch(image)):
            raise KubernetesReleaseError("base images must be explicit release placeholders")

    if rendered and "REPLACE_WITH_" in combined:
        raise KubernetesReleaseError("rendered release still contains placeholders")
    _validate_structured_controls(documents, rendered=rendered)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--rendered", action="store_true")
    args = parser.parse_args()
    try:
        validate_tree(args.path, rendered=args.rendered)
    except KubernetesReleaseError as exc:
        parser.error(str(exc))
    print(
        "Validated Kubernetes identity, parser isolation, mTLS, scaling, egress, "
        "telemetry, and workload controls."
    )


if __name__ == "__main__":
    main()
