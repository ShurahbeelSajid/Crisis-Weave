from __future__ import annotations

import base64
import hashlib
import io
import sys
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from crisisweave.extractors import ExtractionResult
from crisisweave.ingestion import IngestionService
from crisisweave.models import (
    Chunk,
    Document,
    DocumentStatus,
    ImageBoundingBoxRegion,
    Modality,
    NormalizedBoundingBox,
    RegionSource,
)
from crisisweave.object_store import LocalObjectStore, S3ObjectStore
from crisisweave.postgres_storage import PostgresMetadataStore
from crisisweave.security import SecurityError, sha256_file
from crisisweave.storage import MetadataStore, validate_analytics_sql


def test_local_object_store_is_immutable_bounded_and_confined(tmp_path: Path) -> None:
    source = tmp_path / "upload.pdf"
    source.write_bytes(b"trusted evidence")
    digest = sha256_file(source)
    store = LocalObjectStore(tmp_path / "objects", tmp_path / "artifacts")

    tenant_id = "a" * 32
    reference = store.put_original(source, tenant_id=tenant_id, sha256=digest, suffix=".pdf")
    assert store.read_bytes(reference, 1024) == b"trusted evidence"
    assert (
        store.put_original(source, tenant_id=tenant_id, sha256=digest, suffix=".pdf") == reference
    )

    materialized = tmp_path / "job" / "input.pdf"
    store.materialize(
        reference,
        materialized,
        max_bytes=1024,
        expected_sha256=digest,
    )
    assert materialized.read_bytes() == b"trusted evidence"

    Path(reference).write_bytes(b"tampered")
    with pytest.raises(SecurityError, match="different content"):
        store.put_original(source, tenant_id=tenant_id, sha256=digest, suffix=".pdf")
    with pytest.raises(SecurityError, match="escaped"):
        store.read_bytes(str(source), 1024)


def test_original_survives_cross_tenant_publish_delete_interleaving(
    tmp_path: Path,
) -> None:
    """Tenant-scoped keys close the publish/reference versus delete race."""
    source = tmp_path / "shared.pdf"
    source.write_bytes(b"identical evidence")
    digest = sha256_file(source)
    store = LocalObjectStore(tmp_path / "objects", tmp_path / "artifacts")

    first = store.put_original(source, tenant_id="a" * 32, sha256=digest, suffix=".pdf")
    second = store.put_original(source, tenant_id="b" * 32, sha256=digest, suffix=".pdf")
    assert first != second

    # This is the dangerous ordering for a global key: B publishes, then A removes
    # its last metadata reference before B records its own. B's isolated key survives.
    store.delete(first)
    assert store.read_bytes(second, 1024) == b"identical evidence"


class _Body(io.BytesIO):
    pass


class _S3ReadClient:
    def __init__(self, payload: bytes, digest: str) -> None:
        self.payload = payload
        self.digest = digest
        self.content_length = len(payload)
        self.calls: list[dict[str, Any]] = []
        self.bodies: list[_Body] = []

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        body = _Body(self.payload)
        self.bodies.append(body)
        return {
            "Body": body,
            "ContentLength": self.content_length,
            "Metadata": {"sha256": self.digest},
        }


def _s3_store(client: Any) -> S3ObjectStore:
    store = object.__new__(S3ObjectStore)
    store.bucket = "crisisweave-evidence"
    store.prefix = "tenant-data"
    store._sse = "AES256"  # noqa: SLF001
    store._kms_key_id = None  # noqa: SLF001
    store._client = client  # noqa: SLF001
    return store


class _FakeClientError(Exception):
    def __init__(self, response: dict[str, Any]) -> None:
        super().__init__(response)
        self.response = response


class _FakeBotocoreConfig:
    instances: list[_FakeBotocoreConfig] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.instances.append(self)


@pytest.fixture
def _fake_botocore(monkeypatch: pytest.MonkeyPatch) -> None:
    botocore_module = ModuleType("botocore")
    exceptions_module = ModuleType("botocore.exceptions")
    config_module = ModuleType("botocore.config")
    exceptions_module.__dict__["ClientError"] = _FakeClientError
    config_module.__dict__["Config"] = _FakeBotocoreConfig
    botocore_module.__dict__["exceptions"] = exceptions_module
    botocore_module.__dict__["config"] = config_module
    _FakeBotocoreConfig.instances.clear()
    monkeypatch.setitem(sys.modules, "botocore", botocore_module)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions_module)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)


class _S3WriteClient:
    def __init__(
        self,
        put_results: list[dict[str, Any] | Exception],
        head_results: list[dict[str, Any]],
    ) -> None:
        self.put_results = iter(put_results)
        self.head_results = iter(head_results)
        self.put_calls: list[dict[str, Any]] = []
        self.head_calls: list[dict[str, Any]] = []
        self.uploads: list[bytes] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.uploads.append(bytes(kwargs["Body"].read()))
        self.put_calls.append({key: value for key, value in kwargs.items() if key != "Body"})
        result = next(self.put_results)
        if isinstance(result, Exception):
            raise result
        return result

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.head_calls.append(kwargs)
        return next(self.head_results)


def test_s3_constructor_builds_timeout_retry_and_addressing_configuration(
    _fake_botocore: None,
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
) -> None:
    del _fake_botocore
    client = object()
    client_calls: list[tuple[str, dict[str, Any]]] = []
    boto3_module = ModuleType("boto3")

    def fake_client(service: str, **kwargs: Any) -> object:
        client_calls.append((service, kwargs))
        return client

    boto3_module.__dict__["client"] = fake_client
    monkeypatch.setitem(sys.modules, "boto3", boto3_module)
    configured = settings.model_copy(
        update={
            "s3_bucket": "crisisweave-evidence",
            "s3_prefix": "/tenant-data/",
            "s3_endpoint_url": "https://objects.example.test",
            "s3_region": "eu-west-1",
            "s3_addressing_style": "path",
            "object_store_timeout_seconds": 9.0,
        }
    )

    store = S3ObjectStore(configured)

    assert store.bucket == "crisisweave-evidence"
    assert store.prefix == "tenant-data"
    assert client_calls == [
        (
            "s3",
            {
                "endpoint_url": "https://objects.example.test",
                "region_name": "eu-west-1",
                "config": _FakeBotocoreConfig.instances[0],
            },
        )
    ]
    assert _FakeBotocoreConfig.instances[0].kwargs == {
        "connect_timeout": 9.0,
        "read_timeout": 9.0,
        "retries": {"max_attempts": 3, "mode": "standard"},
        "s3": {"addressing_style": "path"},
    }
    assert store._client is client  # noqa: SLF001


def test_s3_constructor_requires_bucket(
    _fake_botocore: None,
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
) -> None:
    del _fake_botocore
    monkeypatch.setitem(sys.modules, "boto3", ModuleType("boto3"))

    with pytest.raises(ValueError, match="s3_bucket is required"):
        S3ObjectStore(settings.model_copy(update={"s3_bucket": None}))


def test_s3_put_success_uses_immutable_checksum_encryption_and_exact_version(
    _fake_botocore: None,
    tmp_path: Path,
) -> None:
    del _fake_botocore
    payload = b"immutable storm evidence"
    digest = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "evidence.pdf"
    source.write_bytes(payload)
    client = _S3WriteClient(
        [{"VersionId": "version 1"}],
        [{"Metadata": {"sha256": digest}}],
    )
    store = _s3_store(client)
    store._sse = "aws:kms"  # noqa: SLF001
    store._kms_key_id = SimpleNamespace(  # type: ignore[assignment]  # noqa: SLF001
        get_secret_value=lambda: "alias/crisisweave"
    )

    reference = store.put_original(
        source,
        tenant_id="a" * 32,
        sha256=digest,
        suffix=".pdf",
    )

    key = f"tenant-data/v1/tenants/{'a' * 32}/originals/{digest[:2]}/{digest}.pdf"
    assert reference == f"s3://crisisweave-evidence/{key}?versionId=version%201"
    assert client.uploads == [payload]
    assert client.put_calls == [
        {
            "ContentLength": len(payload),
            "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
            "Bucket": "crisisweave-evidence",
            "Key": key,
            "Metadata": {"sha256": digest},
            "ServerSideEncryption": "aws:kms",
            "IfNoneMatch": "*",
            "SSEKMSKeyId": "alias/crisisweave",
        }
    ]
    assert client.head_calls == [
        {"Bucket": "crisisweave-evidence", "Key": key, "VersionId": "version 1"}
    ]


def test_s3_put_artifact_and_job_input_use_tenant_scoped_lineage_keys(
    _fake_botocore: None,
    tmp_path: Path,
) -> None:
    del _fake_botocore
    artifact_payload = b"derived frame"
    job_payload = b"queued upload"
    artifact_digest = hashlib.sha256(artifact_payload).hexdigest()
    job_digest = hashlib.sha256(job_payload).hexdigest()
    artifact = tmp_path / "frame.JPG"
    job_input = tmp_path / "queued.pdf"
    artifact.write_bytes(artifact_payload)
    job_input.write_bytes(job_payload)
    client = _S3WriteClient(
        [{"VersionId": "artifact-v1"}, {"VersionId": "job-v1"}],
        [
            {"Metadata": {"sha256": artifact_digest}},
            {"Metadata": {"sha256": job_digest}},
        ],
    )
    store = _s3_store(client)
    tenant_id = "b" * 32
    document_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    artifact_reference = store.put_artifact(
        artifact,
        tenant_id=tenant_id,
        document_id=document_id,
        filename="frame.JPG",
    )
    job_reference = store.put_job_input(
        job_input,
        tenant_id=tenant_id,
        job_id=job_id,
        sha256=job_digest,
        suffix=".pdf",
    )

    artifact_key = (
        f"tenant-data/v1/tenants/{tenant_id}/documents/{document_id}/{artifact_digest}.jpg"
    )
    job_key = f"tenant-data/v1/tenants/{tenant_id}/jobs/{job_id}/{job_digest}.pdf"
    assert artifact_reference == (f"s3://crisisweave-evidence/{artifact_key}?versionId=artifact-v1")
    assert job_reference == f"s3://crisisweave-evidence/{job_key}?versionId=job-v1"
    assert [call["Key"] for call in client.put_calls] == [artifact_key, job_key]
    assert client.uploads == [artifact_payload, job_payload]


@pytest.mark.parametrize(
    ("tenant_id", "digest", "suffix"),
    [
        ("invalid", "a" * 64, ".pdf"),
        ("a" * 32, "invalid", ".pdf"),
        ("a" * 32, "a" * 64, "../pdf"),
    ],
)
def test_s3_put_original_rejects_invalid_lineage_before_network_io(
    tmp_path: Path,
    tenant_id: str,
    digest: str,
    suffix: str,
) -> None:
    source = tmp_path / "evidence.pdf"
    source.write_bytes(b"evidence")
    client = _S3WriteClient([], [])

    with pytest.raises(SecurityError):
        _s3_store(client).put_original(
            source,
            tenant_id=tenant_id,
            sha256=digest,
            suffix=suffix,
        )

    assert client.put_calls == []


@pytest.mark.parametrize(
    ("tenant_id", "document_id", "filename"),
    [
        ("invalid", str(uuid.uuid4()), "frame.jpg"),
        ("a" * 32, "invalid", "frame.jpg"),
        ("a" * 32, str(uuid.uuid4()), "../frame.jpg"),
    ],
)
def test_s3_put_artifact_rejects_invalid_lineage_before_network_io(
    tmp_path: Path,
    tenant_id: str,
    document_id: str,
    filename: str,
) -> None:
    source = tmp_path / "frame.jpg"
    source.write_bytes(b"frame")
    client = _S3WriteClient([], [])

    with pytest.raises(SecurityError, match="invalid"):
        _s3_store(client).put_artifact(
            source,
            tenant_id=tenant_id,
            document_id=document_id,
            filename=filename,
        )

    assert client.put_calls == []


def test_s3_put_job_input_rejects_invalid_lineage_before_network_io(
    tmp_path: Path,
) -> None:
    source = tmp_path / "queued.pdf"
    source.write_bytes(b"queued")
    client = _S3WriteClient([], [])

    with pytest.raises(SecurityError, match="Job object lineage"):
        _s3_store(client).put_job_input(
            source,
            tenant_id="a" * 32,
            job_id="invalid",
            sha256="a" * 64,
            suffix=".pdf",
        )

    assert client.put_calls == []


def test_s3_put_conditional_conflict_reuses_matching_existing_version(
    _fake_botocore: None,
    tmp_path: Path,
) -> None:
    del _fake_botocore
    payload = b"deduplicated evidence"
    digest = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "evidence.bin"
    source.write_bytes(payload)
    conflict = _FakeClientError(
        {
            "ResponseMetadata": {"HTTPStatusCode": 409},
            "Error": {"Code": "ConditionalRequestConflict"},
        }
    )
    client = _S3WriteClient(
        [conflict],
        [
            {"VersionId": "existing-v2", "Metadata": {"sha256": digest}},
            {"Metadata": {"sha256": digest}},
        ],
    )
    store = _s3_store(client)
    key = "tenant-data/v1/deduplicated.bin"

    reference = store._put(source, key, digest)  # noqa: SLF001

    assert reference.endswith("?versionId=existing-v2")
    assert client.head_calls == [
        {"Bucket": "crisisweave-evidence", "Key": key},
        {"Bucket": "crisisweave-evidence", "Key": key, "VersionId": "existing-v2"},
    ]


@pytest.mark.parametrize("version_id", [None, "null"])
def test_s3_put_rejects_missing_or_unversioned_response(
    _fake_botocore: None,
    tmp_path: Path,
    version_id: str | None,
) -> None:
    del _fake_botocore
    payload = b"versioned evidence"
    digest = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "evidence.bin"
    source.write_bytes(payload)
    client = _S3WriteClient([{"VersionId": version_id}], [])

    with pytest.raises(SecurityError, match="immutable version"):
        _s3_store(client)._put(source, "tenant-data/v1/evidence.bin", digest)  # noqa: SLF001

    assert client.head_calls == []


@pytest.mark.parametrize(
    ("put_result", "head_results", "message"),
    [
        (
            {"VersionId": "v1", "Metadata": {"sha256": "0" * 64}},
            [],
            "different content",
        ),
        (
            {"VersionId": "v1"},
            [{"Metadata": {"sha256": "0" * 64}}],
            "integrity metadata",
        ),
    ],
)
def test_s3_put_rejects_conflicting_or_missing_integrity_metadata(
    _fake_botocore: None,
    tmp_path: Path,
    put_result: dict[str, Any],
    head_results: list[dict[str, Any]],
    message: str,
) -> None:
    del _fake_botocore
    payload = b"integrity protected evidence"
    digest = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "evidence.bin"
    source.write_bytes(payload)
    client = _S3WriteClient([put_result], head_results)

    with pytest.raises(SecurityError, match=message):
        _s3_store(client)._put(source, "tenant-data/v1/evidence.bin", digest)  # noqa: SLF001


def test_s3_put_does_not_swallow_unexpected_client_error(
    _fake_botocore: None,
    tmp_path: Path,
) -> None:
    del _fake_botocore
    payload = b"unavailable storage"
    digest = hashlib.sha256(payload).hexdigest()
    source = tmp_path / "evidence.bin"
    source.write_bytes(payload)
    unavailable = _FakeClientError(
        {
            "ResponseMetadata": {"HTTPStatusCode": 503},
            "Error": {"Code": "SlowDown"},
        }
    )
    client = _S3WriteClient([unavailable], [])

    with pytest.raises(_FakeClientError):
        _s3_store(client)._put(source, "tenant-data/v1/evidence.bin", digest)  # noqa: SLF001


def test_s3_reads_exact_version_and_verifies_digest() -> None:
    payload = b"visual pixels"
    client = _S3ReadClient(payload, hashlib.sha256(payload).hexdigest())
    store = _s3_store(client)
    reference = "s3://crisisweave-evidence/tenant-data/v1/image.jpg?versionId=v-123"

    assert store.read_bytes(reference, 1024) == payload
    assert client.calls == [
        {
            "Bucket": "crisisweave-evidence",
            "Key": "tenant-data/v1/image.jpg",
            "VersionId": "v-123",
        }
    ]
    assert client.bodies[0].closed

    client.digest = "0" * 64
    with pytest.raises(SecurityError, match="integrity"):
        store.read_bytes(reference, 1024)
    assert client.bodies[1].closed


def test_s3_read_rejects_invalid_limit_before_network_io() -> None:
    client = _S3ReadClient(b"evidence", hashlib.sha256(b"evidence").hexdigest())

    with pytest.raises(SecurityError, match="limit is invalid"):
        _s3_store(client).read_bytes(
            "s3://crisisweave-evidence/tenant-data/v1/evidence?versionId=v1",
            0,
        )

    assert client.calls == []


@pytest.mark.parametrize("declared_length", [9, 8])
def test_s3_read_enforces_declared_and_streamed_byte_limits(declared_length: int) -> None:
    payload = b"123456789"
    client = _S3ReadClient(payload, hashlib.sha256(payload).hexdigest())
    client.content_length = declared_length

    with pytest.raises(SecurityError, match="exceeds its byte limit"):
        _s3_store(client).read_bytes(
            "s3://crisisweave-evidence/tenant-data/v1/evidence?versionId=v1",
            8,
        )

    assert client.bodies[0].closed


def test_s3_materialize_streams_exact_version_and_verifies_output(tmp_path: Path) -> None:
    payload = b"bounded worker input"
    digest = hashlib.sha256(payload).hexdigest()
    client = _S3ReadClient(payload, digest)
    store = _s3_store(client)
    reference = "s3://crisisweave-evidence/tenant-data/v1/input.pdf?versionId=job-v4"
    target = tmp_path / "job" / "input.pdf"

    store.materialize(
        reference,
        target,
        max_bytes=len(payload),
        expected_sha256=digest,
    )

    assert target.read_bytes() == payload
    assert client.calls == [
        {
            "Bucket": "crisisweave-evidence",
            "Key": "tenant-data/v1/input.pdf",
            "VersionId": "job-v4",
        }
    ]
    assert client.bodies[0].closed


def test_s3_materialize_removes_partial_output_when_stream_exceeds_limit(
    tmp_path: Path,
) -> None:
    expected_payload = b"safe"
    digest = hashlib.sha256(expected_payload).hexdigest()
    client = _S3ReadClient(expected_payload + b"!", digest)
    client.content_length = len(expected_payload)
    store = _s3_store(client)
    target = tmp_path / "job" / "input.pdf"

    with pytest.raises(SecurityError, match="exceeds its byte limit"):
        store.materialize(
            "s3://crisisweave-evidence/tenant-data/v1/input.pdf?versionId=job-v5",
            target,
            max_bytes=len(expected_payload),
            expected_sha256=digest,
        )

    assert not target.exists()
    assert client.bodies[0].closed


def test_s3_materialize_preflight_failure_closes_body_without_creating_target(
    tmp_path: Path,
) -> None:
    payload = b"unexpected object"
    digest = hashlib.sha256(payload).hexdigest()
    client = _S3ReadClient(payload, "0" * 64)
    store = _s3_store(client)
    target = tmp_path / "job" / "input.pdf"

    with pytest.raises(SecurityError, match="size or integrity"):
        store.materialize(
            "s3://crisisweave-evidence/tenant-data/v1/input.pdf?versionId=job-v6",
            target,
            max_bytes=len(payload),
            expected_sha256=digest,
        )

    assert not target.exists()
    assert client.bodies[0].closed


def test_s3_materialize_removes_digest_mismatched_output(tmp_path: Path) -> None:
    payload = b"tampered stream"
    expected_digest = hashlib.sha256(b"trusted stream!").hexdigest()
    client = _S3ReadClient(payload, expected_digest)
    store = _s3_store(client)
    target = tmp_path / "job" / "input.pdf"

    with pytest.raises(SecurityError, match="failed integrity"):
        store.materialize(
            "s3://crisisweave-evidence/tenant-data/v1/input.pdf?versionId=job-v7",
            target,
            max_bytes=len(payload),
            expected_sha256=expected_digest,
        )

    assert not target.exists()
    assert client.bodies[0].closed


@pytest.mark.parametrize(
    ("max_bytes", "digest"),
    [(0, "a" * 64), (1024, "invalid")],
)
def test_s3_materialize_rejects_invalid_validation_parameters_before_network_io(
    tmp_path: Path,
    max_bytes: int,
    digest: str,
) -> None:
    client = _S3ReadClient(b"unused", hashlib.sha256(b"unused").hexdigest())

    with pytest.raises(SecurityError, match="parameters are invalid"):
        _s3_store(client).materialize(
            "s3://crisisweave-evidence/tenant-data/v1/input.pdf?versionId=job-v8",
            tmp_path / "job" / "input.pdf",
            max_bytes=max_bytes,
            expected_sha256=digest,
        )

    assert client.calls == []


class _S3AdministrativeClient:
    def __init__(self, *, versioning_status: str | None = "Enabled", fail: bool = False) -> None:
        self.versioning_status = versioning_status
        self.fail = fail
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def delete_object(self, **kwargs: Any) -> None:
        self.calls.append(("delete_object", kwargs))

    def head_bucket(self, **kwargs: Any) -> None:
        self.calls.append(("head_bucket", kwargs))
        if self.fail:
            raise RuntimeError("S3 is unavailable")

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append(("get_bucket_versioning", kwargs))
        return {"Status": self.versioning_status} if self.versioning_status else {}

    def close(self) -> None:
        self.calls.append(("close", {}))


def test_s3_delete_targets_only_the_referenced_version() -> None:
    client = _S3AdministrativeClient()
    store = _s3_store(client)

    store.delete("s3://crisisweave-evidence/tenant-data/v1/evidence.pdf?versionId=deletable-v2")

    assert client.calls == [
        (
            "delete_object",
            {
                "Bucket": "crisisweave-evidence",
                "Key": "tenant-data/v1/evidence.pdf",
                "VersionId": "deletable-v2",
            },
        )
    ]


@pytest.mark.parametrize(
    ("versioning_status", "fail", "expected"),
    [
        ("Enabled", False, True),
        ("Suspended", False, False),
        (None, False, False),
        ("Enabled", True, False),
    ],
)
def test_s3_health_requires_reachable_bucket_with_versioning_enabled(
    versioning_status: str | None,
    fail: bool,
    expected: bool,
) -> None:
    client = _S3AdministrativeClient(versioning_status=versioning_status, fail=fail)
    store = _s3_store(client)

    assert store.healthcheck() is expected
    if fail:
        assert [name for name, _kwargs in client.calls] == ["head_bucket"]
    else:
        assert [name for name, _kwargs in client.calls] == [
            "head_bucket",
            "get_bucket_versioning",
        ]


def test_s3_close_releases_client_resources() -> None:
    client = _S3AdministrativeClient()

    _s3_store(client).close()

    assert client.calls == [("close", {})]


@pytest.mark.parametrize(
    "reference",
    [
        "s3://other-bucket/tenant-data/v1/image.jpg?versionId=v-123",
        "s3://crisisweave-evidence/outside/image.jpg?versionId=v-123",
        "s3://crisisweave-evidence/tenant-data/v1/image.jpg",
        "s3://crisisweave-evidence/tenant-data/v1/image.jpg?versionId=",
        "s3://user@crisisweave-evidence/tenant-data/v1/image.jpg?versionId=v-123",
    ],
)
def test_s3_reference_parser_rejects_ambiguous_or_cross_namespace_refs(
    reference: str,
) -> None:
    with pytest.raises(SecurityError):
        _s3_store(object())._parse_reference(reference)  # noqa: SLF001


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]], columns: tuple[str, ...] = ()) -> None:
        self.rows = iter(rows)
        self.description = [SimpleNamespace(name=name) for name in columns]

    def fetchone(self) -> tuple[Any, ...] | None:
        return next(self.rows, None)


class _AnalyticsConnection:
    def __init__(self) -> None:
        self.executions: list[tuple[str, list[Any] | None]] = []

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def execute(self, sql: str, parameters: list[Any] | None = None) -> _Cursor:
        self.executions.append((sql, parameters))
        if "set_config" in sql:
            return _Cursor([])
        return _Cursor([(3,)], ("event_count",))


class _Pool:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    @contextmanager
    def connection(self) -> Iterator[Any]:
        yield self._connection


def test_postgres_analytics_injects_bound_tenant_and_ready_filters() -> None:
    connection = _AnalyticsConnection()
    store = object.__new__(PostgresMetadataStore)
    store._pool = _Pool(connection)  # noqa: SLF001
    store._psycopg = SimpleNamespace(Error=Exception)  # noqa: SLF001
    store._analytics_timeout_seconds = 2.0  # noqa: SLF001
    store._max_analytics_result_bytes = 4096  # noqa: SLF001
    store._max_analytics_cell_bytes = 1024  # noqa: SLF001
    tenant_id = "a" * 32

    _safe_sql, rows = store.execute_safe_analytics(
        tenant_id,
        "SELECT COUNT(event_id) AS event_count FROM authorized_storm_events",
    )

    execution_sql, parameters = connection.executions[1]
    assert rows == [{"event_count": 3}]
    assert "crisisweave.storm_events" in execution_sql
    assert "crisisweave.documents" in execution_sql
    assert execution_sql.count("%s") == 2
    assert tenant_id not in execution_sql
    assert parameters == [tenant_id, tenant_id]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT ? FROM authorized_storm_events",
        "SELECT $1 FROM authorized_storm_events",
    ],
)
def test_analytics_policy_rejects_user_parameters(sql: str) -> None:
    with pytest.raises(SecurityError, match="parameters"):
        validate_analytics_sql(sql)


class _LockConnection:
    def __init__(self, acquired: bool = True) -> None:
        self.executions: list[tuple[str, list[int]]] = []
        self.acquired = acquired

    def execute(self, sql: str, parameters: list[int]) -> _Cursor:
        self.executions.append((sql, parameters))
        return _Cursor([(self.acquired,)])


def test_postgres_tenant_lock_is_parameterized_and_released() -> None:
    connection = _LockConnection()
    store = object.__new__(PostgresMetadataStore)
    store._pool = _Pool(connection)  # noqa: SLF001
    store._lock_timeout_seconds = 1.0  # noqa: SLF001

    with store.tenant_lock("f" * 32):
        pass

    assert [item[0] for item in connection.executions] == [
        "SELECT pg_try_advisory_lock(%s)",
        "SELECT pg_advisory_unlock(%s)",
    ]
    assert connection.executions[0][1] == connection.executions[1][1]


def test_postgres_try_tenant_lock_does_not_release_unowned_lock() -> None:
    connection = _LockConnection(acquired=False)
    store = object.__new__(PostgresMetadataStore)
    store._pool = _Pool(connection)  # noqa: SLF001

    with store.try_tenant_lock("f" * 32) as acquired:
        assert not acquired

    assert [item[0] for item in connection.executions] == ["SELECT pg_try_advisory_lock(%s)"]


class _BusyReconcileStore:
    def __init__(self, document: Document) -> None:
        self.document = document
        self.get_called = False

    def list_documents_by_status(self, _statuses: tuple[DocumentStatus, ...]) -> list[Document]:
        return [self.document]

    @contextmanager
    def try_tenant_lock(self, _tenant_id: str) -> Iterator[bool]:
        yield False

    def get_document(self, _tenant_id: str, _document_id: str) -> Document | None:
        self.get_called = True
        return self.document


def test_reconcile_skips_processing_document_owned_by_live_worker() -> None:
    tenant_id = "b" * 32
    document = Document(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        filename="active.pdf",
        media_type="application/pdf",
        sha256="c" * 64,
        size_bytes=10,
        status=DocumentStatus.PROCESSING,
    )
    store = _BusyReconcileStore(document)
    service = object.__new__(IngestionService)
    service.store = store
    service._tenant_locks = (threading.RLock(),)

    service.reconcile()

    assert not store.get_called


class _RemoteObjects:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def put_original(self, _source: Path, *, tenant_id: str, sha256: str, suffix: str) -> str:
        return (
            f"s3://crisisweave-evidence/tenants/{tenant_id}/originals/"
            f"{sha256}{suffix}?versionId=original-v1"
        )

    def put_artifact(
        self,
        _source: Path,
        *,
        tenant_id: str,
        document_id: str,
        filename: str,
    ) -> str:
        return (
            f"s3://crisisweave-evidence/tenants/{tenant_id}/{document_id}/{filename}"
            "?versionId=artifact-v1"
        )

    def delete(self, reference: str) -> None:
        self.deleted.append(reference)


class _VisualExtractor:
    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root

    def extract(
        self,
        _path: Path,
        *,
        tenant_id: str,
        document_id: str,
        source_name: str,
        source_uri: str | None,
        **_kwargs: Any,
    ) -> ExtractionResult:
        artifact = self.artifact_root / document_id / "frame.jpg"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"bounded visual")
        chunk = Chunk(
            id=str(uuid.uuid5(uuid.UUID(document_id), "chunk:0")),
            tenant_id=tenant_id,
            document_id=document_id,
            source_name=source_name,
            source_uri=source_uri,
            modality=Modality.IMAGE,
            text="Satellite image evidence",
            artifact_path=str(artifact),
            regions=[
                ImageBoundingBoxRegion(
                    bbox=NormalizedBoundingBox(x_min=0, y_min=0, x_max=1, y_max=1),
                    source=RegionSource.DERIVED_PROVENANCE,
                )
            ],
        )
        return ExtractionResult(chunks=[chunk])


class _VisualEmbedder:
    def embed_visual_chunk(self, chunk: Chunk) -> list[float]:
        assert chunk.artifact_path and Path(chunk.artifact_path).is_file()
        return [0.25, 0.75]


class _Index:
    def __init__(self) -> None:
        self.embedder = _VisualEmbedder()
        self.indexed: list[Chunk] = []

    def delete_document(self, _tenant_id: str, _document_id: str) -> None:
        return

    def index(
        self,
        chunks: list[Chunk],
        *,
        deadline: float,
        visual_vectors: dict[str, list[float]] | None,
    ) -> None:
        del deadline
        assert visual_vectors and next(iter(visual_vectors.values())) == [0.25, 0.75]
        self.indexed = list(chunks)


def test_ingestion_persists_exact_object_refs_and_deletes_them(
    settings: Any, tmp_path: Path
) -> None:
    configured = settings.model_copy(
        update={
            "object_store_backend": "s3",
            "s3_bucket": "crisisweave-evidence",
            "isolate_parsers": False,
            "max_derived_bytes_per_document": 1024 * 1024,
            "min_free_disk_bytes": 1024 * 1024,
        }
    )
    configured.ensure_directories()
    metadata = MetadataStore(configured.database_path)
    objects = _RemoteObjects()
    index = _Index()
    service = IngestionService(
        configured,
        metadata,
        index,  # type: ignore[arg-type]
        _VisualExtractor(configured.artifact_dir),  # type: ignore[arg-type]
        objects,  # type: ignore[arg-type]
    )
    upload = tmp_path / "evidence.png"
    upload.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    tenant_id = "a" * 32

    result = service.ingest_path(upload, tenant_id=tenant_id, filename="evidence.png")

    assert result.document.object_ref and "versionId=original-v1" in result.document.object_ref
    assert len(index.indexed) == 1
    artifact_reference = index.indexed[0].artifact_path
    assert artifact_reference and "versionId=artifact-v1" in artifact_reference
    assert metadata.artifact_references(tenant_id, result.document.id) == [artifact_reference]
    assert not (configured.artifact_dir / result.document.id).exists()

    assert service.delete(tenant_id, result.document.id)
    assert set(objects.deleted) == {result.document.object_ref, artifact_reference}
    metadata.close()
