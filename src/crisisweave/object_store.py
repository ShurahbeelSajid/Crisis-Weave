"""Immutable local and versioned S3-compatible object persistence."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, unquote, urlparse

from crisisweave.config import Settings
from crisisweave.security import SecurityError, sha256_file


class ObjectStore(Protocol):
    def put_original(self, source: Path, *, tenant_id: str, sha256: str, suffix: str) -> str: ...
    def put_artifact(
        self, source: Path, *, tenant_id: str, document_id: str, filename: str
    ) -> str: ...
    def put_job_input(
        self,
        source: Path,
        *,
        tenant_id: str,
        job_id: str,
        sha256: str,
        suffix: str,
    ) -> str: ...
    def materialize(
        self,
        reference: str,
        target: Path,
        *,
        max_bytes: int,
        expected_sha256: str,
    ) -> None: ...
    def read_bytes(self, reference: str, max_bytes: int) -> bytes: ...
    def delete(self, reference: str) -> None: ...
    def healthcheck(self) -> bool: ...
    def close(self) -> None: ...


def _bounded_file_bytes(path: Path, max_bytes: int) -> bytes:
    if max_bytes <= 0:
        raise SecurityError("Object read limit is invalid")
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_size > max_bytes:
        raise SecurityError("Object is unavailable or exceeds its byte limit")
    with resolved.open("rb") as handle:
        payload = handle.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise SecurityError("Object exceeds its byte limit")
    return payload


class LocalObjectStore:
    """Content-addressed immutable files for development and single-host deployments."""

    def __init__(self, object_root: Path, artifact_root: Path) -> None:
        self.object_root = object_root.resolve()
        self.artifact_root = artifact_root.resolve()
        self.object_root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _publish(source: Path, target: Path, expected_sha256: str) -> str:
        source = source.resolve(strict=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_file(target) != expected_sha256:
                raise SecurityError("Immutable object key contains different content")
            return str(target.resolve())
        temporary = target.parent / f".{target.name}.{uuid.uuid4()}.tmp"
        try:
            with source.open("rb") as input_handle, temporary.open("xb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            if sha256_file(temporary) != expected_sha256:
                raise SecurityError("Object changed during publication")
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or sha256_file(target) != expected_sha256:
                    raise SecurityError(
                        "Immutable object publication raced with different content"
                    ) from None
        finally:
            temporary.unlink(missing_ok=True)
        return str(target.resolve(strict=True))

    def put_original(self, source: Path, *, tenant_id: str, sha256: str, suffix: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        if not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise SecurityError("Object digest is invalid")
        if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
            raise SecurityError("Object suffix is invalid")
        target = (
            self.object_root
            / "tenants"
            / tenant_id
            / "originals"
            / sha256[:2]
            / f"{sha256}{suffix}"
        )
        return self._publish(source, target, sha256)

    def put_artifact(self, source: Path, *, tenant_id: str, document_id: str, filename: str) -> str:
        if (
            not re.fullmatch(r"[a-f0-9]{32}", tenant_id)
            or not re.fullmatch(r"[a-f0-9-]{36}", document_id)
            or Path(filename).name != filename
            or not filename
        ):
            raise SecurityError("Artifact lineage is invalid")
        digest = sha256_file(source)
        target = self.artifact_root / document_id / filename
        if source.resolve(strict=True) == target.resolve():
            return str(target.resolve())
        return self._publish(source, target, digest)

    def put_job_input(
        self,
        source: Path,
        *,
        tenant_id: str,
        job_id: str,
        sha256: str,
        suffix: str,
    ) -> str:
        if (
            not re.fullmatch(r"[a-f0-9]{32}", tenant_id)
            or not re.fullmatch(r"[a-f0-9-]{36}", job_id)
            or not re.fullmatch(r"[a-f0-9]{64}", sha256)
            or not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix)
        ):
            raise SecurityError("Job object lineage is invalid")
        target = self.object_root / "jobs" / tenant_id / job_id / f"{sha256}{suffix}"
        return self._publish(source, target, sha256)

    def _validated_path(self, reference: str) -> Path:
        unresolved = Path(reference)
        resolved = unresolved.resolve(strict=True)
        if unresolved.is_symlink() or not any(
            resolved.is_relative_to(root) for root in (self.object_root, self.artifact_root)
        ):
            raise SecurityError("Object reference escaped its storage root")
        return resolved

    def read_bytes(self, reference: str, max_bytes: int) -> bytes:
        return _bounded_file_bytes(self._validated_path(reference), max_bytes)

    def materialize(
        self,
        reference: str,
        target: Path,
        *,
        max_bytes: int,
        expected_sha256: str,
    ) -> None:
        source = self._validated_path(reference)
        if source.stat().st_size > max_bytes or sha256_file(source) != expected_sha256:
            raise SecurityError("Job object failed size or integrity validation")
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_handle, target.open("xb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        if target.stat().st_size > max_bytes or sha256_file(target) != expected_sha256:
            target.unlink(missing_ok=True)
            raise SecurityError("Materialized job object failed integrity validation")

    def delete(self, reference: str) -> None:
        try:
            path = self._validated_path(reference)
        except FileNotFoundError:
            return
        path.unlink(missing_ok=True)

    def healthcheck(self) -> bool:
        return self.object_root.is_dir() and self.artifact_root.is_dir()

    def close(self) -> None:
        return


class S3ObjectStore:
    """S3 adapter requiring bucket versioning and exact version references."""

    def __init__(self, settings: Settings) -> None:
        import boto3
        from botocore.config import Config

        if not settings.s3_bucket:
            raise ValueError("s3_bucket is required")
        self.bucket = settings.s3_bucket
        self.prefix = settings.s3_prefix.strip("/")
        self._sse = settings.s3_server_side_encryption
        self._kms_key_id = settings.s3_kms_key_id
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url or None,
            region_name=settings.s3_region or None,
            config=Config(
                connect_timeout=settings.object_store_timeout_seconds,
                read_timeout=settings.object_store_timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
                s3={"addressing_style": settings.s3_addressing_style},
            ),
        )

    def _key(self, relative: str) -> str:
        return f"{self.prefix}/{relative}" if self.prefix else relative

    def _reference(self, key: str, version_id: str) -> str:
        return f"s3://{self.bucket}/{quote(key, safe='/')}?versionId={quote(version_id, safe='')}"

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        parsed = urlparse(reference)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if (
            parsed.scheme != "s3"
            or parsed.netloc != self.bucket
            or parsed.username
            or parsed.password
            or parsed.fragment
            or set(query) != {"versionId"}
            or len(query["versionId"]) != 1
        ):
            raise SecurityError("Object reference is malformed")
        key = unquote(parsed.path.lstrip("/"))
        version_id = query["versionId"][0]
        required_prefix = f"{self.prefix}/" if self.prefix else ""
        if (
            not key
            or not version_id
            or not key.startswith(required_prefix)
            or ".." in Path(key).parts
            or any(ord(character) < 32 for character in key + version_id)
        ):
            raise SecurityError("Object reference is outside the configured namespace")
        return key, version_id

    def _put(self, source: Path, key: str, digest: str) -> str:
        from botocore.exceptions import ClientError

        source = source.resolve(strict=True)
        kwargs: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Metadata": {"sha256": digest},
            "ServerSideEncryption": self._sse,
            "IfNoneMatch": "*",
        }
        if self._sse == "aws:kms" and self._kms_key_id:
            kwargs["SSEKMSKeyId"] = self._kms_key_id.get_secret_value()
        try:
            with source.open("rb") as handle:
                response = self._client.put_object(
                    Body=handle,
                    ContentLength=source.stat().st_size,
                    ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
                    **kwargs,
                )
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = exc.response.get("Error", {}).get("Code")
            if status != 412 and code not in {"PreconditionFailed", "ConditionalRequestConflict"}:
                raise
            response = self._client.head_object(Bucket=self.bucket, Key=key)
        version_id = response.get("VersionId")
        metadata = response.get("Metadata", {})
        if not version_id or version_id == "null":
            raise SecurityError("S3 bucket did not return an immutable version identifier")
        if metadata and metadata.get("sha256") != digest:
            raise SecurityError("Immutable S3 key contains different content")
        head = self._client.head_object(Bucket=self.bucket, Key=key, VersionId=version_id)
        if head.get("Metadata", {}).get("sha256") != digest:
            raise SecurityError("S3 object integrity metadata is missing or incorrect")
        return self._reference(key, str(version_id))

    def put_original(self, source: Path, *, tenant_id: str, sha256: str, suffix: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        if not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise SecurityError("Object digest is invalid")
        if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
            raise SecurityError("Object suffix is invalid")
        key = self._key(f"v1/tenants/{tenant_id}/originals/{sha256[:2]}/{sha256}{suffix}")
        return self._put(source, key, sha256)

    def put_artifact(self, source: Path, *, tenant_id: str, document_id: str, filename: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", tenant_id):
            raise SecurityError("Tenant identifier is invalid")
        if not re.fullmatch(r"[a-f0-9-]{36}", document_id) or Path(filename).name != filename:
            raise SecurityError("Artifact lineage is invalid")
        digest = sha256_file(source)
        suffix = Path(filename).suffix.lower()
        key = self._key(f"v1/tenants/{tenant_id}/documents/{document_id}/{digest}{suffix}")
        return self._put(source, key, digest)

    def put_job_input(
        self,
        source: Path,
        *,
        tenant_id: str,
        job_id: str,
        sha256: str,
        suffix: str,
    ) -> str:
        if (
            not re.fullmatch(r"[a-f0-9]{32}", tenant_id)
            or not re.fullmatch(r"[a-f0-9-]{36}", job_id)
            or not re.fullmatch(r"[a-f0-9]{64}", sha256)
            or not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix)
        ):
            raise SecurityError("Job object lineage is invalid")
        key = self._key(f"v1/tenants/{tenant_id}/jobs/{job_id}/{sha256}{suffix}")
        return self._put(source, key, sha256)

    def read_bytes(self, reference: str, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            raise SecurityError("Object read limit is invalid")
        key, version_id = self._parse_reference(reference)
        response = self._client.get_object(Bucket=self.bucket, Key=key, VersionId=version_id)
        body = response["Body"]
        try:
            if int(response.get("ContentLength", max_bytes + 1)) > max_bytes:
                raise SecurityError("Object exceeds its byte limit")
            payload = bytes(body.read(max_bytes + 1))
            if len(payload) > max_bytes:
                raise SecurityError("Object exceeds its byte limit")
            expected = response.get("Metadata", {}).get("sha256")
            if not expected or not hmac.compare_digest(
                hashlib.sha256(payload).hexdigest(), expected
            ):
                raise SecurityError("Object integrity verification failed")
            return payload
        finally:
            body.close()

    def materialize(
        self,
        reference: str,
        target: Path,
        *,
        max_bytes: int,
        expected_sha256: str,
    ) -> None:
        if max_bytes <= 0 or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise SecurityError("Job object validation parameters are invalid")
        key, version_id = self._parse_reference(reference)
        response = self._client.get_object(Bucket=self.bucket, Key=key, VersionId=version_id)
        body = response["Body"]
        expected_length = int(response.get("ContentLength", max_bytes + 1))
        metadata_digest = response.get("Metadata", {}).get("sha256")
        if expected_length > max_bytes or metadata_digest != expected_sha256:
            body.close()
            raise SecurityError("Job object failed size or integrity validation")
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        written = 0
        try:
            with target.open("xb") as output:
                while block := body.read(min(1024 * 1024, max_bytes - written + 1)):
                    written += len(block)
                    if written > max_bytes:
                        raise SecurityError("Job object exceeds its byte limit")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if written != expected_length or digest.hexdigest() != expected_sha256:
                raise SecurityError("Materialized job object failed integrity validation")
        except Exception:
            target.unlink(missing_ok=True)
            raise
        finally:
            body.close()

    def delete(self, reference: str) -> None:
        key, version_id = self._parse_reference(reference)
        self._client.delete_object(Bucket=self.bucket, Key=key, VersionId=version_id)

    def healthcheck(self) -> bool:
        try:
            self._client.head_bucket(Bucket=self.bucket)
            versioning = self._client.get_bucket_versioning(Bucket=self.bucket)
            return bool(versioning.get("Status") == "Enabled")
        except Exception:
            return False

    def close(self) -> None:
        self._client.close()


def build_object_store(settings: Settings) -> ObjectStore:
    if settings.object_store_backend == "s3":
        return S3ObjectStore(settings)
    return LocalObjectStore(settings.object_dir, settings.artifact_dir)
