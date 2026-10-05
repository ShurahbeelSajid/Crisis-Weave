"""FastAPI security boundary for CrisisWeave."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import structlog
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from crisisweave import __version__
from crisisweave.auth import (
    AuthenticationError,
    IdentityType,
    Permission,
    Principal,
    TokenVerifier,
    build_authenticator,
    require_permission,
)
from crisisweave.bootstrap import build_container
from crisisweave.config import Settings, get_settings
from crisisweave.governance import (
    OversightService,
    build_governance_repository,
)
from crisisweave.job_store import EnqueueJobResult, IngestionJob, JobQueueFullError
from crisisweave.jobs import (
    JobNotFoundError,
    JobStateConflictError,
    create_job_service,
)
from crisisweave.models import (
    DeleteDocumentsResult,
    Document,
    HealthResponse,
    IdentityAuditEvent,
    IngestionResult,
    QueryRequest,
    QueryResponse,
    ReviewDecisionRequest,
    ReviewRecord,
    ReviewStatus,
    ReviewSubmission,
)
from crisisweave.observability import (
    HTTP_DURATION,
    HTTP_REQUESTS,
    INGESTIONS,
    QUERIES,
    configure_logging,
    instrument_fastapi_app,
    observe_root_operation,
    record_query_end_to_end_completion,
)
from crisisweave.security import SecurityError, malware_scanner_healthcheck, safe_filename

logger = structlog.get_logger()


class ReadinessProbe:
    """Single-flight, briefly cached dependency checks for an unauthenticated endpoint."""

    def __init__(self, container: Any, ttl_seconds: float = 5.0) -> None:
        self.container = container
        self.ttl_seconds = ttl_seconds
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[dict[str, str]] | None = None
        self._cached: dict[str, str] | None = None
        self._expires_at = 0.0

    def _run(self) -> dict[str, str]:
        database_name = getattr(self.container.settings, "database_backend", "duckdb")
        callbacks = [
            (database_name, self.container.store.healthcheck),
            ("qdrant", self.container.index.healthcheck),
        ]
        if getattr(self.container.settings, "ingestion_worker_enabled", True):
            callbacks.extend(
                [
                    (
                        "malware_scanner",
                        lambda: malware_scanner_healthcheck(self.container.settings),
                    ),
                    ("parser_service", self.container.ingestion.parser_healthcheck),
                ]
            )
        object_store = getattr(self.container, "object_store", None)
        if object_store is not None:
            callbacks.append(("object_store", object_store.healthcheck))
        checks: dict[str, str] = {}
        for name, callback in callbacks:
            try:
                checks[name] = "ok" if callback() else "failed"
            except Exception:
                checks[name] = "failed"
        return checks

    async def check(self) -> dict[str, str]:
        now = time.monotonic()
        async with self._lock:
            if self._cached is not None and now < self._expires_at:
                return dict(self._cached)
            if self._task is None:
                self._task = asyncio.create_task(asyncio.to_thread(self._run))
            task = self._task
            if task is None:
                raise RuntimeError("Readiness single-flight task was not created")
        result = await asyncio.shield(task)
        async with self._lock:
            if self._task is task:
                self._cached = dict(result)
                self._expires_at = time.monotonic() + self.ttl_seconds
                self._task = None
        return result

    async def drain(self) -> None:
        async with self._lock:
            task = self._task
        if task is not None:
            await asyncio.shield(task)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", "")
        if not request_id.isascii() or not 1 <= len(request_id) <= 80:
            request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path in {"/docs", "/openapi.json"}:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src https://cdn.jsdelivr.net; "
                "style-src https://cdn.jsdelivr.net 'unsafe-inline'; img-src data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        response.headers["Cache-Control"] = "no-store"
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        duration = time.perf_counter() - started
        HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
        HTTP_DURATION.labels(request.method, route_path).observe(duration)
        if request.url.path.startswith("/v1/"):
            repository = getattr(request.app.state, "governance", None)
            principal = getattr(request.state, "principal", None)
            if repository is not None:
                if isinstance(principal, Principal):
                    tenant_id = principal.tenant_id
                    subject_id = principal.subject_id
                    identity_type = principal.identity_type.value
                    auth_method = principal.auth_method
                else:
                    tenant_id = None
                    subject_id = "anonymous"
                    identity_type = "unknown"
                    auth_method = "unknown"
                denied = response.status_code in {401, 403}
                event_type = (
                    "authentication.denied"
                    if response.status_code == 401
                    else "authorization.denied"
                    if response.status_code == 403
                    else "request.completed"
                )
                custom_event_type = getattr(request.state, "audit_event_type", None)
                if response.status_code < 400 and isinstance(custom_event_type, str):
                    event_type = custom_event_type[:80]
                outcome = (
                    "denied" if denied else "success" if response.status_code < 400 else "failed"
                )
                details = {
                    "method": request.method,
                    "route": str(route_path)[:500],
                    "status_code": str(response.status_code),
                }
                permission = getattr(request.state, "authorization_permission", None)
                if isinstance(permission, str):
                    details["permission"] = permission
                custom_details = getattr(request.state, "audit_details", None)
                if isinstance(custom_details, dict):
                    for key, value in tuple(custom_details.items())[:10]:
                        if isinstance(key, str) and isinstance(value, str):
                            details[key[:80]] = value[:500]
                try:
                    await asyncio.to_thread(
                        repository.record_identity_event,
                        tenant_id=tenant_id,
                        subject_id=subject_id,
                        identity_type=identity_type,
                        auth_method=auth_method,
                        event_type=event_type,
                        outcome=outcome,
                        request_id=request_id,
                        details=details,
                    )
                except Exception as exc:
                    logger.error(
                        "identity_audit_persistence_failed",
                        request_id=request_id,
                        error_type=type(exc).__name__,
                    )
                    runtime_settings = getattr(request.app.state, "runtime_settings", None)
                    if getattr(runtime_settings, "app_env", None) == "production":
                        return JSONResponse(
                            status_code=503,
                            content={"detail": "Identity audit persistence unavailable"},
                            headers={"X-Request-ID": request_id, "Cache-Control": "no-store"},
                        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        requests: int,
        window_seconds: int,
        credentials: tuple[tuple[str, str], ...],
        max_identities: int,
    ) -> None:
        super().__init__(app)
        self.limit = requests
        self.window = window_seconds
        self.credentials = credentials
        self.max_identities = max_identities
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path.startswith("/health/"):
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        principal = getattr(request.state, "principal", None)
        authenticator = getattr(request.app.state, "authenticator", None)
        if not isinstance(principal, Principal) and authenticator is not None:
            try:
                principal = await asyncio.to_thread(
                    authenticator.authenticate,
                    authorization=request.headers.get("Authorization"),
                    api_key=request.headers.get("X-API-Key"),
                )
                request.state.principal = principal
            except AuthenticationError:
                principal = None
        if not isinstance(principal, Principal):
            from crisisweave.auth import resolve_principal

            principal = resolve_principal(request.headers.get("X-API-Key"), self.credentials)
        stable_identity = principal.tenant_id if principal else f"ip:{client}"
        identity = hashlib.sha256(stable_identity.encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            if identity not in self._events and len(self._events) >= self.max_identities:
                stale = [
                    key
                    for key, values in self._events.items()
                    if not values or values[-1] <= now - self.window
                ]
                for key in stale:
                    self._events.pop(key, None)
                if len(self._events) >= self.max_identities:
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Rate limiter identity capacity exceeded"},
                        headers={
                            "Retry-After": str(self.window),
                            "Connection": "close",
                        },
                    )
            events = self._events[identity]
            while events and events[0] <= now - self.window:
                events.popleft()
            if len(events) >= self.limit:
                retry_after = max(1, int(self.window - (now - events[0])))
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(retry_after), "Connection": "close"},
                )
            events.append(now)
        return await call_next(request)


class _RequestBodyTooLarge(Exception):
    pass


class _RequestBodyTimedOut(Exception):
    pass


class QueryEndToEndMiddleware:
    """Measure query receipt through the final response body without content labels."""

    def __init__(self, app: ASGIApp, *, compute_cost_per_hour: float = 0.0) -> None:
        self.app = app
        self.compute_cost_per_hour = compute_cost_per_hour

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/v1/query"
        ):
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        response_status: int | None = None
        response_completed = False
        with observe_root_operation(
            "query",
            uuid.uuid4().hex,
            compute_cost_per_hour=self.compute_cost_per_hour,
        ) as root_operation:

            async def measured_send(message: Message) -> None:
                nonlocal response_completed, response_status
                await send(message)
                if message.get("type") == "http.response.start":
                    candidate = message.get("status")
                    response_status = candidate if isinstance(candidate, int) else None
                elif message.get("type") == "http.response.body" and not message.get(
                    "more_body", False
                ):
                    duration = time.perf_counter() - started
                    if response_status is None:
                        raise RuntimeError("query response completed without an HTTP status")
                    response_completed = True
                    try:
                        record_query_end_to_end_completion(
                            response_status,
                            duration,
                            completed=True,
                        )
                    except Exception as exc:
                        logger.warning(
                            "query_completion_metric_failed",
                            error_type=type(exc).__name__,
                        )
                    try:
                        root_operation.complete(f"{response_status // 100}xx", duration)
                    except Exception as exc:
                        logger.warning(
                            "query_completion_span_failed",
                            error_type=type(exc).__name__,
                        )

            try:
                await self.app(scope, receive, measured_send)
            finally:
                if not response_completed:
                    duration = time.perf_counter() - started
                    try:
                        record_query_end_to_end_completion(
                            response_status,
                            duration,
                            completed=False,
                        )
                    except Exception as exc:
                        logger.warning(
                            "query_completion_metric_failed",
                            error_type=type(exc).__name__,
                        )
                    try:
                        root_operation.complete("aborted", duration)
                    except Exception as exc:
                        logger.warning(
                            "query_completion_span_failed",
                            error_type=type(exc).__name__,
                        )


class RequestBoundaryMiddleware:
    """Authenticate, reserve capacity, and bound request bodies before parsing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_upload_body_bytes: int,
        max_query_body_bytes: int,
        queue_timeout_seconds: float,
        upload_body_timeout_seconds: float,
        query_body_timeout_seconds: float,
        body_chunk_timeout_seconds: float,
        credentials: tuple[tuple[str, str], ...],
        synchronous_ingestion_enabled: bool = True,
    ) -> None:
        self.app = app
        self.max_upload_body_bytes = max_upload_body_bytes
        self.max_query_body_bytes = max_query_body_bytes
        self.queue_timeout_seconds = queue_timeout_seconds
        self.upload_body_timeout_seconds = upload_body_timeout_seconds
        self.query_body_timeout_seconds = query_body_timeout_seconds
        self.body_chunk_timeout_seconds = body_chunk_timeout_seconds
        self.credentials = credentials
        self.synchronous_ingestion_enabled = synchronous_ingestion_enabled

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = scope.get("path")
        review_decision = bool(
            isinstance(path, str) and path.startswith("/v1/reviews/") and path.endswith("/decision")
        )
        await self._handle_bounded_request(
            scope,
            receive,
            send,
            path=path,
            review_decision=review_decision,
        )

    async def _handle_bounded_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        path: object,
        review_decision: bool,
    ) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or (
                path
                not in {
                    "/v1/documents",
                    "/v1/ingestion-jobs",
                    "/v1/query",
                }
                and not review_decision
            )
        ):
            await self.app(scope, receive, send)
            return

        header_values: defaultdict[str, list[str]] = defaultdict(list)
        for key, value in scope.get("headers", []):
            header_values[key.decode("latin-1").lower()].append(value.decode("latin-1"))
        if any(
            len(header_values[name]) > 1
            for name in (
                "content-length",
                "content-type",
                "authorization",
                "x-api-key",
                "transfer-encoding",
            )
        ):
            await JSONResponse(
                status_code=400,
                content={"detail": "Ambiguous headers"},
                headers={"Connection": "close"},
            )(scope, receive, send)
            return
        headers = {name: values[0] for name, values in header_values.items() if values}
        state = scope.setdefault("state", {})
        principal = state.get("principal")
        if not isinstance(principal, Principal):
            authenticator = getattr(scope["app"].state, "authenticator", None)
            if authenticator is not None:
                try:
                    principal = await asyncio.to_thread(
                        authenticator.authenticate,
                        authorization=headers.get("authorization"),
                        api_key=headers.get("x-api-key"),
                    )
                except AuthenticationError:
                    principal = None
            else:
                from crisisweave.auth import resolve_principal

                principal = resolve_principal(headers.get("x-api-key"), self.credentials)
        if not isinstance(principal, Principal):
            await JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing credentials"},
                headers={"Connection": "close", "WWW-Authenticate": "Bearer, ApiKey"},
            )(scope, receive, send)
            return
        state["principal"] = principal
        if path == "/v1/documents" and not self.synchronous_ingestion_enabled:
            await JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "detail": (
                        "Synchronous ingestion is disabled in production; "
                        "submit the upload to /v1/ingestion-jobs"
                    )
                },
                headers={"Connection": "close"},
            )(scope, receive, send)
            return
        is_upload = path in {"/v1/documents", "/v1/ingestion-jobs"}
        max_body_bytes = self.max_upload_body_bytes if is_upload else self.max_query_body_bytes
        body_timeout_seconds = (
            self.upload_body_timeout_seconds if is_upload else self.query_body_timeout_seconds
        )
        if not is_upload:
            media_type = headers.get("content-type", "").partition(";")[0].strip().lower()
            if media_type != "application/json":
                await JSONResponse(
                    status_code=415,
                    content={"detail": "Query requests require application/json"},
                    headers={"Connection": "close"},
                )(scope, receive, send)
                return
        if headers.get("content-length") and headers.get("transfer-encoding"):
            await JSONResponse(
                status_code=400,
                content={"detail": "Content-Length and Transfer-Encoding cannot be combined"},
                headers={"Connection": "close"},
            )(scope, receive, send)
            return
        transfer_encoding = headers.get("transfer-encoding")
        if transfer_encoding and transfer_encoding.strip().lower() != "chunked":
            await JSONResponse(
                status_code=400,
                content={"detail": "Unsupported Transfer-Encoding"},
                headers={"Connection": "close"},
            )(scope, receive, send)
            return
        raw_length = headers.get("content-length")
        content_length = (
            int(raw_length)
            if raw_length is not None and raw_length.isascii() and raw_length.isdecimal()
            else None
        )
        if raw_length is not None and content_length is None:
            content_length = -1
        if content_length is not None and content_length < 0:
            await JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length"},
                headers={"Connection": "close"},
            )(scope, receive, send)
            return
        if content_length is not None and content_length > max_body_bytes:
            await JSONResponse(
                status_code=413,
                content={"detail": "Request body is too large"},
                headers={"Connection": "close"},
            )(scope, receive, send)
            return

        app_state = scope["app"].state
        semaphore = app_state.ingestion_slots if is_upload else app_state.query_slots
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=self.queue_timeout_seconds)
        except TimeoutError:
            await JSONResponse(
                status_code=503,
                content={"detail": "Server capacity is currently exhausted"},
                headers={"Retry-After": "1", "Connection": "close"},
            )(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        slot_name = "ingestion" if is_upload else "query"
        state[f"{slot_name}_slot_held"] = True
        received_bytes = 0
        body_complete = False
        deadline = asyncio.get_running_loop().time() + body_timeout_seconds

        async def bounded_receive() -> Message:
            nonlocal body_complete, received_bytes
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise _RequestBodyTimedOut
            try:
                message = await asyncio.wait_for(
                    receive(), timeout=min(self.body_chunk_timeout_seconds, remaining)
                )
            except TimeoutError as exc:
                raise _RequestBodyTimedOut from exc
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > max_body_bytes:
                    raise _RequestBodyTooLarge
                body_complete = not message.get("more_body", False)
            return message

        async def guarded_send(message: Message) -> None:
            if message.get("type") == "http.response.start" and not body_complete:
                response_headers = list(message.get("headers", []))
                if not any(key.lower() == b"connection" for key, _ in response_headers):
                    response_headers.append((b"connection", b"close"))
                    message = {**message, "headers": response_headers}
            await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except _RequestBodyTooLarge:
            await JSONResponse(
                status_code=413,
                content={"detail": "Request body is too large"},
                headers={"Connection": "close"},
            )(scope, receive, send)
        except _RequestBodyTimedOut:
            await JSONResponse(
                status_code=408,
                content={"detail": "Request body timed out"},
                headers={"Connection": "close"},
            )(scope, receive, send)
        finally:
            if not state.get(f"{slot_name}_slot_owned"):
                semaphore.release()


def _validate_source_uri(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) > 1000:
        raise SecurityError("Source URI is too long")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise SecurityError("Source URI cannot contain whitespace or control characters")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise SecurityError("Source URI is malformed") from exc
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        raise SecurityError("Source URI must be a credential-free HTTPS URL")
    return value


async def _save_bounded_upload(upload: UploadFile, target: Path, max_bytes: int) -> int:
    size = 0
    handle = await _open_exclusive_upload(target)
    try:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise SecurityError(f"Upload exceeds the {max_bytes}-byte limit")
            write = asyncio.create_task(asyncio.to_thread(handle.write, chunk))
            try:
                await asyncio.shield(write)
            except asyncio.CancelledError:
                await write
                raise
    except Exception:
        await asyncio.to_thread(handle.close)
        await asyncio.to_thread(target.unlink, missing_ok=True)
        raise
    finally:
        if not handle.closed:
            await asyncio.to_thread(handle.close)
        await upload.close()
    if size == 0:
        await asyncio.to_thread(target.unlink, missing_ok=True)
        raise SecurityError("Upload is empty")
    return size


async def _open_exclusive_upload(target: Path) -> Any:
    opening = asyncio.create_task(asyncio.to_thread(target.open, "xb"))
    try:
        return await asyncio.shield(opening)
    except asyncio.CancelledError:
        try:
            handle = await opening
        except Exception as exc:
            logger.debug(
                "upload_open_failed_after_cancellation",
                error_type=type(exc).__name__,
            )
        else:
            await asyncio.to_thread(handle.close)
            await asyncio.to_thread(target.unlink, missing_ok=True)
        raise


async def _reserve_disk(ingestion: Any, reservation_bytes: int) -> None:
    """Make a blocking reservation cancellation-safe and release it on cancellation."""
    reservation = asyncio.create_task(asyncio.to_thread(ingestion.reserve_disk, reservation_bytes))
    try:
        await asyncio.shield(reservation)
    except asyncio.CancelledError:
        try:
            await reservation
        except Exception as exc:
            logger.debug(
                "upload_reservation_failed_after_cancellation",
                error_type=type(exc).__name__,
            )
        else:
            ingestion.release_disk(reservation_bytes)
        raise


def create_app(
    settings: Settings | None = None,
    *,
    token_verifier: TokenVerifier | None = None,
) -> FastAPI:
    runtime_settings = settings or get_settings()
    configure_logging(runtime_settings.log_level)
    authenticator = build_authenticator(runtime_settings, token_verifier=token_verifier)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await asyncio.to_thread(build_container, runtime_settings)
        try:
            governance = await asyncio.to_thread(build_governance_repository, runtime_settings)
        except Exception:
            await asyncio.to_thread(container.close)
            raise
        app.state.container = container
        app.state.governance = governance
        app.state.oversight = OversightService(runtime_settings, container.store, governance)
        app.state.query_slots = asyncio.Semaphore(runtime_settings.max_concurrent_queries)
        app.state.ingestion_slots = asyncio.Semaphore(runtime_settings.max_concurrent_ingestions)
        app.state.job_service = create_job_service(
            runtime_settings,
            container.ingestion,
            container.ingestion.object_store,
        )
        app.state.job_stop = asyncio.Event()
        app.state.job_worker = (
            asyncio.create_task(
                app.state.job_service.run(app.state.job_stop, app.state.ingestion_slots),
                name="durable-ingestion-worker",
            )
            if runtime_settings.ingestion_worker_enabled
            else None
        )
        app.state.background_ingestions = set()
        app.state.background_file_cleanups = set()
        app.state.readiness_probe = ReadinessProbe(container)
        logger.info(
            "application_started",
            environment=runtime_settings.app_env,
            version=__version__,
        )
        try:
            yield
        finally:
            app.state.job_stop.set()
            if app.state.job_worker is not None:
                await app.state.job_worker
            await asyncio.to_thread(app.state.job_service.close)
            pending = tuple(app.state.background_ingestions)
            if pending:
                logger.info("draining_background_ingestions", count=len(pending))
                await asyncio.gather(*pending, return_exceptions=True)
            file_cleanups = tuple(app.state.background_file_cleanups)
            if file_cleanups:
                await asyncio.gather(*file_cleanups, return_exceptions=True)
            await app.state.readiness_probe.drain()
            await asyncio.to_thread(governance.close)
            await asyncio.to_thread(container.close)
            logger.info("application_stopped")

    docs_url = "/docs" if runtime_settings.enable_docs else None
    app = FastAPI(
        title="CrisisWeave API",
        version=__version__,
        description="Evidence-first agentic multimodal RAG for disaster intelligence",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url="/openapi.json" if runtime_settings.enable_docs else None,
        lifespan=lifespan,
    )
    app.state.authenticator = authenticator
    app.state.runtime_settings = runtime_settings
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=runtime_settings.cors_origin_values,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=runtime_settings.trusted_host_values)
    app.add_middleware(
        RequestBoundaryMiddleware,
        max_upload_body_bytes=(
            runtime_settings.max_upload_bytes + runtime_settings.max_multipart_overhead_bytes
        ),
        max_query_body_bytes=runtime_settings.max_query_body_bytes,
        queue_timeout_seconds=runtime_settings.queue_timeout_seconds,
        upload_body_timeout_seconds=runtime_settings.upload_body_timeout_seconds,
        query_body_timeout_seconds=runtime_settings.query_body_timeout_seconds,
        body_chunk_timeout_seconds=runtime_settings.body_chunk_timeout_seconds,
        credentials=runtime_settings.api_credentials,
        synchronous_ingestion_enabled=runtime_settings.app_env != "production",
    )
    app.add_middleware(
        RateLimitMiddleware,
        requests=runtime_settings.rate_limit_requests,
        window_seconds=runtime_settings.rate_limit_window_seconds,
        credentials=runtime_settings.api_credentials,
        max_identities=runtime_settings.max_rate_limit_identities,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    # Added last so it is the outermost application middleware and includes auth,
    # rate limiting, serialization, compression, and the final response body.
    app.add_middleware(
        QueryEndToEndMiddleware,
        compute_cost_per_hour=runtime_settings.query_compute_cost_per_hour_usd,
    )

    @app.exception_handler(SecurityError)
    async def security_error_handler(_request: Request, exc: SecurityError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = [
            {"loc": list(item["loc"]), "msg": item["msg"], "type": item["type"]}
            for item in exc.errors()[:20]
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "unhandled_request_error",
            request_id=getattr(request.state, "request_id", None),
            error_type=type(exc).__name__,
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    @app.get("/health/live", response_model=HealthResponse, tags=["health"])
    async def live() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.get("/health/ready", response_model=HealthResponse, tags=["health"])
    async def ready(request: Request) -> HealthResponse:
        checks = await request.app.state.readiness_probe.check()
        if request.app.state.job_worker is not None:
            checks["ingestion_worker"] = "failed" if request.app.state.job_worker.done() else "ok"
        response = HealthResponse(
            status="ok" if all(value == "ok" for value in checks.values()) else "degraded",
            version=__version__,
            checks=checks,
        )
        if response.status != "ok":
            raise HTTPException(status_code=503, detail=response.model_dump(mode="json"))
        return response

    @app.get("/metrics", include_in_schema=False)
    async def metrics(
        x_metrics_key: Annotated[str | None, Header(alias="X-Metrics-Key")] = None,
        x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> Response:
        from crisisweave.auth import resolve_principal

        authorized = False
        bearer_key: str | None = None
        if authorization:
            scheme, separator, candidate = authorization.partition(" ")
            if separator and scheme.lower() == "bearer" and candidate and " " not in candidate:
                bearer_key = candidate
        metric_candidates = [value for value in (x_metrics_key, bearer_key) if value is not None]
        if runtime_settings.metrics_api_key and len(metric_candidates) == 1:
            authorized = hmac.compare_digest(
                metric_candidates[0].encode(),
                runtime_settings.metrics_api_key.get_secret_value().encode(),
            )
        elif not metric_candidates and runtime_settings.app_env != "production":
            authorized = resolve_principal(x_api_key, runtime_settings.api_credentials) is not None
        if not authorized:
            raise HTTPException(status_code=401, detail="Invalid or missing metrics key")
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post(
        "/v1/documents",
        response_model=IngestionResult,
        status_code=status.HTTP_201_CREATED,
        tags=["documents"],
    )
    async def ingest_document(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_WRITE))],
        file: Annotated[UploadFile, File(description="PDF, image, MP4/WebM, CSV, JSON, or text")],
        source_uri: Annotated[str | None, Form()] = None,
    ) -> IngestionResult:
        if runtime_settings.app_env == "production":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Synchronous ingestion is disabled in production; "
                    "submit the upload to /v1/ingestion-jobs"
                ),
            )
        filename = safe_filename(file.filename)
        validated_source_uri = _validate_source_uri(source_uri)
        if not getattr(request.state, "ingestion_slot_held", False):
            raise RuntimeError("Upload capacity boundary was not applied")
        temp_dir = runtime_settings.data_dir / "tmp"
        temp_path = temp_dir / f"{uuid.uuid4()}{Path(filename).suffix.lower()}"
        upload_reservation = runtime_settings.max_upload_bytes
        upload_reserved = False
        try:
            await _reserve_disk(request.app.state.container.ingestion, upload_reservation)
            upload_reserved = True
            await asyncio.to_thread(temp_dir.mkdir, parents=True, exist_ok=True)
            await _save_bounded_upload(file, temp_path, runtime_settings.max_upload_bytes)
        except asyncio.CancelledError:
            if upload_reserved:
                request.app.state.container.ingestion.release_disk(upload_reservation)
            await file.close()
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)
            raise
        except Exception:
            if upload_reserved:
                request.app.state.container.ingestion.release_disk(upload_reservation)
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)
            raise
        request.state.ingestion_slot_owned = True
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(
                None,
                partial(
                    request.app.state.container.ingestion.ingest_path,
                    temp_path,
                    tenant_id=principal.tenant_id,
                    filename=filename,
                    source_uri=validated_source_uri,
                ),
            )
        except Exception:
            request.app.state.ingestion_slots.release()
            request.app.state.container.ingestion.release_disk(upload_reservation)
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)
            raise
        request.app.state.background_ingestions.add(future)
        future.add_done_callback(request.app.state.background_ingestions.discard)
        background_cleanup = False
        try:
            result: IngestionResult = await asyncio.wait_for(
                asyncio.shield(future), timeout=runtime_settings.ingestion_timeout_seconds
            )
            INGESTIONS.labels(result.document.media_type, "success").inc()
            return result
        except TimeoutError as exc:
            INGESTIONS.labels("unknown", "timeout").inc()
            background_cleanup = True

            def finish_background(done: asyncio.Future[IngestionResult]) -> None:
                try:
                    done.exception()
                except asyncio.CancelledError:
                    logger.debug("background_ingestion_cancelled")
                finally:
                    request.app.state.ingestion_slots.release()
                    request.app.state.container.ingestion.release_disk(upload_reservation)
                    cleanup = loop.run_in_executor(
                        None,
                        partial(temp_path.unlink, missing_ok=True),
                    )
                    request.app.state.background_file_cleanups.add(cleanup)
                    cleanup.add_done_callback(request.app.state.background_file_cleanups.discard)

            future.add_done_callback(finish_background)
            raise HTTPException(status_code=504, detail="Ingestion timed out") from exc
        except asyncio.CancelledError:
            background_cleanup = True

            def finish_cancelled(done: asyncio.Future[IngestionResult]) -> None:
                try:
                    done.exception()
                except asyncio.CancelledError:
                    logger.debug("background_ingestion_cancelled")
                finally:
                    request.app.state.ingestion_slots.release()
                    request.app.state.container.ingestion.release_disk(upload_reservation)
                    cleanup = loop.run_in_executor(
                        None,
                        partial(temp_path.unlink, missing_ok=True),
                    )
                    request.app.state.background_file_cleanups.add(cleanup)
                    cleanup.add_done_callback(request.app.state.background_file_cleanups.discard)

            future.add_done_callback(finish_cancelled)
            raise
        finally:
            if not background_cleanup:
                request.app.state.ingestion_slots.release()
                request.app.state.container.ingestion.release_disk(upload_reservation)
                await asyncio.to_thread(temp_path.unlink, missing_ok=True)

    @app.post(
        "/v1/ingestion-jobs",
        response_model=EnqueueJobResult,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["ingestion-jobs"],
    )
    async def enqueue_ingestion_job(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_WRITE))],
        file: Annotated[UploadFile, File(description="PDF, image, MP4/WebM, CSV, JSON, or text")],
        source_uri: Annotated[str | None, Form()] = None,
    ) -> EnqueueJobResult:
        filename = safe_filename(file.filename)
        validated_source_uri = _validate_source_uri(source_uri)
        if not getattr(request.state, "ingestion_slot_held", False):
            raise RuntimeError("Upload capacity boundary was not applied")
        temp_dir = runtime_settings.data_dir / "tmp"
        temp_path = temp_dir / f"{uuid.uuid4()}{Path(filename).suffix.lower()}"
        upload_reservation = runtime_settings.max_upload_bytes
        upload_reserved = False
        try:
            await _reserve_disk(request.app.state.container.ingestion, upload_reservation)
            upload_reserved = True
            await asyncio.to_thread(temp_dir.mkdir, parents=True, exist_ok=True)
            await _save_bounded_upload(file, temp_path, runtime_settings.max_upload_bytes)
            try:
                return await asyncio.to_thread(
                    request.app.state.job_service.enqueue,
                    temp_path,
                    tenant_id=principal.tenant_id,
                    filename=filename,
                    source_uri=validated_source_uri,
                )
            except JobQueueFullError as exc:
                raise HTTPException(
                    status_code=429,
                    detail="Tenant ingestion queue quota exceeded",
                    headers={"Retry-After": "30"},
                ) from exc
        finally:
            if upload_reserved:
                request.app.state.container.ingestion.release_disk(upload_reservation)
            await file.close()
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)

    @app.get(
        "/v1/ingestion-jobs",
        response_model=list[IngestionJob],
        tags=["ingestion-jobs"],
    )
    async def list_ingestion_jobs(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_READ))],
        limit: int = 100,
    ) -> list[IngestionJob]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return await asyncio.to_thread(
            request.app.state.job_service.list,
            principal.tenant_id,
            limit=limit,
        )

    @app.get(
        "/v1/ingestion-jobs/{job_id}",
        response_model=IngestionJob,
        tags=["ingestion-jobs"],
    )
    async def get_ingestion_job(
        job_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_READ))],
    ) -> IngestionJob:
        try:
            return await asyncio.to_thread(
                request.app.state.job_service.get,
                principal.tenant_id,
                str(job_id),
            )
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Ingestion job not found") from exc

    @app.post(
        "/v1/ingestion-jobs/{job_id}/cancel",
        response_model=IngestionJob,
        tags=["ingestion-jobs"],
    )
    async def cancel_ingestion_job(
        job_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.JOB_CONTROL))],
    ) -> IngestionJob:
        try:
            return await asyncio.to_thread(
                request.app.state.job_service.cancel,
                principal.tenant_id,
                str(job_id),
            )
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Ingestion job not found") from exc

    @app.post(
        "/v1/ingestion-jobs/{job_id}/retry",
        response_model=IngestionJob,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["ingestion-jobs"],
    )
    async def retry_ingestion_job(
        job_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.JOB_CONTROL))],
    ) -> IngestionJob:
        try:
            return await asyncio.to_thread(
                request.app.state.job_service.retry,
                principal.tenant_id,
                str(job_id),
            )
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Ingestion job not found") from exc
        except JobStateConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.delete(
        "/v1/ingestion-jobs/{job_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["ingestion-jobs"],
    )
    async def delete_ingestion_job(
        job_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.JOB_CONTROL))],
    ) -> Response:
        try:
            await asyncio.to_thread(
                request.app.state.job_service.delete,
                principal.tenant_id,
                str(job_id),
            )
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Ingestion job not found") from exc
        except JobStateConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/v1/documents", response_model=list[Document], tags=["documents"])
    async def list_documents(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_READ))],
        limit: int = 100,
    ) -> list[Document]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return await asyncio.to_thread(
            request.app.state.container.store.list_documents, principal.tenant_id, limit
        )

    @app.delete(
        "/v1/documents",
        response_model=DeleteDocumentsResult,
        tags=["documents"],
    )
    async def delete_documents(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_DELETE))],
        confirmation: Annotated[str, Query()],
    ) -> DeleteDocumentsResult:
        if confirmation != "RESET":
            raise HTTPException(status_code=422, detail="confirmation must equal RESET")
        cancel_timeout_seconds = max(
            1.0,
            min(30.0, runtime_settings.request_timeout_seconds - 5.0),
        )
        try:
            deleted_count = await asyncio.to_thread(
                request.app.state.job_service.reset,
                principal.tenant_id,
                timeout_seconds=cancel_timeout_seconds,
            )
        except JobStateConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return DeleteDocumentsResult(deleted_count=deleted_count)

    @app.get("/v1/documents/{document_id}", response_model=Document, tags=["documents"])
    async def get_document(
        document_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_READ))],
    ) -> Document:
        document: Document | None = await asyncio.to_thread(
            request.app.state.container.store.get_document,
            principal.tenant_id,
            str(document_id),
        )
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        return document

    @app.delete("/v1/documents/{document_id}", status_code=204, tags=["documents"])
    async def delete_document(
        document_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.EVIDENCE_DELETE))],
    ) -> Response:
        deleted = await asyncio.to_thread(
            request.app.state.container.ingestion.delete,
            principal.tenant_id,
            str(document_id),
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="Document not found")
        return Response(status_code=204)

    @app.post(
        "/v1/query",
        response_model=QueryResponse | ReviewSubmission,
        responses={202: {"description": "Answer withheld pending mandatory human review"}},
        tags=["query"],
    )
    async def query(
        payload: QueryRequest,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.QUERY))],
    ) -> Any:
        if not getattr(request.state, "query_slot_held", False):
            raise RuntimeError("Query capacity boundary was not applied")
        try:
            result: QueryResponse = await asyncio.wait_for(
                request.app.state.container.agent.ask(principal.tenant_id, payload),
                timeout=runtime_settings.request_timeout_seconds,
            )
            result = result.model_copy(update={"request_id": request.state.request_id})
            if runtime_settings.oversight_enabled:
                assessment = await asyncio.to_thread(
                    request.app.state.oversight.assess,
                    principal.tenant_id,
                    payload.query,
                    result,
                )
                if assessment.requires_review:
                    review = await asyncio.to_thread(
                        request.app.state.oversight.submit,
                        tenant_id=principal.tenant_id,
                        query=payload.query,
                        requester=principal,
                        response=result,
                        assessment=assessment,
                    )
                    request.state.audit_event_type = "review.submitted"
                    request.state.audit_details = {"review_id": review.id}
                    QUERIES.labels("review_required").inc()
                    submission = ReviewSubmission(
                        review_id=review.id,
                        risk_level=review.risk_level,
                        reasons=review.reasons,
                        request_id=request.state.request_id,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_202_ACCEPTED,
                        content=submission.model_dump(mode="json"),
                    )
            QUERIES.labels("success").inc()
            return result
        except TimeoutError as exc:
            QUERIES.labels("timeout").inc()
            raise HTTPException(status_code=504, detail="Query timed out") from exc

    @app.get("/v1/reviews", response_model=list[ReviewRecord], tags=["reviews"])
    async def list_reviews(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.REVIEW_READ))],
        review_status: Annotated[ReviewStatus | None, Query(alias="status")] = None,
        limit: int = 100,
    ) -> list[ReviewRecord]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return await asyncio.to_thread(
            request.app.state.governance.list_reviews,
            principal.tenant_id,
            status=review_status,
            limit=limit,
        )

    @app.get("/v1/reviews/{review_id}", response_model=ReviewRecord, tags=["reviews"])
    async def get_review(
        review_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.REVIEW_READ))],
    ) -> ReviewRecord:
        review: ReviewRecord | None = await asyncio.to_thread(
            request.app.state.governance.get_review,
            principal.tenant_id,
            str(review_id),
        )
        if review is None:
            raise HTTPException(status_code=404, detail="Review not found")
        return review

    @app.post(
        "/v1/reviews/{review_id}/decision",
        response_model=ReviewRecord,
        tags=["reviews"],
    )
    async def decide_review(
        review_id: uuid.UUID,
        payload: ReviewDecisionRequest,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.REVIEW_DECIDE))],
    ) -> ReviewRecord:
        if principal.identity_type != IdentityType.USER:
            raise HTTPException(status_code=403, detail="A human user identity must decide reviews")
        reason = payload.reason.strip()
        if len(reason) < 3:
            raise HTTPException(status_code=422, detail="A substantive decision reason is required")
        current = await asyncio.to_thread(
            request.app.state.governance.get_review,
            principal.tenant_id,
            str(review_id),
        )
        if current is None:
            raise HTTPException(status_code=404, detail="Review not found")
        if current.status != ReviewStatus.PENDING:
            raise HTTPException(status_code=409, detail="Review has already been decided")
        if current.requester_subject == principal.subject_id:
            raise HTTPException(
                status_code=409,
                detail="Requesters cannot approve their own answer",
            )
        review: ReviewRecord | None = await asyncio.to_thread(
            request.app.state.governance.decide_review,
            principal.tenant_id,
            str(review_id),
            reviewer=principal,
            decision=payload.decision,
            reason=reason,
        )
        if review is None:
            raise HTTPException(
                status_code=409,
                detail="Review decision conflicted with another update",
            )
        request.state.audit_event_type = f"review.{payload.decision.value}d"
        request.state.audit_details = {"review_id": review.id}
        return review

    @app.get(
        "/v1/reviews/{review_id}/result",
        response_model=QueryResponse,
        tags=["reviews"],
    )
    async def get_review_result(
        review_id: uuid.UUID,
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.QUERY))],
    ) -> QueryResponse:
        review: ReviewRecord | None = await asyncio.to_thread(
            request.app.state.governance.get_review,
            principal.tenant_id,
            str(review_id),
        )
        if review is None:
            raise HTTPException(status_code=404, detail="Review not found")
        if review.requester_subject != principal.subject_id and not principal.permits(
            Permission.REVIEW_READ
        ):
            # Preserve the same response as a cross-tenant/missing ID so review state
            # cannot be used as an oracle by unrelated same-tenant query users.
            raise HTTPException(status_code=404, detail="Review not found")
        if review.status == ReviewStatus.PENDING:
            raise HTTPException(status_code=409, detail="Review is still pending")
        if review.status == ReviewStatus.REJECTED:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Answer was rejected")
        if review.candidate_response is None:
            raise RuntimeError("Approved review has no candidate response")
        return review.candidate_response

    @app.get(
        "/v1/audit/identity-events",
        response_model=list[IdentityAuditEvent],
        tags=["audit"],
    )
    async def list_identity_events(
        request: Request,
        principal: Annotated[Principal, Depends(require_permission(Permission.AUDIT_READ))],
        limit: int = 100,
    ) -> list[IdentityAuditEvent]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        return await asyncio.to_thread(
            request.app.state.governance.list_identity_events,
            principal.tenant_id,
            limit=limit,
        )

    instrument_fastapi_app(app, runtime_settings)
    return app


app = create_app()
