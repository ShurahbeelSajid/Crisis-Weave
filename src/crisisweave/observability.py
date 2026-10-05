"""Privacy-preserving structured logs and process metrics."""

from __future__ import annotations

import logging
import math
import re
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from typing import Any, Literal, ParamSpec, Protocol, TypeVar, cast

import structlog
from prometheus_client import Counter, Gauge, Histogram, start_http_server

HTTP_REQUESTS = Counter(
    "crisisweave_http_requests_total", "HTTP requests", ("method", "route", "status")
)
HTTP_DURATION = Histogram(
    "crisisweave_http_request_duration_seconds", "HTTP request duration", ("method", "route")
)
QUERY_END_TO_END_DURATION = Histogram(
    "crisisweave_query_end_to_end_duration_seconds",
    "Query HTTP receipt-to-final-response latency",
    ("status_class",),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)
INGESTIONS = Counter("crisisweave_ingestions_total", "Ingestion outcomes", ("media_type", "status"))
QUERIES = Counter("crisisweave_queries_total", "Query outcomes", ("status",))
PIPELINE_STAGE_DURATION = Histogram(
    "crisisweave_pipeline_stage_duration_seconds",
    "Measured pipeline stage duration",
    ("stage", "status"),
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10,
        30,
        60,
        120,
        300,
        600,
        1200,
        1800,
    ),
)
PIPELINE_OPERATIONS = Counter(
    "crisisweave_pipeline_operations_total",
    "Pipeline stage outcomes",
    ("stage", "status"),
)
MODEL_TOKENS = Counter(
    "crisisweave_model_tokens_total",
    "Provider-reported model tokens after bounded validation",
    ("role", "direction"),
)
MODEL_COST_USD = Counter(
    "crisisweave_model_cost_usd_total",
    "Calculated model cost from configured per-million-token rates",
    ("role",),
)
OPERATION_COST_USD = Counter(
    "crisisweave_operation_cost_usd_total",
    "Allocated model and compute cost by operation type",
    ("operation_type",),
)
INGESTED_BYTES = Counter(
    "crisisweave_ingested_bytes_total",
    "Accepted ingestion input bytes",
    ("media_type",),
)
INGESTION_JOB_END_TO_END_DURATION = Histogram(
    "crisisweave_ingestion_job_end_to_end_seconds",
    "Upload enqueue-to-terminal ingestion latency",
    ("status",),
    buckets=(1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200),
)
INGESTION_LIFECYCLE_EXCLUDED = Counter(
    "crisisweave_ingestion_lifecycle_excluded_total",
    "Terminal ingestion lifecycle samples excluded from latency and cost evidence",
    ("reason",),
)
JOB_QUEUE_DEPTH = Gauge(
    "crisisweave_ingestion_jobs",
    "Durable ingestion jobs by lifecycle status",
    ("status",),
)
JOB_QUEUE_READY = Gauge(
    "crisisweave_ingestion_queue_ready",
    "Durable ingestion jobs ready now or waiting for retry",
)
JOB_QUEUE_REFRESH_FAILURES = Counter(
    "crisisweave_ingestion_job_metric_refresh_failures_total",
    "Failed attempts to refresh durable ingestion queue metrics",
)
INGESTION_LIFECYCLE_OUTBOX_PENDING = Gauge(
    "crisisweave_ingestion_lifecycle_outbox_pending",
    "Undelivered terminal lifecycle events in the durable worker outbox",
)
INGESTION_LIFECYCLE_OUTBOX_OLDEST_PENDING_SECONDS = Gauge(
    "crisisweave_ingestion_lifecycle_outbox_oldest_pending_seconds",
    "Age in seconds of the oldest undelivered terminal lifecycle event",
)
INGESTION_LIFECYCLE_DELIVERY_FAILURES = Counter(
    "crisisweave_ingestion_lifecycle_delivery_failures_total",
    "Lifecycle outbox delivery failures by fixed worker stage",
    ("stage",),
)

_JOB_STATUSES = (
    "queued",
    "running",
    "retry_wait",
    "cancelling",
    "succeeded",
    "cancelled",
    "dead_letter",
)

_STAGES = frozenset(
    {
        "ingestion",
        "ocr",
        "transcription",
        "retrieval",
        "reranking",
        "llm_generation",
        "query",
    }
)
_FORWARDED_PARSER_STAGES = frozenset({"ocr", "transcription"})
_MAX_FORWARDED_STAGE_OBSERVATIONS = 4096
# Explicit authenticated metrics listener, never used as an outbound destination.
_ALL_INTERFACES = "0.0.0.0"  # noqa: S104  # nosec B104
_LOGGER = logging.getLogger(__name__)
_P = ParamSpec("_P")
_R = TypeVar("_R")


class TelemetrySettings(Protocol):
    app_env: Literal["development", "test", "production", "parser"]
    telemetry_enabled: bool
    otel_service_name: str
    otel_exporter_otlp_endpoint: str | None
    otel_exporter_headers: Any
    otel_exporter_ca_file: Any
    otel_trace_sample_ratio: float


@dataclass(frozen=True)
class ModelUsage:
    input_tokens: int
    output_tokens: int
    cost_usd: float


@dataclass
class OperationUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    model_cost_usd: float = 0.0
    compute_cost_usd: float = 0.0

    @property
    def total_cost_usd(self) -> float:
        return self.model_cost_usd + self.compute_cost_usd


@dataclass
class RootOperation:
    """Content-free usage accumulated across one externally visible operation."""

    operation_type: Literal["query", "document"]
    compute_cost_per_hour: float
    usage: OperationUsage
    completed: bool = False

    def complete(self, terminal_status: str, duration_seconds: float) -> None:
        if self.completed:
            return
        if (
            not re.fullmatch(r"[a-z0-9_]{2,32}", terminal_status)
            or not math.isfinite(duration_seconds)
            or not 0 <= duration_seconds <= 30 * 24 * 60 * 60
        ):
            raise ValueError("root operation completion is malformed")
        self.usage.compute_cost_usd = duration_seconds * self.compute_cost_per_hour / 3600
        self.completed = True
        _set_span_attributes(
            {
                "crisisweave.terminal_status": terminal_status,
                "crisisweave.end_to_end_duration_seconds": duration_seconds,
                "gen_ai.usage.input_tokens": self.usage.input_tokens,
                "gen_ai.usage.output_tokens": self.usage.output_tokens,
                "crisisweave.model_cost_usd": self.usage.model_cost_usd,
                "crisisweave.compute_cost_usd": self.usage.compute_cost_usd,
                "crisisweave.total_cost_usd": self.usage.total_cost_usd,
            }
        )


_CURRENT_OPERATION_USAGE: ContextVar[OperationUsage | None] = ContextVar(
    "crisisweave_operation_usage", default=None
)
_CURRENT_ROOT_OPERATION: ContextVar[RootOperation | None] = ContextVar(
    "crisisweave_root_operation", default=None
)
_COLLECTED_STAGE_OBSERVATIONS: ContextVar[list[dict[str, str | float]] | None] = ContextVar(
    "crisisweave_collected_stage_observations", default=None
)


_TELEMETRY_LOCK = threading.Lock()
_TELEMETRY_CONFIGURED = False


def _span_context(name: str, attributes: dict[str, str]) -> Any:
    try:
        from opentelemetry import trace
    except ImportError:
        return nullcontext()
    return trace.get_tracer("crisisweave").start_as_current_span(name, attributes=attributes)


def _set_span_attributes(attributes: dict[str, str | int | float]) -> None:
    try:
        from opentelemetry import trace
    except ImportError:
        return
    span = trace.get_current_span()
    if not span.is_recording():
        return
    for name, value in attributes.items():
        try:
            span.set_attribute(name, value)
        # Telemetry attribute failures must never affect application control flow.
        except Exception:  # noqa: S112  # nosec B112
            # Telemetry must never change an application response or queue transition.
            continue


@contextmanager
def observe_stage(stage: str) -> Any:
    """Measure one low-cardinality stage and emit a matching OpenTelemetry span."""

    if stage not in _STAGES:
        raise ValueError(f"Unsupported pipeline stage: {stage}")
    collector = _COLLECTED_STAGE_OBSERVATIONS.get()
    started = time.perf_counter()
    status = "ok"
    span_context = (
        nullcontext()
        if collector is not None
        else _span_context(
            f"crisisweave.{stage}",
            {
                "crisisweave.stage": stage,
                "crisisweave.measurement_scope": "core_operation",
            },
        )
    )
    with span_context:
        try:
            yield
        except BaseException:
            status = "error"
            raise
        finally:
            elapsed = max(0.0, time.perf_counter() - started)
            if collector is None:
                PIPELINE_STAGE_DURATION.labels(stage, status).observe(elapsed)
                PIPELINE_OPERATIONS.labels(stage, status).inc()
            else:
                if len(collector) >= _MAX_FORWARDED_STAGE_OBSERVATIONS:
                    raise RuntimeError("isolated parser emitted too many stage observations")
                collector.append(
                    {
                        "stage": stage,
                        "status": status,
                        "duration_seconds": elapsed,
                    }
                )


@contextmanager
def observe_root_operation(
    operation_type: Literal["query", "document"],
    operation_id: str,
    *,
    compute_cost_per_hour: float,
) -> Iterator[RootOperation]:
    """Create one privacy-safe root span and aggregate nested provider usage into it."""

    if not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise ValueError("root operation identifier must be a random 128-bit hex value")
    if not math.isfinite(compute_cost_per_hour) or compute_cost_per_hour < 0:
        raise ValueError("root operation compute cost must be finite and non-negative")
    root = RootOperation(operation_type, compute_cost_per_hour, OperationUsage())
    token = _CURRENT_ROOT_OPERATION.set(root)
    started = time.perf_counter()
    try:
        with _span_context(
            f"crisisweave.{operation_type}.end_to_end",
            {
                "crisisweave.operation_type": operation_type,
                "crisisweave.operation_id": operation_id,
                "crisisweave.measurement_scope": "end_to_end",
            },
        ):
            try:
                yield root
            finally:
                if not root.completed:
                    try:
                        root.complete("aborted", max(0.0, time.perf_counter() - started))
                    except Exception as exc:
                        _LOGGER.warning(
                            "root operation telemetry completion failed: %s",
                            type(exc).__name__,
                        )
    finally:
        _CURRENT_ROOT_OPERATION.reset(token)


@contextmanager
def collect_stage_observations() -> Iterator[list[dict[str, str | float]]]:
    """Collect child-process timings without exporting credentials or dead process metrics."""

    observations: list[dict[str, str | float]] = []
    token = _COLLECTED_STAGE_OBSERVATIONS.set(observations)
    try:
        yield observations
    finally:
        _COLLECTED_STAGE_OBSERVATIONS.reset(token)


def validate_stage_observations(raw: Any) -> list[dict[str, str | float]]:
    """Validate the bounded, content-free timing envelope returned by an isolated parser."""

    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > _MAX_FORWARDED_STAGE_OBSERVATIONS:
        raise ValueError("parser stage observations are malformed or excessive")
    validated: list[dict[str, str | float]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {
            "stage",
            "status",
            "duration_seconds",
        }:
            raise ValueError("parser stage observation is malformed")
        stage = item["stage"]
        status = item["status"]
        duration = item["duration_seconds"]
        if (
            stage not in _FORWARDED_PARSER_STAGES
            or status not in {"ok", "error"}
            or isinstance(duration, bool)
            or not isinstance(duration, (int, float))
        ):
            raise ValueError("parser stage observation contains an invalid value")
        duration_value = float(duration)
        if not math.isfinite(duration_value) or not 0.0 <= duration_value <= 3600.0:
            raise ValueError("parser stage duration is invalid")
        validated.append(
            {
                "stage": str(stage),
                "status": str(status),
                "duration_seconds": duration_value,
            }
        )
    return validated


def record_stage_observations(observations: list[dict[str, str | float]]) -> None:
    """Emit validated child timings in the long-lived, scrapeable worker process."""

    for observation in validate_stage_observations(observations):
        stage = str(observation["stage"])
        status = str(observation["status"])
        duration = float(observation["duration_seconds"])
        PIPELINE_STAGE_DURATION.labels(stage, status).observe(duration)
        PIPELINE_OPERATIONS.labels(stage, status).inc()
        try:
            from opentelemetry import trace
        except ImportError:
            continue
        end_time = time.time_ns()
        start_time = max(0, end_time - int(duration * 1_000_000_000))
        span = trace.get_tracer("crisisweave").start_span(
            f"crisisweave.{stage}",
            attributes={
                "crisisweave.stage": stage,
                "crisisweave.measurement_scope": "core_operation",
                "crisisweave.forwarded_from_isolated_parser": True,
                "crisisweave.stage_status": status,
            },
            start_time=start_time,
        )
        span.end(end_time=end_time)


def start_worker_metrics_server(host: str, port: int) -> tuple[Any, threading.Thread]:
    """Start the worker-only Prometheus listener on an operator-restricted interface."""

    if host not in {"127.0.0.1", _ALL_INTERFACES} or not 1 <= port <= 65535:
        raise ValueError("worker metrics listener address is invalid")
    return start_http_server(port=port, addr=host)


def stop_worker_metrics_server(server: tuple[Any, threading.Thread] | None) -> None:
    """Stop and join the Prometheus listener during graceful worker shutdown."""

    if server is None:
        return
    httpd, thread = server
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def record_job_queue_depth(counts: Mapping[str, int]) -> None:
    """Publish low-cardinality global queue depth without tenant or content labels."""

    if any(
        status not in _JOB_STATUSES
        or isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        for status, value in counts.items()
    ):
        raise ValueError("ingestion queue metrics are malformed")
    for status in _JOB_STATUSES:
        JOB_QUEUE_DEPTH.labels(status).set(counts.get(status, 0))
    JOB_QUEUE_READY.set(counts.get("queued", 0) + counts.get("retry_wait", 0))


def record_ingestion_lifecycle_outbox_state(
    pending_count: int,
    oldest_pending_seconds: float,
) -> None:
    """Publish content-free lifecycle delivery backlog state."""

    if (
        isinstance(pending_count, bool)
        or not isinstance(pending_count, int)
        or pending_count < 0
        or not math.isfinite(oldest_pending_seconds)
        or oldest_pending_seconds < 0
    ):
        raise ValueError("ingestion lifecycle outbox state is malformed")
    if pending_count == 0 and oldest_pending_seconds != 0:
        raise ValueError("ingestion lifecycle outbox state has an age without pending events")
    INGESTION_LIFECYCLE_OUTBOX_PENDING.set(pending_count)
    INGESTION_LIFECYCLE_OUTBOX_OLDEST_PENDING_SECONDS.set(oldest_pending_seconds)


def record_ingestion_lifecycle_delivery_failure(stage: str) -> None:
    """Count one failure using a fixed, low-cardinality delivery stage."""

    if stage not in {"claim", "emit", "ack", "prune"}:
        raise ValueError("ingestion lifecycle delivery failure stage is invalid")
    INGESTION_LIFECYCLE_DELIVERY_FAILURES.labels(stage).inc()


def record_ingestion_job_completion(status: str, duration_seconds: float) -> None:
    """Record a terminal queue lifecycle without content or tenant labels."""

    if (
        status not in {"succeeded", "cancelled", "dead_letter"}
        or not math.isfinite(duration_seconds)
        or duration_seconds < 0
        or duration_seconds > 30 * 24 * 60 * 60
    ):
        raise ValueError("ingestion job completion metric is malformed")
    INGESTION_JOB_END_TO_END_DURATION.labels(status).observe(duration_seconds)


def record_ingestion_lifecycle_exclusion(reason: str) -> None:
    """Count a bounded reason for excluding invalid lifecycle evidence."""

    if reason not in {"clock_skew", "older_than_30_days"}:
        raise ValueError("ingestion lifecycle exclusion reason is invalid")
    INGESTION_LIFECYCLE_EXCLUDED.labels(reason).inc()


def record_ingestion_lifecycle_span(
    operation_id: str,
    status: str,
    *,
    lifecycle_started_at: datetime,
    terminal_at: datetime,
    processing_seconds: float,
    compute_cost_usd: float,
    measurement_quality: Literal["measured", "estimated"],
) -> None:
    """Emit one historical enqueue-to-terminal span without tenant or content data."""

    duration_seconds = (terminal_at - lifecycle_started_at).total_seconds()
    if not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise ValueError("lifecycle operation identifier is invalid")
    if status not in {"succeeded", "cancelled", "dead_letter"}:
        raise ValueError("lifecycle terminal status is invalid")
    if lifecycle_started_at.tzinfo is None or terminal_at.tzinfo is None:
        raise ValueError("lifecycle timestamps must be timezone-aware")
    numeric = (duration_seconds, processing_seconds, compute_cost_usd)
    if any(not math.isfinite(value) or value < 0 for value in numeric):
        raise ValueError("lifecycle telemetry values are invalid")
    if duration_seconds > 30 * 24 * 60 * 60:
        raise ValueError("lifecycle duration exceeds the observable bound")
    if measurement_quality not in {"measured", "estimated"}:
        raise ValueError("lifecycle measurement quality is invalid")
    try:
        from opentelemetry import trace
    except ImportError:
        return
    start_time = int(lifecycle_started_at.timestamp() * 1_000_000_000)
    end_time = int(terminal_at.timestamp() * 1_000_000_000)
    if start_time < 0 or end_time < start_time:
        raise ValueError("lifecycle timestamps are outside the supported range")
    span = trace.get_tracer("crisisweave").start_span(
        "crisisweave.document.end_to_end",
        attributes={
            "crisisweave.operation_type": "document",
            "crisisweave.operation_id": operation_id,
            "crisisweave.measurement_scope": "end_to_end",
            "crisisweave.terminal_status": status,
            "crisisweave.end_to_end_duration_seconds": duration_seconds,
            "crisisweave.processing_seconds": processing_seconds,
            "crisisweave.compute_cost_usd": compute_cost_usd,
            "crisisweave.cost_measurement_quality": measurement_quality,
        },
        start_time=start_time,
    )
    span.end(end_time=end_time)


def record_query_end_to_end_completion(
    status_code: int | None,
    duration_seconds: float,
    *,
    completed: bool,
) -> None:
    """Record the full query HTTP lifecycle, including rejected and aborted requests."""

    if not math.isfinite(duration_seconds) or not 0 <= duration_seconds <= 3600:
        raise ValueError("query end-to-end metric is malformed")
    if completed:
        if status_code is None or not 100 <= status_code <= 599:
            raise ValueError("query end-to-end status is malformed")
        status_class = f"{status_code // 100}xx"
    else:
        status_class = "aborted"
    QUERY_END_TO_END_DURATION.labels(status_class).observe(duration_seconds)


def record_model_usage(
    role: str,
    usage: Any,
    *,
    input_cost_per_million: float,
    output_cost_per_million: float,
) -> ModelUsage:
    """Validate provider usage and calculate cost from operator-controlled prices."""

    if role not in {"router", "answer"}:
        raise ValueError("Model role must be router or answer")
    if not isinstance(usage, dict):
        return ModelUsage(0, 0, 0.0)

    def token_count(*names: str) -> int:
        raw = next((usage.get(name) for name in names if name in usage), 0)
        if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 10_000_000:
            return 0
        return raw

    input_tokens = token_count("prompt_tokens", "input_tokens")
    output_tokens = token_count("completion_tokens", "output_tokens")
    prices = (input_cost_per_million, output_cost_per_million)
    if any(not math.isfinite(value) or value < 0 for value in prices):
        raise ValueError("Model token prices must be finite and non-negative")
    cost = (
        input_tokens * input_cost_per_million + output_tokens * output_cost_per_million
    ) / 1_000_000
    MODEL_TOKENS.labels(role, "input").inc(input_tokens)
    MODEL_TOKENS.labels(role, "output").inc(output_tokens)
    MODEL_COST_USD.labels(role).inc(cost)
    current = _CURRENT_OPERATION_USAGE.get()
    if current is not None:
        current.input_tokens += input_tokens
        current.output_tokens += output_tokens
        current.model_cost_usd += cost
    root = _CURRENT_ROOT_OPERATION.get()
    if root is not None and root.usage is not current:
        root.usage.input_tokens += input_tokens
        root.usage.output_tokens += output_tokens
        root.usage.model_cost_usd += cost
    _set_span_attributes(
        {
            "gen_ai.usage.input_tokens": input_tokens,
            "gen_ai.usage.output_tokens": output_tokens,
            "crisisweave.model_cost_usd": cost,
        }
    )
    return ModelUsage(input_tokens, output_tokens, cost)


@contextmanager
def capture_operation_usage(operation_type: str, *, compute_cost_per_hour: float) -> Any:
    """Capture per-query/document usage without using tenant or content labels."""

    if operation_type not in {"query", "document"}:
        raise ValueError("operation_type must be query or document")
    if not math.isfinite(compute_cost_per_hour) or compute_cost_per_hour < 0:
        raise ValueError("compute cost must be finite and non-negative")
    usage = OperationUsage()
    token = _CURRENT_OPERATION_USAGE.set(usage)
    started = time.perf_counter()
    try:
        yield usage
    finally:
        elapsed_hours = max(0.0, time.perf_counter() - started) / 3600
        usage.compute_cost_usd = elapsed_hours * compute_cost_per_hour
        OPERATION_COST_USD.labels(operation_type).inc(usage.total_cost_usd)
        _set_span_attributes(
            {
                "crisisweave.operation_type": operation_type,
                "gen_ai.usage.input_tokens": usage.input_tokens,
                "gen_ai.usage.output_tokens": usage.output_tokens,
                "crisisweave.model_cost_usd": usage.model_cost_usd,
                "crisisweave.compute_cost_usd": usage.compute_cost_usd,
                "crisisweave.total_cost_usd": usage.total_cost_usd,
            }
        )
        _CURRENT_OPERATION_USAGE.reset(token)


def observed_operation(
    stage: str, operation_type: str, *, compute_cost_setting: str
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    """Decorate a synchronous service method with stage and allocated-cost measurement."""

    def decorator(function: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(function)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            if not args:
                raise TypeError("observed service methods require an instance")
            instance = args[0]
            settings = getattr(instance, "settings", None)
            rate = getattr(settings, compute_cost_setting, 0.0)
            with (
                observe_stage(stage),
                capture_operation_usage(operation_type, compute_cost_per_hour=rate),
            ):
                result = function(*args, **kwargs)
            if operation_type == "document":
                document = getattr(result, "document", None)
                media_type = getattr(document, "media_type", "unknown")
                size_bytes = getattr(document, "size_bytes", 0)
                if isinstance(media_type, str) and isinstance(size_bytes, int) and size_bytes >= 0:
                    INGESTED_BYTES.labels(media_type[:80]).inc(size_bytes)
            return result

        return wrapper

    return decorator


def _otel_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    value = raw.get_secret_value() if hasattr(raw, "get_secret_value") else str(raw)
    headers: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        key, separator, header_value = item.partition("=")
        key = key.strip()
        header_value = header_value.strip()
        if (
            not separator
            or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}", key)
            or not header_value
            or any(character in header_value for character in "\r\n")
        ):
            raise ValueError("OpenTelemetry exporter headers are malformed")
        headers[key] = header_value
    return headers


def configure_telemetry(settings: TelemetrySettings) -> bool:
    """Configure one process-wide OTLP/HTTP trace exporter when explicitly enabled."""

    global _TELEMETRY_CONFIGURED
    if not settings.telemetry_enabled:
        return False
    with _TELEMETRY_LOCK:
        if _TELEMETRY_CONFIGURED:
            return True
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
        except ImportError as exc:
            if settings.app_env == "production":
                raise RuntimeError(
                    "Production telemetry requires the crisisweave[telemetry] dependencies"
                ) from exc
            return False
        endpoint = settings.otel_exporter_otlp_endpoint
        if not endpoint:
            raise ValueError("An OTLP trace endpoint is required when telemetry is enabled")
        provider = TracerProvider(
            resource=Resource.create({"service.name": settings.otel_service_name}),
            sampler=ParentBased(TraceIdRatioBased(settings.otel_trace_sample_ratio)),
        )
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=endpoint,
                    headers=_otel_headers(settings.otel_exporter_headers),
                    certificate_file=(
                        str(settings.otel_exporter_ca_file)
                        if settings.otel_exporter_ca_file is not None
                        else None
                    ),
                )
            )
        )
        trace.set_tracer_provider(provider)
        _TELEMETRY_CONFIGURED = True
        return True


def instrument_fastapi_app(app: Any, settings: TelemetrySettings) -> bool:
    """Attach ASGI tracing without recording request bodies or authentication headers."""

    if not configure_telemetry(settings):
        return False
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError as exc:
        if settings.app_env == "production":
            raise RuntimeError("FastAPI OpenTelemetry instrumentation is unavailable") from exc
        return False
    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls="/health/live,/health/ready,/metrics",
    )
    return True


_SENSITIVE_KEYS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "secret",
    "set_cookie",
    "token",
)
_SECRET_PATTERN = re.compile(
    r"(?i)([\"']?(?:authorization|api[_-]?key|token|password|secret|cookie)"
    r"[\"']?\s*[:=]\s*)[\"']?(?:(?:bearer|basic)\s+)?[^\"'\s,;&}\]]+"
)
_URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(https?://)[^/@\s]+@")


def _redact_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[REDACTED_DEPTH]"
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            redacted[key] = (
                "[REDACTED]"
                if any(marker in normalized for marker in _SENSITIVE_KEYS)
                else _redact_value(item, depth=depth + 1)
            )
        return redacted
    if isinstance(value, list):
        return [_redact_value(item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, depth=depth + 1) for item in value)
    if isinstance(value, str):
        cleaned = value.replace("\r", " ").replace("\n", " ")
        cleaned = _SECRET_PATTERN.sub(r"\1[REDACTED]", cleaned)
        return _URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]@", cleaned)
    return value


def redact_event(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> dict[str, Any]:
    return cast(dict[str, Any], _redact_value(dict(event_dict)))


def configure_logging(level: str) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_event,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
