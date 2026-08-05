from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from crisisweave.models import QueryUsageSummary
from crisisweave.observability import (
    _otel_headers,
    capture_operation_usage,
    collect_stage_observations,
    configure_telemetry,
    observe_root_operation,
    observe_stage,
    record_ingestion_job_completion,
    record_ingestion_lifecycle_delivery_failure,
    record_ingestion_lifecycle_exclusion,
    record_ingestion_lifecycle_outbox_state,
    record_ingestion_lifecycle_span,
    record_job_queue_depth,
    record_model_usage,
    record_query_end_to_end_completion,
    record_stage_observations,
    redact_event,
    start_worker_metrics_server,
    validate_stage_observations,
)

_ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - deliberate listener-validation input


def test_log_redactor_removes_nested_credentials_and_header_values() -> None:
    event = {
        "authorization": "Bearer top-secret-token",
        "nested": {
            "Set-Cookie": "session=secret",
            "message": "Authorization: Bearer another-secret\r\nforged=true",
        },
        "items": ["api_key=third-secret&safe=yes", {"password": "fourth-secret"}],
        "url": "https://user:pass@example.org/path?token=fifth-secret&ok=1",
    }
    redacted = redact_event(None, "info", event)
    rendered = repr(redacted)
    for secret in (
        "top-secret-token",
        "session=secret",
        "another-secret",
        "third-secret",
        "fourth-secret",
        "user:pass",
        "fifth-secret",
    ):
        assert secret not in rendered
    assert "\r" not in rendered and "\n" not in rendered
    assert redacted["authorization"] == "[REDACTED]"


def test_model_usage_is_bounded_and_costed_from_operator_prices() -> None:
    with capture_operation_usage("query", compute_cost_per_hour=0.0) as operation:
        usage = record_model_usage(
            "answer",
            {"prompt_tokens": 1_000_000, "completion_tokens": 500_000},
            input_cost_per_million=2.0,
            output_cost_per_million=4.0,
        )
    assert usage.input_tokens == 1_000_000
    assert usage.output_tokens == 500_000
    assert usage.cost_usd == 4.0
    assert operation.model_cost_usd == 4.0
    assert operation.total_cost_usd == 4.0

    ignored = record_model_usage(
        "router",
        {"prompt_tokens": -1, "completion_tokens": True},
        input_cost_per_million=1.0,
        output_cost_per_million=1.0,
    )
    assert ignored.input_tokens == ignored.output_tokens == 0
    with pytest.raises(ValueError, match="finite"):
        record_model_usage(
            "router",
            {},
            input_cost_per_million=float("nan"),
            output_cost_per_million=0.0,
        )


def test_operation_cost_and_usage_model_validate_totals(monkeypatch: pytest.MonkeyPatch) -> None:
    moments = iter((100.0, 3700.0))
    monkeypatch.setattr("crisisweave.observability.time.perf_counter", lambda: next(moments))
    with capture_operation_usage("document", compute_cost_per_hour=3.0) as usage:
        pass
    assert usage.compute_cost_usd == 3.0
    assert QueryUsageSummary(compute_cost_usd=3.0, total_cost_usd=3.0).total_cost_usd == 3.0
    with pytest.raises(ValidationError, match="total query cost"):
        QueryUsageSummary(compute_cost_usd=3.0, total_cost_usd=2.0)


def test_root_operation_aggregates_nested_usage_without_content_labels() -> None:
    with observe_root_operation(
        "query",
        "0123456789abcdef0123456789abcdef",
        compute_cost_per_hour=3.6,
    ) as root:
        with capture_operation_usage("query", compute_cost_per_hour=0.0):
            record_model_usage(
                "answer",
                {"input_tokens": 10, "output_tokens": 2},
                input_cost_per_million=1.0,
                output_cost_per_million=5.0,
            )
        root.complete("2xx", 10.0)

    assert root.usage.input_tokens == 10
    assert root.usage.output_tokens == 2
    assert root.usage.model_cost_usd == pytest.approx(0.00002)
    assert root.usage.compute_cost_usd == pytest.approx(0.01)
    assert root.completed is True

    with (
        pytest.raises(ValueError, match="identifier"),
        observe_root_operation("query", "tenant-or-content", compute_cost_per_hour=0.0),
    ):
        pass


def test_telemetry_helpers_fail_closed_without_leaking_headers() -> None:
    assert _otel_headers("x-api-key=secret,x-tenant=opaque") == {
        "x-api-key": "secret",
        "x-tenant": "opaque",
    }
    for malformed in ("missing-separator", "bad header=value", "valid=bad\nvalue"):
        with pytest.raises(ValueError, match="malformed"):
            _otel_headers(malformed)
    assert (
        configure_telemetry(
            SimpleNamespace(
                app_env="test",
                telemetry_enabled=False,
                otel_service_name="test-service",
                otel_exporter_otlp_endpoint=None,
                otel_exporter_headers=None,
                otel_exporter_ca_file=None,
                otel_trace_sample_ratio=0.0,
            )
        )
        is False
    )
    with pytest.raises(ValueError, match="Unsupported"), observe_stage("unknown"):
        pass


def test_isolated_parser_stage_observations_are_bounded_and_reemitted() -> None:
    with collect_stage_observations() as observations, observe_stage("ocr"):
        pass

    validated = validate_stage_observations(observations)
    assert len(validated) == 1
    assert validated[0]["stage"] == "ocr"
    assert validated[0]["status"] == "ok"
    assert float(validated[0]["duration_seconds"]) >= 0
    record_stage_observations(validated)

    for malformed in (
        {"stage": "ocr"},
        [{"stage": "retrieval", "status": "ok", "duration_seconds": 1.0}],
        [{"stage": "ocr", "status": "ok", "duration_seconds": float("nan")}],
        [{"stage": "ocr", "status": "other", "duration_seconds": 1.0}],
    ):
        with pytest.raises(ValueError, match="stage"):
            validate_stage_observations(malformed)


def test_worker_metrics_listener_rejects_unsafe_addresses() -> None:
    for host, port in (("example.org", 9100), (_ALL_INTERFACES, 0), ("::", 9100)):
        with pytest.raises(ValueError, match="address"):
            start_worker_metrics_server(host, port)


def test_job_queue_metrics_reject_content_or_unbounded_labels() -> None:
    record_job_queue_depth({"queued": 2, "dead_letter": 1})
    for malformed in (
        {"tenant-a": 1},
        {"queued": -1},
        {"queued": True},
    ):
        with pytest.raises(ValueError, match="queue metrics"):
            record_job_queue_depth(malformed)

    record_ingestion_lifecycle_outbox_state(3, 15.5)
    record_ingestion_lifecycle_outbox_state(0, 0.0)
    for count, age in ((True, 0.0), (-1, 0.0), (0, 1.0), (1, float("inf"))):
        with pytest.raises(ValueError, match="outbox state"):
            record_ingestion_lifecycle_outbox_state(count, age)  # type: ignore[arg-type]

    for stage in ("claim", "emit", "ack", "prune"):
        record_ingestion_lifecycle_delivery_failure(stage)
    with pytest.raises(ValueError, match="stage"):
        record_ingestion_lifecycle_delivery_failure("tenant-a")


def test_ingestion_end_to_end_metric_accepts_only_terminal_bounded_samples() -> None:
    record_ingestion_job_completion("succeeded", 12.5)
    for status, duration in (
        ("running", 1.0),
        ("succeeded", -1.0),
        ("dead_letter", float("nan")),
    ):
        with pytest.raises(ValueError, match="completion metric"):
            record_ingestion_job_completion(status, duration)

    with pytest.raises(ValueError, match="reason"):
        record_ingestion_lifecycle_exclusion("tenant-specific")


def test_historical_ingestion_span_uses_enqueue_and_terminal_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentelemetry import trace

    captured: dict[str, object] = {}

    class Span:
        def end(self, *, end_time: int) -> None:
            captured["end_time"] = end_time

    class Tracer:
        def start_span(self, name: str, **kwargs: object) -> Span:
            captured["name"] = name
            captured.update(kwargs)
            return Span()

    monkeypatch.setattr(trace, "get_tracer", lambda _name: Tracer())
    started = datetime(2026, 8, 3, 1, 2, 3, tzinfo=UTC)
    terminal = started + timedelta(seconds=12.5)
    record_ingestion_lifecycle_span(
        "a" * 32,
        "succeeded",
        lifecycle_started_at=started,
        terminal_at=terminal,
        processing_seconds=9.0,
        compute_cost_usd=0.12,
        measurement_quality="estimated",
    )

    assert captured["name"] == "crisisweave.document.end_to_end"
    assert captured["start_time"] == int(started.timestamp() * 1_000_000_000)
    assert captured["end_time"] == int(terminal.timestamp() * 1_000_000_000)
    attributes = captured["attributes"]
    assert isinstance(attributes, dict)
    assert attributes["crisisweave.end_to_end_duration_seconds"] == 12.5
    assert attributes["crisisweave.cost_measurement_quality"] == "estimated"
    assert not any("tenant" in key or "content" in key for key in attributes)


def test_query_end_to_end_metric_validates_completion_status() -> None:
    record_query_end_to_end_completion(200, 0.25, completed=True)
    record_query_end_to_end_completion(None, 0.5, completed=False)
    with pytest.raises(ValueError, match="status"):
        record_query_end_to_end_completion(None, 0.25, completed=True)
    with pytest.raises(ValueError, match="metric"):
        record_query_end_to_end_completion(200, float("inf"), completed=True)
