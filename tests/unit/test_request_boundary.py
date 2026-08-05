from __future__ import annotations

import asyncio
import io
import threading
from collections import deque
from types import SimpleNamespace
from typing import Any

import pytest

from crisisweave.api import (
    QueryEndToEndMiddleware,
    RequestBoundaryMiddleware,
    _open_exclusive_upload,
    _reserve_disk,
)


def _scope(path: str, headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    state = SimpleNamespace(
        ingestion_slots=asyncio.Semaphore(1),
        query_slots=asyncio.Semaphore(1),
    )
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
        "app": SimpleNamespace(state=state),
    }


def _middleware(app: Any, **overrides: Any) -> RequestBoundaryMiddleware:
    options = {
        "max_upload_body_bytes": 20,
        "max_query_body_bytes": 10,
        "queue_timeout_seconds": 0.1,
        "upload_body_timeout_seconds": 0.05,
        "query_body_timeout_seconds": 0.05,
        "body_chunk_timeout_seconds": 0.01,
        "credentials": (("alpha", "secret"),),
    }
    options.update(overrides)
    return RequestBoundaryMiddleware(app, **options)


async def _consume_body(
    _scope_value: dict[str, Any],
    receive: Any,
    send: Any,
) -> None:
    while True:
        message = await receive()
        if not message.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def test_query_content_length_is_rejected_before_body_or_slot_use() -> None:
    scope = _scope(
        "/v1/query",
        [
            (b"x-api-key", b"secret"),
            (b"content-type", b"application/json"),
            (b"content-length", b"11"),
        ],
    )
    receive_called = False
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal receive_called
        receive_called = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(_consume_body)(scope, receive, send))

    assert sent[0]["status"] == 413
    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not receive_called
    assert not scope["app"].state.query_slots.locked()


def test_query_end_to_end_metric_reaches_final_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[int | None, bool]] = []
    monkeypatch.setattr(
        "crisisweave.api.record_query_end_to_end_completion",
        lambda status_code, _duration, *, completed: observed.append((status_code, completed)),
    )
    scope = _scope(
        "/v1/query",
        [
            (b"x-api-key", b"secret"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ],
    )

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(_message: dict[str, Any]) -> None:
        return None

    asyncio.run(QueryEndToEndMiddleware(_middleware(_consume_body))(scope, receive, send))

    assert observed == [(204, True)]


def test_query_response_survives_completion_metric_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "crisisweave.api.record_query_end_to_end_completion",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("metrics unavailable")),
    )
    scope = _scope(
        "/v1/query",
        [
            (b"x-api-key", b"secret"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ],
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(QueryEndToEndMiddleware(_middleware(_consume_body))(scope, receive, send))

    assert sent[0]["status"] == 204


def test_query_response_survives_completion_span_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "crisisweave.observability.RootOperation.complete",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("tracing unavailable")),
    )
    scope = _scope(
        "/v1/query",
        [
            (b"x-api-key", b"secret"),
            (b"content-type", b"application/json"),
            (b"content-length", b"2"),
        ],
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(QueryEndToEndMiddleware(_middleware(_consume_body))(scope, receive, send))

    assert sent[0]["status"] == 204


def test_capacity_queue_timeout_is_retryable_and_does_not_call_app() -> None:
    scope = _scope(
        "/v1/query",
        [(b"x-api-key", b"secret"), (b"content-type", b"application/json")],
    )
    scope["app"].state.query_slots = asyncio.Semaphore(0)
    sent: list[dict[str, Any]] = []
    app_called = False

    async def app(_scope_value: dict[str, Any], _receive: Any, _send: Any) -> None:
        nonlocal app_called
        app_called = True

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(app, queue_timeout_seconds=0.01)(scope, receive, send))

    assert sent[0]["status"] == 503
    response_headers = dict(sent[0]["headers"])
    assert response_headers[b"retry-after"] == b"1"
    assert response_headers[b"connection"] == b"close"
    assert not app_called


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        (
            [
                (b"x-api-key", b"secret"),
                (b"content-type", b"application/json"),
                (b"content-type", b"text/plain"),
            ],
            400,
        ),
        ([(b"x-api-key", b"wrong"), (b"content-type", b"application/json")], 401),
        ([(b"x-api-key", b"secret"), (b"content-type", b"text/plain")], 415),
        (
            [
                (b"x-api-key", b"secret"),
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
                (b"transfer-encoding", b"chunked"),
            ],
            400,
        ),
        (
            [
                (b"x-api-key", b"secret"),
                (b"content-type", b"application/json"),
                (b"transfer-encoding", b"gzip"),
            ],
            400,
        ),
        (
            [
                (b"x-api-key", b"secret"),
                (b"content-type", b"application/json"),
                (b"content-length", b"+2"),
            ],
            400,
        ),
    ],
)
def test_invalid_or_ambiguous_request_headers_fail_before_body_read(
    headers: list[tuple[bytes, bytes]], expected_status: int
) -> None:
    scope = _scope("/v1/query", headers)
    sent: list[dict[str, Any]] = []
    receive_called = False
    app_called = False

    async def app(_scope_value: dict[str, Any], _receive: Any, _send: Any) -> None:
        nonlocal app_called
        app_called = True

    async def receive() -> dict[str, Any]:
        nonlocal receive_called
        receive_called = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(app)(scope, receive, send))

    assert sent[0]["status"] == expected_status
    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not receive_called
    assert not app_called


def test_production_sync_ingestion_is_rejected_before_body_or_slot_use() -> None:
    scope = _scope(
        "/v1/documents",
        [(b"x-api-key", b"secret"), (b"content-type", b"multipart/form-data")],
    )
    sent: list[dict[str, Any]] = []
    receive_called = False
    app_called = False

    async def app(_scope_value: dict[str, Any], _receive: Any, _send: Any) -> None:
        nonlocal app_called
        app_called = True

    async def receive() -> dict[str, Any]:
        nonlocal receive_called
        receive_called = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(app, synchronous_ingestion_enabled=False)(scope, receive, send))

    assert sent[0]["status"] == 409
    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not receive_called
    assert not app_called
    assert not scope["app"].state.ingestion_slots.locked()


def test_non_target_request_bypasses_body_boundary() -> None:
    scope = _scope("/health/live", [])
    scope["method"] = "GET"
    called = False

    async def app(_scope_value: dict[str, Any], _receive: Any, send: Any) -> None:
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> dict[str, Any]:
        raise AssertionError("body should not be read")

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(app)(scope, receive, send))

    assert called
    assert sent[0]["status"] == 204


def test_downstream_response_before_body_completion_forces_connection_close() -> None:
    scope = _scope(
        "/v1/query",
        [(b"x-api-key", b"secret"), (b"content-type", b"application/json")],
    )

    async def app(_scope_value: dict[str, Any], _receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 422, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> dict[str, Any]:
        raise AssertionError("body should not be read")

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(app)(scope, receive, send))

    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not scope["app"].state.query_slots.locked()


def test_completed_body_response_does_not_add_connection_close() -> None:
    scope = _scope(
        "/v1/query",
        [(b"x-api-key", b"secret"), (b"content-type", b"application/json")],
    )
    incoming = deque([{"type": "http.request", "body": b"{}", "more_body": False}])

    async def receive() -> dict[str, Any]:
        return incoming.popleft()

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(_consume_body)(scope, receive, send))

    assert b"connection" not in dict(sent[0]["headers"])
    assert not scope["app"].state.query_slots.locked()


def test_chunked_query_body_is_bounded_and_releases_slot() -> None:
    scope = _scope(
        "/v1/query",
        [(b"x-api-key", b"secret"), (b"content-type", b"application/json")],
    )
    incoming = deque(
        [
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"789012", "more_body": False},
        ]
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return incoming.popleft()

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(_consume_body)(scope, receive, send))

    assert sent[0]["status"] == 413
    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not scope["app"].state.query_slots.locked()


def test_slow_upload_times_out_and_releases_ingestion_slot() -> None:
    scope = _scope(
        "/v1/documents",
        [(b"x-api-key", b"secret"), (b"content-type", b"multipart/form-data")],
    )
    sent: list[dict[str, Any]] = []
    never = asyncio.Event()

    async def receive() -> dict[str, Any]:
        await never.wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(_middleware(_consume_body)(scope, receive, send))

    assert sent[0]["status"] == 408
    assert dict(sent[0]["headers"])[b"connection"] == b"close"
    assert not scope["app"].state.ingestion_slots.locked()


class _DelayedReservation:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.finish = threading.Event()
        self.reserved = 0
        self.release_calls = 0

    def reserve_disk(self, amount: int) -> None:
        self.started.set()
        if not self.finish.wait(timeout=2):
            raise TimeoutError("test reservation was not released")
        self.reserved += amount

    def release_disk(self, amount: int) -> None:
        self.reserved -= amount
        self.release_calls += 1


def test_cancelled_disk_reservation_is_released_after_worker_finishes() -> None:
    reservation = _DelayedReservation()

    async def scenario() -> None:
        task = asyncio.create_task(_reserve_disk(reservation, 100))
        started = await asyncio.to_thread(reservation.started.wait, 1)
        assert started
        task.cancel()
        reservation.finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert reservation.reserved == 0
    assert reservation.release_calls == 1


class _DelayedOpenTarget:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.finish = threading.Event()
        self.handle = io.BytesIO()
        self.unlinked = False

    def open(self, mode: str) -> io.BytesIO:
        assert mode == "xb"
        self.started.set()
        if not self.finish.wait(timeout=2):
            raise TimeoutError("test open was not released")
        return self.handle

    def unlink(self, *, missing_ok: bool) -> None:
        assert missing_ok
        self.unlinked = True


def test_cancelled_upload_open_closes_handle_and_unlinks_late_file() -> None:
    target = _DelayedOpenTarget()

    async def scenario() -> None:
        task = asyncio.create_task(_open_exclusive_upload(target))  # type: ignore[arg-type]
        started = await asyncio.to_thread(target.started.wait, 1)
        assert started
        task.cancel()
        target.finish.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert target.handle.closed
    assert target.unlinked
