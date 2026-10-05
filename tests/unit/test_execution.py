from __future__ import annotations

import asyncio
import contextlib
import threading
from contextvars import ContextVar

from crisisweave.execution import BlockingRunner


async def test_blocking_call_receives_a_copy_of_the_callers_context() -> None:
    runner = BlockingRunner(1)
    request_context: ContextVar[str] = ContextVar("request_context", default="unset")
    token = request_context.set("request-a")

    def inspect_and_mutate_context() -> tuple[str, str]:
        inherited = request_context.get()
        request_context.set("worker-only")
        return inherited, request_context.get()

    try:
        assert await runner.run(inspect_and_mutate_context) == ("request-a", "worker-only")
        assert request_context.get() == "request-a"
    finally:
        request_context.reset(token)
        runner.close()


async def test_concurrent_blocking_calls_keep_contexts_isolated() -> None:
    runner = BlockingRunner(2)
    request_context: ContextVar[str] = ContextVar("request_context", default="unset")
    workers_ready = threading.Barrier(2)

    def inspect_context() -> tuple[str, str]:
        inherited = request_context.get()
        request_context.set(f"{inherited}-worker")
        workers_ready.wait(timeout=2)
        return inherited, request_context.get()

    async def invoke(value: str) -> tuple[str, str]:
        token = request_context.set(value)
        try:
            return await runner.run(inspect_context)
        finally:
            request_context.reset(token)

    try:
        results = await asyncio.gather(invoke("request-a"), invoke("request-b"))
        assert set(results) == {
            ("request-a", "request-a-worker"),
            ("request-b", "request-b-worker"),
        }
        assert request_context.get() == "unset"
    finally:
        runner.close()


async def test_cancelled_blocking_call_holds_capacity_until_worker_finishes() -> None:
    runner = BlockingRunner(1)
    started = threading.Event()
    release = threading.Event()

    def blocked() -> str:
        started.set()
        release.wait(timeout=5)
        return "done"

    first = asyncio.create_task(runner.run(blocked))
    await asyncio.to_thread(started.wait, 1)
    first.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await first
    second = asyncio.create_task(runner.run(lambda: "second"))
    await asyncio.sleep(0.02)
    assert not second.done()
    release.set()
    assert await asyncio.wait_for(second, 1) == "second"
    runner.close()
