"""Cancellation-aware bounded execution for blocking storage/model adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from functools import partial
from typing import Any, TypeVar

T = TypeVar("T")


class BlockingRunner:
    def __init__(self, workers: int) -> None:
        self._slots = asyncio.Semaphore(workers)
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="crisisweave-query"
        )

    async def run(self, function: Callable[..., T], *args: Any) -> T:
        await self._slots.acquire()
        loop = asyncio.get_running_loop()
        context = copy_context()
        future = loop.run_in_executor(
            self._executor,
            context.run,
            partial(function, *args),
        )
        release_in_callback = False
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            release_in_callback = True
            future.add_done_callback(lambda _done: self._slots.release())
            raise
        finally:
            if not release_in_callback:
                self._slots.release()

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)
