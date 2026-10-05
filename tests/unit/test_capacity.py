from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from crisisweave.api import ReadinessProbe
from crisisweave.ingestion import IngestionService, ingestion_reservation_bytes
from crisisweave.security import SecurityError


async def test_readiness_checks_are_single_flight_and_cached() -> None:
    calls = 0

    def check() -> bool:
        nonlocal calls
        calls += 1
        time.sleep(0.02)
        return True

    container = SimpleNamespace(
        store=SimpleNamespace(healthcheck=check),
        index=SimpleNamespace(healthcheck=check),
        ingestion=SimpleNamespace(parser_healthcheck=check),
        settings=SimpleNamespace(app_env="test", malware_scanner_host=None),
    )
    probe = ReadinessProbe(container, ttl_seconds=30)
    results = await asyncio.gather(*(probe.check() for _ in range(20)))
    assert all(all(value == "ok" for value in result.values()) for result in results)
    assert calls == 3
    await probe.check()
    assert calls == 3


def test_remote_ingestion_reserves_one_local_derived_copy(settings) -> None:
    configured = settings.model_copy(
        update={
            "parser_service_url": "http://parser:8001",
            "max_derived_bytes_per_document": 10_000,
        }
    )
    assert (
        ingestion_reservation_bytes(
            configured,
            input_size=500,
            additional_original_bytes=500,
        )
        == 10_500
    )


def test_concurrent_disk_reservations_share_headroom(
    settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = object.__new__(IngestionService)
    service.settings = settings.model_copy(
        update={"data_dir": tmp_path, "min_free_disk_bytes": 1_000}
    )
    service._disk_guard = threading.RLock()  # noqa: SLF001
    service._reserved_disk_bytes = 0  # noqa: SLF001
    monkeypatch.setattr(
        "crisisweave.ingestion.shutil.disk_usage",
        lambda _path: SimpleNamespace(free=2_500),
    )
    service.reserve_disk(1_000)
    with pytest.raises(SecurityError, match="headroom"):
        service.reserve_disk(1_000)
    service.release_disk(1_000)
    service.reserve_disk(1_000)
