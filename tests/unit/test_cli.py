from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from crisisweave import cli
from crisisweave.auth import tenant_identifier
from crisisweave.models import QueryRequest


class JsonResult:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value

    def model_dump_json(self, *, indent: int) -> str:
        return json.dumps(self.value, indent=indent)


def test_parser_exposes_operational_subcommands() -> None:
    parser = cli._parser()
    serve = parser.parse_args(["serve"])
    assert (serve.host, serve.port, serve.workers) == ("127.0.0.1", 8000, 1)

    worker = parser.parse_args(["parser-worker", "--host", "192.0.2.1", "--port", "9001"])
    assert (worker.host, worker.port) == ("192.0.2.1", 9001)

    ingestion_worker = parser.parse_args(["ingestion-worker", "--once"])
    assert (ingestion_worker.command, ingestion_worker.once) == ("ingestion-worker", True)
    assert parser.parse_args(["migrate"]).command == "migrate"

    ingest = parser.parse_args(
        ["ingest", "report.pdf", "--tenant", "response", "--source-uri", "nasa://report"]
    )
    assert ingest.path == Path("report.pdf")
    assert (ingest.tenant, ingest.source_uri) == ("response", "nasa://report")

    query = parser.parse_args(
        ["query", "Where is flooding?", "--tenant", "response", "--allow-web", "--top-k", "3"]
    )
    assert (query.tenant, query.allow_web, query.top_k) == ("response", True, 3)
    assert parser.parse_args(["doctor"]).command == "doctor"


def doctor_settings(tmp_path: Path) -> SimpleNamespace:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return SimpleNamespace(
        app_env="test",
        data_dir=data_dir,
        ffmpeg_path="ffmpeg",
        ffprobe_path="ffprobe",
        tesseract_path="tesseract",
        llm_provider="disabled",
        embedding_provider="hash",
        qdrant_url=None,
    )


def doctor_container(*, store_healthy: bool = True, index_healthy: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        store=SimpleNamespace(healthcheck=lambda: store_healthy),
        index=SimpleNamespace(healthcheck=lambda: index_healthy),
        close=MagicMock(),
    )


def test_doctor_reports_checks_and_closes_container(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    settings = doctor_settings(tmp_path)
    container = doctor_container()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli.shutil, "which", lambda executable: f"C:/bin/{executable}.exe")
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    assert cli._doctor() == 0
    checks = json.loads(capsys.readouterr().out)
    assert checks == {
        "environment": "test",
        "data_dir_writable": True,
        "ffmpeg": True,
        "ffprobe": True,
        "tesseract": True,
        "llm_enabled": False,
        "production_embeddings": False,
        "external_qdrant": False,
        "duckdb": True,
        "qdrant": True,
    }
    container.close.assert_called_once_with()


def test_doctor_returns_failure_for_required_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = doctor_settings(tmp_path)
    container = doctor_container(index_healthy=False)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli.shutil, "which", lambda _executable: None)
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    assert cli._doctor() == 1
    container.close.assert_called_once_with()


def invoke_main(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
    monkeypatch.setattr(sys, "argv", ["crisisweave", *arguments])
    cli.main()


def test_serve_invokes_uvicorn_with_proxy_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(trust_proxy_headers=True, forwarded_allow_ips="10.0.0.1")
    run = MagicMock()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli.uvicorn, "run", run)

    invoke_main(monkeypatch, "serve", "--host", "192.0.2.1", "--port", "8080")

    run.assert_called_once_with(
        "crisisweave.api:app",
        host="192.0.2.1",
        port=8080,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.1",
    )


def test_serve_rejects_multiple_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: SimpleNamespace(trust_proxy_headers=False, forwarded_allow_ips="127.0.0.1"),
    )
    with pytest.raises(SystemExit, match="exactly one"):
        invoke_main(monkeypatch, "serve", "--workers", "2")


def test_parser_worker_builds_isolated_app(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace()
    app = object()
    run = MagicMock()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr("crisisweave.parser_service.create_parser_app", lambda value: app)
    monkeypatch.setattr(cli.uvicorn, "run", run)

    invoke_main(monkeypatch, "parser-worker", "--host", "192.0.2.1", "--port", "9001")

    run.assert_called_once_with(
        app,
        host="192.0.2.1",
        port=9001,
        workers=1,
        proxy_headers=False,
    )


def test_ingestion_worker_owns_parser_scratch_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = object()
    jobs = SimpleNamespace(process_next=MagicMock(return_value=False), close=MagicMock())
    ingestion = SimpleNamespace(object_store=object())
    container = SimpleNamespace(ingestion=ingestion, close=MagicMock())
    build = MagicMock(return_value=container)
    create_jobs = MagicMock(return_value=jobs)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_ingestion_worker_container", build)
    monkeypatch.setattr("crisisweave.jobs.create_job_service", create_jobs)
    configure_telemetry = MagicMock(return_value=False)
    monkeypatch.setattr(cli, "configure_telemetry", configure_telemetry)

    invoke_main(monkeypatch, "ingestion-worker", "--once")

    configure_telemetry.assert_called_once_with(settings)
    build.assert_called_once_with(settings)
    create_jobs.assert_called_once_with(settings, ingestion, ingestion.object_store)
    jobs.process_next.assert_called_once_with()
    jobs.close.assert_called_once_with()
    container.close.assert_called_once_with()


def test_ingestion_worker_periodically_runs_bounded_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OneIterationEvent:
        def __init__(self) -> None:
            self.checks = 0

        def is_set(self) -> bool:
            self.checks += 1
            return self.checks > 1

        def set(self) -> None:
            self.checks = 2

        def wait(self, _timeout: float) -> None:
            return

    settings = SimpleNamespace(reconciliation_interval_seconds=5.0)
    jobs = SimpleNamespace(process_next=MagicMock(return_value=False), close=MagicMock())
    ingestion = SimpleNamespace(object_store=object(), reconcile=MagicMock())
    container = SimpleNamespace(ingestion=ingestion, close=MagicMock())
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_ingestion_worker_container", lambda _settings: container)
    monkeypatch.setattr("crisisweave.jobs.create_job_service", lambda *_args: jobs)
    monkeypatch.setattr(cli, "configure_telemetry", MagicMock(return_value=False))
    monkeypatch.setattr(cli.threading, "Event", OneIterationEvent)
    monkeypatch.setattr(cli.time, "monotonic", MagicMock(side_effect=[0.0, 5.0]))
    monkeypatch.setattr(cli.signal, "getsignal", lambda _signal: object())
    monkeypatch.setattr(cli.signal, "signal", MagicMock())

    invoke_main(monkeypatch, "ingestion-worker")

    jobs.process_next.assert_called_once_with()
    ingestion.reconcile.assert_called_once_with()
    jobs.close.assert_called_once_with()
    container.close.assert_called_once_with()


def test_ingestion_worker_starts_and_stops_configured_metrics_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(
        worker_metrics_host="0.0.0.0",  # noqa: S104 - verifies the explicit worker bind
        worker_metrics_port=9100,
        reconciliation_interval_seconds=60.0,
    )
    jobs = SimpleNamespace(process_next=MagicMock(return_value=True), close=MagicMock())
    ingestion = SimpleNamespace(object_store=object())
    container = SimpleNamespace(ingestion=ingestion, close=MagicMock())
    server = object()
    start = MagicMock(return_value=server)
    stop = MagicMock()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_ingestion_worker_container", lambda _settings: container)
    monkeypatch.setattr("crisisweave.jobs.create_job_service", lambda *_args: jobs)
    monkeypatch.setattr(cli, "configure_telemetry", MagicMock(return_value=True))
    monkeypatch.setattr(cli, "start_worker_metrics_server", start)
    monkeypatch.setattr(cli, "stop_worker_metrics_server", stop)

    invoke_main(monkeypatch, "ingestion-worker", "--once")

    start.assert_called_once_with("0.0.0.0", 9100)  # noqa: S104 - expected bind
    stop.assert_called_once_with(server)


def test_migrate_uses_privileged_database_and_qdrant_schema_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dsn = SimpleNamespace(get_secret_value=lambda: "postgresql://migrator.invalid/app")
    settings = SimpleNamespace(
        app_env="production",
        runtime_role="migration",
        postgres_dsn=dsn,
        postgres_api_role="crisisweave_api",
        postgres_worker_role="crisisweave_worker",
        postgres_pool_timeout_seconds=4.0,
        postgres_rls_enabled=True,
    )
    migrate = MagicMock()
    embedder = object()
    index = SimpleNamespace(healthcheck=MagicMock(return_value=True), close=MagicMock())
    index_factory = MagicMock(return_value=index)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "migrate_postgres", migrate)
    monkeypatch.setattr(cli, "build_embedder", lambda _settings: embedder)
    monkeypatch.setattr(cli, "EvidenceIndex", index_factory)

    invoke_main(monkeypatch, "migrate")

    migrate.assert_called_once_with(
        "postgresql://migrator.invalid/app",
        api_role="crisisweave_api",
        worker_role="crisisweave_worker",
        timeout_seconds=4.0,
        enable_rls=True,
    )
    index_factory.assert_called_once_with(settings, embedder, provision_schema=True)
    index.healthcheck.assert_called_once_with()
    index.close.assert_called_once_with()
    assert capsys.readouterr().out == "PostgreSQL and Qdrant migrations completed.\n"


def test_migrate_rejects_non_migration_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: SimpleNamespace(app_env="production", runtime_role="api"),
    )
    with pytest.raises(SystemExit, match="runtime_role=migration"):
        invoke_main(monkeypatch, "migrate")


def test_doctor_command_exits_with_doctor_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_doctor", lambda: 7)
    with pytest.raises(SystemExit) as raised:
        invoke_main(monkeypatch, "doctor")
    assert raised.value.code == 7


def command_container() -> SimpleNamespace:
    return SimpleNamespace(
        ingestion=SimpleNamespace(ingest_path=MagicMock()),
        agent=SimpleNamespace(ask=MagicMock()),
        close=MagicMock(),
    )


def test_ingest_command_passes_tenant_and_source_metadata(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    path = tmp_path / "report.txt"
    path.write_text("field report", encoding="utf-8")
    container = command_container()
    container.ingestion.ingest_path.return_value = JsonResult({"document_id": "doc-1"})
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    invoke_main(
        monkeypatch,
        "ingest",
        str(path),
        "--tenant",
        "response-team",
        "--source-uri",
        "local://report",
    )

    container.ingestion.ingest_path.assert_called_once_with(
        path.resolve(),
        tenant_id=tenant_identifier("response-team"),
        filename="report.txt",
        source_uri="local://report",
    )
    assert json.loads(capsys.readouterr().out) == {"document_id": "doc-1"}
    container.close.assert_called_once_with()


def test_ingest_missing_file_still_closes_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    container = command_container()
    missing = tmp_path / "missing.pdf"
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    with pytest.raises(SystemExit, match="File does not exist"):
        invoke_main(monkeypatch, "ingest", str(missing))
    container.ingestion.ingest_path.assert_not_called()
    container.close.assert_called_once_with()


def test_query_command_builds_validated_request_and_closes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    container = command_container()
    received: list[tuple[str, QueryRequest]] = []

    async def ask(tenant_id: str, request: QueryRequest) -> JsonResult:
        received.append((tenant_id, request))
        return JsonResult({"answer": "Flooding is reported."})

    container.agent.ask = ask
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    invoke_main(
        monkeypatch,
        "query",
        "Where is flooding?",
        "--tenant",
        "response-team",
        "--allow-web",
        "--top-k",
        "4",
    )

    assert len(received) == 1
    tenant_id, request = received[0]
    assert tenant_id == tenant_identifier("response-team")
    assert request.query == "Where is flooding?"
    assert request.allow_web is True
    assert request.top_k == 4
    assert json.loads(capsys.readouterr().out) == {"answer": "Flooding is reported."}
    container.close.assert_called_once_with()


def test_command_container_closes_when_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    container = command_container()

    async def fail(_tenant_id: str, _request: QueryRequest) -> Any:
        raise RuntimeError("query failed")

    container.agent.ask = fail
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    monkeypatch.setattr(cli, "build_container", lambda _settings: container)

    with pytest.raises(RuntimeError, match="query failed"):
        invoke_main(monkeypatch, "query", "Where is flooding?")
    container.close.assert_called_once_with()
