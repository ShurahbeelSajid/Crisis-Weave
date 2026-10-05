"""Operational command line entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import signal
import threading
import time
from pathlib import Path

import uvicorn

from crisisweave.auth import tenant_identifier
from crisisweave.bootstrap import build_container, build_ingestion_worker_container
from crisisweave.config import get_settings
from crisisweave.embeddings import build_embedder
from crisisweave.models import QueryRequest
from crisisweave.observability import (
    configure_telemetry,
    start_worker_metrics_server,
    stop_worker_metrics_server,
)
from crisisweave.postgres_migrations import migrate_postgres
from crisisweave.vector_store import EvidenceIndex

LOGGER = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crisisweave", description="CrisisWeave operations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the FastAPI service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--workers", type=int, default=1)

    parser_worker = subparsers.add_parser(
        "parser-worker", help="Run the isolated media parser service"
    )
    parser_worker.add_argument("--host", default="127.0.0.1")
    parser_worker.add_argument("--port", type=int, default=8001)

    ingestion_worker = subparsers.add_parser(
        "ingestion-worker",
        help="Run the durable PostgreSQL/S3 ingestion worker",
    )
    ingestion_worker.add_argument(
        "--once",
        action="store_true",
        help="Process at most one available job and exit",
    )

    subparsers.add_parser(
        "migrate",
        help="Apply PostgreSQL and Qdrant schema changes with the privileged migration role",
    )

    ingest = subparsers.add_parser("ingest", help="Ingest one local file")
    ingest.add_argument("path", type=Path)
    ingest.add_argument("--tenant", default="default")
    ingest.add_argument("--source-uri")

    query = subparsers.add_parser("query", help="Run a query")
    query.add_argument("question")
    query.add_argument("--tenant", default="default")
    query.add_argument("--allow-web", action="store_true")
    query.add_argument("--top-k", type=int, default=8)

    subparsers.add_parser("doctor", help="Check configuration and external executables")
    return parser


def _doctor() -> int:
    settings = get_settings()
    checks = {
        "environment": settings.app_env,
        "data_dir_writable": settings.data_dir.exists() and settings.data_dir.is_dir(),
        "ffmpeg": shutil.which(settings.ffmpeg_path) is not None,
        "ffprobe": shutil.which(settings.ffprobe_path) is not None,
        "tesseract": shutil.which(settings.tesseract_path) is not None,
        "llm_enabled": settings.llm_provider != "disabled",
        "production_embeddings": settings.embedding_provider != "hash",
        "external_qdrant": bool(settings.qdrant_url),
    }
    container = build_container(settings)
    database_backend = getattr(settings, "database_backend", "duckdb")
    object_store = getattr(container, "object_store", None)
    try:
        checks[database_backend] = container.store.healthcheck()
        checks["qdrant"] = container.index.healthcheck()
        if object_store is not None:
            checks["object_store"] = object_store.healthcheck()
    finally:
        container.close()
    print(json.dumps(checks, indent=2))
    required = ["data_dir_writable", database_backend, "qdrant"]
    if object_store is not None:
        required.append("object_store")
    return 0 if all(checks[item] for item in required) else 1


def main() -> None:
    args = _parser().parse_args()
    if args.command == "migrate":
        settings = get_settings()
        if settings.app_env != "production" or settings.runtime_role != "migration":
            raise SystemExit("Migrations require app_env=production and runtime_role=migration")
        if settings.postgres_dsn is None:
            raise SystemExit("Migrations require a PostgreSQL DSN")
        if not settings.postgres_api_role or not settings.postgres_worker_role:
            raise SystemExit("Migrations require explicit PostgreSQL API and worker role names")
        migrate_postgres(
            settings.postgres_dsn.get_secret_value(),
            api_role=settings.postgres_api_role,
            worker_role=settings.postgres_worker_role,
            timeout_seconds=settings.postgres_pool_timeout_seconds,
            enable_rls=settings.postgres_rls_enabled,
        )
        embedder = build_embedder(settings)
        index = EvidenceIndex(settings, embedder, provision_schema=True)
        try:
            if not index.healthcheck():
                raise SystemExit("Qdrant schema migration did not become ready")
        finally:
            index.close()
        print("PostgreSQL and Qdrant migrations completed.")
        return
    if args.command == "serve":
        settings = get_settings()
        if args.workers < 1:
            raise SystemExit("API workers must be at least one")
        if args.workers != 1 and getattr(settings, "database_backend", "duckdb") != "postgresql":
            raise SystemExit("DuckDB metadata and in-process limits require exactly one API worker")
        uvicorn.run(
            "crisisweave.api:app",
            host=args.host,
            port=args.port,
            workers=args.workers,
            proxy_headers=settings.trust_proxy_headers,
            forwarded_allow_ips=settings.forwarded_allow_ips,
        )
        return
    if args.command == "parser-worker":
        from crisisweave.parser_service import create_parser_app

        settings = get_settings()
        uvicorn.run(
            create_parser_app(settings),
            host=args.host,
            port=args.port,
            workers=1,
            proxy_headers=False,
        )
        return
    if args.command == "ingestion-worker":
        from crisisweave.jobs import create_job_service

        settings = get_settings()
        configure_telemetry(settings)
        worker_metrics_port = int(getattr(settings, "worker_metrics_port", 0))
        metrics_server = None
        worker_container = None
        jobs = None
        stop = threading.Event()
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def request_stop(_signum: int, _frame: object) -> None:
            stop.set()

        try:
            worker_container = build_ingestion_worker_container(settings)
            jobs = create_job_service(
                settings,
                worker_container.ingestion,
                worker_container.ingestion.object_store,
            )
            if worker_metrics_port:
                metrics_server = start_worker_metrics_server(
                    str(getattr(settings, "worker_metrics_host", "127.0.0.1")),
                    worker_metrics_port,
                )
            if args.once:
                jobs.process_next()
                return
            signal.signal(signal.SIGTERM, request_stop)
            next_reconciliation = time.monotonic() + settings.reconciliation_interval_seconds
            while not stop.is_set():
                processed = jobs.process_next()
                now = time.monotonic()
                if now >= next_reconciliation:
                    try:
                        worker_container.ingestion.reconcile()
                    except Exception:
                        LOGGER.exception("bounded ingestion reconciliation failed")
                    next_reconciliation = now + settings.reconciliation_interval_seconds
                if not processed:
                    stop.wait(0.25)
        except KeyboardInterrupt:
            stop.set()
            return
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
            if jobs is not None:
                jobs.close()
            if worker_container is not None:
                worker_container.close()
            stop_worker_metrics_server(metrics_server)
        return
    if args.command == "doctor":
        raise SystemExit(_doctor())

    settings = get_settings()
    container = build_container(settings)
    try:
        tenant_id = tenant_identifier(args.tenant)
        if args.command == "ingest":
            path = args.path.resolve()
            if not path.is_file():
                raise SystemExit(f"File does not exist: {path}")
            ingestion_result = container.ingestion.ingest_path(
                path,
                tenant_id=tenant_id,
                filename=path.name,
                source_uri=args.source_uri,
            )
            print(ingestion_result.model_dump_json(indent=2))
        elif args.command == "query":
            query_result = asyncio.run(
                container.agent.ask(
                    tenant_id,
                    QueryRequest(query=args.question, allow_web=args.allow_web, top_k=args.top_k),
                )
            )
            print(query_result.model_dump_json(indent=2))
    finally:
        container.close()


if __name__ == "__main__":
    main()
