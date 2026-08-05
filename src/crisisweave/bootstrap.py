"""The sole dependency-composition root for API, CLI, and tests."""

from __future__ import annotations

import asyncio
import importlib.util
import shutil
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from crisisweave.agent import CrisisAgent
from crisisweave.config import Settings
from crisisweave.embeddings import Embedder, build_embedder
from crisisweave.execution import BlockingRunner
from crisisweave.extractors import Extractor
from crisisweave.ingestion import IngestionService
from crisisweave.llm import ModelGateway
from crisisweave.object_store import ObjectStore, build_object_store
from crisisweave.postgres_storage import PostgresMetadataStore
from crisisweave.reranking import Reranker, build_reranker
from crisisweave.security import verify_malware_scanner
from crisisweave.storage import MetadataStore, MetadataStoreProtocol
from crisisweave.vector_store import EvidenceIndex
from crisisweave.web_search import WebSearch


@dataclass
class Container:
    settings: Settings
    store: MetadataStoreProtocol
    object_store: ObjectStore
    embedder: Embedder
    index: EvidenceIndex
    reranker: Reranker
    ingestion: IngestionService
    agent: CrisisAgent
    blocking_runner: BlockingRunner

    def close(self) -> None:
        self.blocking_runner.close()
        self.index.close()
        self.store.close()
        self.object_store.close()


@dataclass
class IngestionWorkerContainer:
    settings: Settings
    store: MetadataStoreProtocol
    object_store: ObjectStore
    embedder: Embedder
    index: EvidenceIndex
    ingestion: IngestionService

    def close(self) -> None:
        self.index.close()
        self.store.close()
        self.object_store.close()


def _verify_production_runtime(settings: Settings, *, query_runtime: bool) -> None:
    if settings.app_env != "production":
        return
    models = [
        ("text embedding", settings.text_embedding_model),
        ("visual embedding", settings.visual_embedding_model),
    ]
    if query_runtime:
        models.append(("reranker", settings.reranker_model))
    else:
        required_executables = {
            "ffmpeg": settings.ffmpeg_path,
            "ffprobe": settings.ffprobe_path,
            "tesseract": settings.tesseract_path,
        }
        if settings.malware_scanner_path:
            required_executables["malware scanner"] = settings.malware_scanner_path
        missing = [
            name
            for name, executable in required_executables.items()
            if not executable
            or not (
                Path(executable).is_file()
                if Path(executable).is_absolute()
                else shutil.which(executable)
            )
        ]
        if missing:
            raise RuntimeError(f"Missing production executables: {', '.join(missing)}")
        if importlib.util.find_spec("faster_whisper") is None:
            raise RuntimeError("The production transcription dependency is unavailable")
        models.append(("transcription", settings.whisper_model))
    missing_models = [name for name, path in models if not Path(path).is_dir()]
    if missing_models:
        raise RuntimeError(f"Missing preloaded production models: {', '.join(missing_models)}")
    if not settings.model_bundle_manifest or not settings.model_bundle_manifest.is_file():
        raise RuntimeError("The production model bundle manifest is unavailable")
    if not query_runtime:
        verify_malware_scanner(settings)


def _build_metadata_store(settings: Settings) -> MetadataStoreProtocol:
    if settings.database_backend == "postgresql":
        if settings.postgres_dsn is None:
            raise RuntimeError("The PostgreSQL backend requires a DSN")
        return PostgresMetadataStore(
            settings.postgres_dsn.get_secret_value(),
            pool_min_size=settings.postgres_pool_min_size,
            pool_max_size=settings.postgres_pool_max_size,
            pool_timeout_seconds=settings.postgres_pool_timeout_seconds,
            audit_retention_days=settings.audit_retention_days,
            max_audit_rows=settings.max_audit_rows,
            analytics_timeout_seconds=settings.analytics_timeout_seconds,
            max_analytics_result_bytes=settings.max_analytics_result_bytes,
            max_analytics_cell_bytes=settings.max_analytics_cell_bytes,
            rls_enabled=settings.postgres_rls_enabled,
            migrate_on_startup=settings.app_env != "production",
        )
    return MetadataStore(
        settings.database_path,
        audit_retention_days=settings.audit_retention_days,
        max_audit_rows=settings.max_audit_rows,
        analytics_timeout_seconds=settings.analytics_timeout_seconds,
        max_analytics_result_bytes=settings.max_analytics_result_bytes,
        max_analytics_cell_bytes=settings.max_analytics_cell_bytes,
    )


def build_container(settings: Settings) -> Container:
    if settings.app_env == "production" and settings.runtime_role != "api":
        raise RuntimeError("The API container requires runtime_role=api")
    # Production API replicas must never run global reconciliation; that duty belongs
    # only to the dedicated ingestion-worker role.
    reconcile_on_startup = settings.app_env != "production" and settings.ingestion_worker_enabled
    settings.ensure_directories()
    _verify_production_runtime(settings, query_runtime=True)
    with ExitStack() as cleanup:
        object_store = build_object_store(settings)
        cleanup.callback(object_store.close)
        model = ModelGateway(settings, object_store)
        if settings.app_env == "production" and settings.provider_canary_on_startup:
            asyncio.run(model.verify_capabilities())
        store = _build_metadata_store(settings)
        cleanup.callback(store.close)
        embedder = build_embedder(settings)
        index = EvidenceIndex(settings, embedder)
        cleanup.callback(index.close)
        reranker = build_reranker(settings)
        extractor = Extractor(settings)
        ingestion = IngestionService(
            settings,
            store,
            index,
            extractor,
            object_store,
            reconcile_on_startup=reconcile_on_startup,
        )
        web = WebSearch(settings)
        blocking_runner = BlockingRunner(settings.max_concurrent_queries)
        cleanup.callback(blocking_runner.close)
        agent = CrisisAgent(settings, store, index, reranker, model, web, blocking_runner)
        container = Container(
            settings=settings,
            store=store,
            object_store=object_store,
            embedder=embedder,
            index=index,
            reranker=reranker,
            ingestion=ingestion,
            agent=agent,
            blocking_runner=blocking_runner,
        )
        cleanup.pop_all()
        return container


def build_ingestion_worker_container(settings: Settings) -> IngestionWorkerContainer:
    """Build only the dependencies required to lease, parse, and index ingestion jobs."""
    if settings.app_env == "production" and settings.runtime_role != "ingestion_worker":
        raise RuntimeError("The ingestion worker requires runtime_role=ingestion_worker")
    settings.ensure_directories()
    _verify_production_runtime(settings, query_runtime=False)
    with ExitStack() as cleanup:
        object_store = build_object_store(settings)
        cleanup.callback(object_store.close)
        store = _build_metadata_store(settings)
        cleanup.callback(store.close)
        embedder = build_embedder(settings)
        index = EvidenceIndex(settings, embedder)
        cleanup.callback(index.close)
        extractor = Extractor(settings)
        ingestion = IngestionService(
            settings,
            store,
            index,
            extractor,
            object_store,
            reconcile_on_startup=True,
        )
        container = IngestionWorkerContainer(
            settings=settings,
            store=store,
            object_store=object_store,
            embedder=embedder,
            index=index,
            ingestion=ingestion,
        )
        cleanup.pop_all()
        return container
