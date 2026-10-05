from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from crisisweave.ingestion import IngestionService
from crisisweave.models import Document, DocumentStatus


class FakeStore:
    def __init__(self, documents: list[Document]) -> None:
        self.documents = {document.id: document for document in documents}
        self.list_calls = 0

    def list_documents(self, tenant_id: str, limit: int) -> list[Document]:
        self.list_calls += 1
        return [
            document for document in self.documents.values() if document.tenant_id == tenant_id
        ][:limit]

    def mark_document(
        self,
        tenant_id: str,
        document_id: str,
        status: DocumentStatus,
    ) -> None:
        document = self.documents[document_id]
        assert document.tenant_id == tenant_id
        self.documents[document_id] = document.model_copy(update={"status": status})

    @contextmanager
    def tenant_lock(self, _tenant_id: str) -> Iterator[None]:
        yield


def test_delete_all_processes_more_than_the_public_listing_limit() -> None:
    tenant_id = "a" * 64
    documents = [
        Document(
            id=f"document-{index}",
            tenant_id=tenant_id,
            filename=f"evidence-{index}.txt",
            media_type="text/plain",
            sha256=f"{index:064x}",
            size_bytes=1,
            status=DocumentStatus.READY,
        )
        for index in range(501)
    ]
    store = FakeStore(documents)
    service = object.__new__(IngestionService)
    service.store = store
    service._tenant_locks = (threading.RLock(),)

    deleted_statuses: list[DocumentStatus] = []

    def delete_locked(document: Document) -> bool:
        deleted_statuses.append(document.status)
        del store.documents[document.id]
        return True

    service._delete_locked = delete_locked  # type: ignore[method-assign]

    assert service.delete_all(tenant_id) == 501
    assert store.documents == {}
    assert store.list_calls == 3
    assert set(deleted_statuses) == {DocumentStatus.DELETING}
