"""Ingestion service responsible for validating and persisting incoming documents.

Note: This service only handles document ingestion and storage.
It does NOT perform security analysis, risk scoring, or LLM interactions.
"""

from datetime import datetime, timezone
from typing import List, Optional
import uuid

from app.database import (
    get_document_by_id,
    get_recent_documents,
    insert_document,
    update_document_status,
)
from app.models.document import Document, DocumentCreate, DocumentStatus


class IngestionService:
    """Service handling document ingestion and retrieval."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def ingest_document(self, payload: DocumentCreate) -> Document:
        """Validate, construct, and persist an incoming document.

        Newly ingested documents are always initialized with status PENDING.
        """
        doc = Document(
            id=str(uuid.uuid4()),
            title=payload.title.strip(),
            content=payload.content,
            source=payload.source.strip(),
            source_type=payload.source_type.strip(),
            timestamp=datetime.now(timezone.utc),
            status=DocumentStatus.PENDING,
        )
        return insert_document(doc, db_path=self.db_path)

    def get_document(self, document_id: str) -> Optional[Document]:
        """Retrieve a stored document by ID."""
        return get_document_by_id(document_id, db_path=self.db_path)

    def list_documents(self, limit: int = 50, offset: int = 0) -> List[Document]:
        """Retrieve recent documents ordered by ingestion time descending."""
        return get_recent_documents(limit=limit, offset=offset, db_path=self.db_path)

    def update_document_status(
        self, document_id: str, new_status: DocumentStatus
    ) -> Optional[Document]:
        """Update lifecycle status of a document (e.g., for persistence testing)."""
        return update_document_status(
            document_id, new_status, db_path=self.db_path
        )
