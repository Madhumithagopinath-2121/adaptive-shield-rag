"""ChromaDB vector store service for security-gated knowledge segregation.

Maintains strict physical separation between trusted and quarantined knowledge.
Enforces the core security invariant:
- SAFE documents -> Trusted collection
- QUARANTINE documents -> Quarantined collection
- BLOCK documents -> Never inserted into any vector collection
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.models.document import Document
from app.models.knowledge import (
    KnowledgeDocumentItem,
    KnowledgeIndexResult,
    KnowledgeStatsResult,
    StorageDestination,
)
from app.models.security_decision import SecurityDecision


def resolve_vector_db_dir(dir_path: Optional[str] = None) -> Path:
    """Resolve vector store directory, ensuring parent directories exist."""
    path_val = dir_path or settings.vector_db_dir
    target = Path(path_val)
    if not target.is_absolute():
        backend_dir = Path(__file__).resolve().parent.parent.parent
        project_root = backend_dir.parent
        target = (project_root / target).resolve()

    target.mkdir(parents=True, exist_ok=True)
    return target


class ChromaVectorStore:
    """ChromaDB manager supporting security-gated knowledge collections."""

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        trusted_collection_name: Optional[str] = None,
        quarantine_collection_name: Optional[str] = None,
        embedding_model_name: Optional[str] = None,
    ):
        self.persist_dir = resolve_vector_db_dir(persist_dir)
        self.trusted_collection_name = (
            trusted_collection_name or settings.trusted_collection_name
        )
        self.quarantine_collection_name = (
            quarantine_collection_name or settings.quarantine_collection_name
        )
        self.embedding_model_name = (
            embedding_model_name or settings.embedding_model_name
        )
        self._client = None
        self._trusted_collection = None
        self._quarantine_collection = None

    @property
    def client(self):
        """Lazy load ChromaDB persistent client."""
        if self._client is None:
            import chromadb

            self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        return self._client

    @property
    def trusted_collection(self):
        """Collection containing ONLY verified SAFE knowledge."""
        if self._trusted_collection is None:
            self._trusted_collection = self.client.get_or_create_collection(
                name=self.trusted_collection_name,
                metadata={"description": "Verified trusted knowledge corpus"},
            )
        return self._trusted_collection

    @property
    def quarantine_collection(self):
        """Isolated collection containing QUARANTINED knowledge."""
        if self._quarantine_collection is None:
            self._quarantine_collection = self.client.get_or_create_collection(
                name=self.quarantine_collection_name,
                metadata={"description": "Isolated quarantined knowledge corpus"},
            )
        return self._quarantine_collection

    def index_document(
        self,
        document: Document,
        decision: SecurityDecision,
        risk_score: float,
        embedding: List[float],
    ) -> KnowledgeIndexResult:
        """Index document into appropriate collection based on security decision."""
        # 1. Reject BLOCK documents unconditionally
        if decision == SecurityDecision.BLOCK:
            return KnowledgeIndexResult(
                document_id=document.id,
                decision=decision,
                risk_score=risk_score,
                storage_destination=StorageDestination.NONE.value,
                indexed=False,
                reason="Document classified as BLOCK; strictly rejected from all vector storage.",
            )

        # 2. Determine target collection
        if decision == SecurityDecision.SAFE:
            target_collection = self.trusted_collection
            target_destination = StorageDestination.TRUSTED.value
            alternate_collection = self.quarantine_collection
        elif decision == SecurityDecision.QUARANTINE:
            target_collection = self.quarantine_collection
            target_destination = StorageDestination.QUARANTINE.value
            alternate_collection = self.trusted_collection
        else:
            return KnowledgeIndexResult(
                document_id=document.id,
                decision=decision,
                risk_score=risk_score,
                storage_destination=StorageDestination.NONE.value,
                indexed=False,
                reason=f"Unrecognized security decision '{decision}'; rejected from vector storage.",
            )

        # 3. Prevent duplicate indexing in target collection
        existing = target_collection.get(ids=[document.id])
        if existing and existing.get("ids"):
            return KnowledgeIndexResult(
                document_id=document.id,
                decision=decision,
                risk_score=risk_score,
                storage_destination=target_destination,
                indexed=False,
                reason=f"Document '{document.id}' is already indexed in the {target_destination} collection.",
            )

        # If document exists in alternate collection, remove it to maintain segregation
        alt_existing = alternate_collection.get(ids=[document.id])
        if alt_existing and alt_existing.get("ids"):
            alternate_collection.delete(ids=[document.id])

        # 4. Prepare metadata
        metadata: Dict[str, Any] = {
            "document_id": document.id,
            "title": document.title,
            "source": document.source,
            "source_type": document.source_type,
            "timestamp": document.timestamp.isoformat(),
            "decision": decision.value,
            "risk_score": float(risk_score),
        }

        # 5. Insert into target collection
        target_collection.add(
            ids=[document.id],
            embeddings=[embedding],
            documents=[document.content],
            metadatas=[metadata],
        )

        return KnowledgeIndexResult(
            document_id=document.id,
            decision=decision,
            risk_score=risk_score,
            storage_destination=target_destination,
            indexed=True,
            reason=f"Document successfully indexed into {target_destination} collection.",
        )

    def get_document(self, document_id: str) -> Optional[KnowledgeDocumentItem]:
        """Look up document across trusted and quarantine collections."""
        # Check trusted collection first
        res = self.trusted_collection.get(
            ids=[document_id], include=["documents", "metadatas"]
        )
        if res and res.get("ids") and len(res["ids"]) > 0:
            doc_text = res["documents"][0] if res.get("documents") else ""
            meta = res["metadatas"][0] if res.get("metadatas") else {}
            return KnowledgeDocumentItem(
                document_id=document_id,
                storage_destination=StorageDestination.TRUSTED.value,
                title=meta.get("title", ""),
                content=doc_text,
                source=meta.get("source", ""),
                source_type=meta.get("source_type", ""),
                timestamp=meta.get("timestamp", ""),
                decision=meta.get("decision", SecurityDecision.SAFE.value),
                risk_score=float(meta.get("risk_score", 0.0)),
                metadata=meta,
            )

        # Check quarantine collection
        res = self.quarantine_collection.get(
            ids=[document_id], include=["documents", "metadatas"]
        )
        if res and res.get("ids") and len(res["ids"]) > 0:
            doc_text = res["documents"][0] if res.get("documents") else ""
            meta = res["metadatas"][0] if res.get("metadatas") else {}
            return KnowledgeDocumentItem(
                document_id=document_id,
                storage_destination=StorageDestination.QUARANTINE.value,
                title=meta.get("title", ""),
                content=doc_text,
                source=meta.get("source", ""),
                source_type=meta.get("source_type", ""),
                timestamp=meta.get("timestamp", ""),
                decision=meta.get("decision", SecurityDecision.QUARANTINE.value),
                risk_score=float(meta.get("risk_score", 0.0)),
                metadata=meta,
            )

        return None

    def get_stats(self) -> KnowledgeStatsResult:
        """Return counts and configuration across vector collections."""
        trusted_count = self.trusted_collection.count()
        quarantine_count = self.quarantine_collection.count()
        return KnowledgeStatsResult(
            trusted_count=trusted_count,
            quarantine_count=quarantine_count,
            total_indexed=trusted_count + quarantine_count,
            storage_backend="chromadb",
            embedding_model=self.embedding_model_name,
            trusted_collection=self.trusted_collection_name,
            quarantine_collection=self.quarantine_collection_name,
        )
