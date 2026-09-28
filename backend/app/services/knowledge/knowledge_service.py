"""Knowledge management service orchestrating security-gated vector indexing.

Receives document ingestion IDs, obtains or performs security assessments,
and indexes documents into segregated vector stores based on triage decisions:
- SAFE -> Trusted collection
- QUARANTINE -> Quarantine collection
- BLOCK -> Rejected from vector storage
"""

from typing import Optional

from app.database import get_db_connection, record_security_assessment
from app.models.document import Document
from app.models.knowledge import (
    KnowledgeDocumentItem,
    KnowledgeIndexResult,
    KnowledgeStatsResult,
)
from app.models.security_decision import SecurityDecision
from app.services.ingestion import IngestionService
from app.services.knowledge.embedding_service import EmbeddingService
from app.services.knowledge.vector_store import ChromaVectorStore
from app.services.security.decision_engine import DecisionEngine
from app.services.security.security_analyzer import SecurityAnalyzer


class KnowledgeService:
    """Coordinates security evaluation, embedding computation, and vector indexing."""

    def __init__(
        self,
        ingestion_service: Optional[IngestionService] = None,
        security_analyzer: Optional[SecurityAnalyzer] = None,
        decision_engine: Optional[DecisionEngine] = None,
        vector_store: Optional[ChromaVectorStore] = None,
        embedding_service: Optional[EmbeddingService] = None,
        db_path: Optional[str] = None,
    ):
        self.db_path = db_path
        self.ingestion_service = ingestion_service or IngestionService(
            db_path=db_path
        )
        self.security_analyzer = security_analyzer or SecurityAnalyzer()
        self.decision_engine = decision_engine or DecisionEngine()
        self.vector_store = vector_store or ChromaVectorStore()
        self.embedding_service = embedding_service or EmbeddingService()

    def get_latest_assessment(self, document_id: str) -> Optional[dict]:
        """Fetch the most recent security assessment for a document if one exists."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT id, document_id, risk_score, decision, timestamp
                FROM security_assessments
                WHERE document_id = ?
                ORDER BY timestamp DESC
                LIMIT 1;
                """,
                (document_id,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "document_id": row["document_id"],
                    "risk_score": float(row["risk_score"]),
                    "decision": row["decision"],
                    "timestamp": row["timestamp"],
                }
        return None

    def index_document(self, document_id: str) -> Optional[KnowledgeIndexResult]:
        """Assess and index a document into segregated vector storage."""
        # 1. Fetch document record
        document: Optional[Document] = self.ingestion_service.get_document(
            document_id
        )
        if document is None:
            return None

        # 2. Obtain existing security assessment or execute assessment
        assessment = self.get_latest_assessment(document_id)
        if assessment:
            decision = SecurityDecision(assessment["decision"])
            risk_score = float(assessment["risk_score"])
        else:
            # If not assessed yet, evaluate now and record assessment
            analysis_res = self.security_analyzer.analyze_document(document)
            decision_res = self.decision_engine.assess(analysis_res)
            decision = decision_res.decision
            risk_score = decision_res.risk_score

            record_security_assessment(
                document_id=document.id,
                risk_score=risk_score,
                decision=decision.value,
                db_path=self.db_path,
            )

        # 3. Handle BLOCK documents immediately without embedding computation
        if decision == SecurityDecision.BLOCK:
            return self.vector_store.index_document(
                document=document,
                decision=decision,
                risk_score=risk_score,
                embedding=[],
            )

        # 4. Generate local dense embedding for SAFE or QUARANTINE documents
        embedding = self.embedding_service.embed_text(document.content)

        # 5. Index into designated collection
        return self.vector_store.index_document(
            document=document,
            decision=decision,
            risk_score=risk_score,
            embedding=embedding,
        )

    def get_document(self, document_id: str) -> Optional[KnowledgeDocumentItem]:
        """Look up indexed knowledge document across vector collections."""
        return self.vector_store.get_document(document_id)

    def get_stats(self) -> KnowledgeStatsResult:
        """Retrieve aggregated storage statistics."""
        return self.vector_store.get_stats()
