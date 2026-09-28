"""RAG orchestration service coordinating retrieval, context construction, and generation."""

from typing import Optional

from app.models.rag import (
    RAGQueryResponse,
    RAGSourceItem,
    RetrievalResponse,
)
from app.services.knowledge.embedding_service import EmbeddingService
from app.services.knowledge.vector_store import ChromaVectorStore
from app.services.rag.context_builder import ContextBuilder
from app.services.rag.generator import RAGGenerator
from app.services.rag.retrieval_service import TrustAwareRetriever


class RAGService:
    """Orchestrator for trust-aware retrieval and secure RAG queries."""

    def __init__(
        self,
        retriever: Optional[TrustAwareRetriever] = None,
        context_builder: Optional[ContextBuilder] = None,
        generator: Optional[RAGGenerator] = None,
        vector_store: Optional[ChromaVectorStore] = None,
        embedding_service: Optional[EmbeddingService] = None,
    ):
        v_store = vector_store or ChromaVectorStore()
        emb_svc = embedding_service or EmbeddingService()

        self.retriever = retriever or TrustAwareRetriever(
            vector_store=v_store,
            embedding_service=emb_svc,
        )
        self.context_builder = context_builder or ContextBuilder()
        self.generator = generator or RAGGenerator(
            context_builder=self.context_builder,
        )

    def retrieve(self, query: str, top_k: int = 5) -> RetrievalResponse:
        """Execute trust-aware retrieval against the trusted knowledge store."""
        results = self.retriever.retrieve(query=query, top_k=top_k)
        return RetrievalResponse(
            query=query,
            retrieved_count=len(results),
            results=results,
        )

    def query(self, query: str, top_k: int = 5) -> RAGQueryResponse:
        """Run complete RAG workflow: retrieve trusted docs -> build context -> generate answer."""
        retrieved_items = self.retriever.retrieve(query=query, top_k=top_k)
        context = self.context_builder.build_context(retrieved_items)
        answer = self.generator.generate(
            query=query,
            retrieval_items=retrieved_items,
            context=context,
        )

        sources = [
            RAGSourceItem(
                document_id=item.document_id,
                title=item.title,
                content=item.content,
                source=item.source,
                source_type=item.source_type,
                timestamp=item.timestamp,
                decision=item.decision,
                risk_score=item.risk_score,
                distance=item.distance,
            )
            for item in retrieved_items
        ]

        return RAGQueryResponse(
            query=query,
            answer=answer,
            sources=sources,
            retrieved_count=len(sources),
        )
