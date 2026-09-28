"""Trust-aware retrieval service.

Enforces the core security invariant for RAG retrieval:
The retriever MUST query ONLY the trusted SAFE vector collection.
Never retrieve from quarantine collections, blocked documents, or raw SQLite tables.
"""

from typing import List, Optional

from app.models.rag import RetrievalResultItem
from app.services.knowledge.embedding_service import EmbeddingService
from app.services.knowledge.vector_store import ChromaVectorStore


class TrustAwareRetriever:
    """Retrieves relevant knowledge strictly and exclusively from the trusted collection."""

    def __init__(
        self,
        vector_store: Optional[ChromaVectorStore] = None,
        embedding_service: Optional[EmbeddingService] = None,
    ):
        self.vector_store = vector_store or ChromaVectorStore()
        self.embedding_service = embedding_service or EmbeddingService()

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievalResultItem]:
        """Query the trusted vector collection for top_k relevant documents.
        
        Guaranteed:
        - NEVER accesses quarantine collection
        - NEVER accesses blocked documents
        - Queries only the trusted collection
        """
        if not query or not query.strip():
            return []

        if top_k <= 0:
            return []

        # Access ONLY the trusted collection
        trusted_coll = self.vector_store.trusted_collection

        # Safe guard against querying an empty collection
        try:
            total_count = trusted_coll.count()
        except Exception:
            return []

        if total_count == 0:
            return []

        n_results = min(top_k, total_count)

        # Generate query embedding
        query_embedding = self.embedding_service.embed_text(query)

        # Query trusted collection
        query_res = trusted_coll.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )

        if not query_res or not query_res.get("ids") or len(query_res["ids"]) == 0:
            return []

        ids = query_res["ids"][0]
        docs = (
            query_res["documents"][0]
            if query_res.get("documents")
            else [""] * len(ids)
        )
        metas = (
            query_res["metadatas"][0]
            if query_res.get("metadatas")
            else [{}] * len(ids)
        )
        distances = (
            query_res["distances"][0]
            if query_res.get("distances")
            else [None] * len(ids)
        )

        results: List[RetrievalResultItem] = []
        for doc_id, doc_text, meta, dist in zip(ids, docs, metas, distances):
            meta_dict = meta or {}
            results.append(
                RetrievalResultItem(
                    document_id=doc_id,
                    title=meta_dict.get("title", ""),
                    content=doc_text or "",
                    source=meta_dict.get("source", ""),
                    source_type=meta_dict.get("source_type", ""),
                    timestamp=meta_dict.get("timestamp", ""),
                    decision=meta_dict.get("decision", "SAFE"),
                    risk_score=float(meta_dict.get("risk_score", 0.0)),
                    distance=round(float(dist), 4) if dist is not None else None,
                )
            )

        return results
