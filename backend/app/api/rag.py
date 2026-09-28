"""RAG and trust-aware retrieval API routes."""

from fastapi import APIRouter, Depends, status

from app.models.rag import (
    RAGQueryRequest,
    RAGQueryResponse,
    RetrievalRequest,
    RetrievalResponse,
)
from app.services.rag.rag_service import RAGService

router = APIRouter(prefix="/rag", tags=["RAG & Retrieval"])


def get_rag_service() -> RAGService:
    """Dependency provider for RAGService."""
    return RAGService()


@router.post(
    "/retrieve",
    response_model=RetrievalResponse,
    status_code=status.HTTP_200_OK,
    summary="Trust-aware knowledge retrieval",
    description=(
        "Retrieves top-k relevant knowledge items strictly and exclusively from "
        "the trusted SAFE vector collection. Quarantined, blocked, or unverified "
        "documents are never retrieved."
    ),
)
def retrieve_trusted_knowledge(
    payload: RetrievalRequest,
    service: RAGService = Depends(get_rag_service),
) -> RetrievalResponse:
    """Retrieve trusted knowledge items for a natural-language query."""
    return service.retrieve(query=payload.query, top_k=payload.top_k)


@router.post(
    "/query",
    response_model=RAGQueryResponse,
    status_code=status.HTTP_200_OK,
    summary="Trust-aware RAG question answering",
    description=(
        "Executes complete RAG pipeline: retrieves trusted SAFE context, constructs "
        "a grounded prompt, and generates an answer using configured LLM (with graceful "
        "fallback if no LLM provider is configured)."
    ),
)
def rag_query(
    payload: RAGQueryRequest,
    service: RAGService = Depends(get_rag_service),
) -> RAGQueryResponse:
    """Execute complete RAG question answering with verified trusted context."""
    return service.query(query=payload.query, top_k=payload.top_k)
