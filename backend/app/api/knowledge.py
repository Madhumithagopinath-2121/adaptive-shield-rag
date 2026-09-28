"""Knowledge storage and vector indexing API routes."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.documents import get_ingestion_service
from app.models.knowledge import (
    KnowledgeDocumentItem,
    KnowledgeIndexResult,
    KnowledgeStatsResult,
)
from app.services.ingestion import IngestionService
from app.services.knowledge.knowledge_service import KnowledgeService

router = APIRouter(prefix="/knowledge", tags=["Knowledge Storage"])


def get_knowledge_service(
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> KnowledgeService:
    """Dependency provider for KnowledgeService."""
    return KnowledgeService(
        ingestion_service=ingestion_service,
        db_path=ingestion_service.db_path,
    )


@router.post(
    "/index/{document_id}",
    response_model=KnowledgeIndexResult,
    status_code=status.HTTP_200_OK,
    summary="Index document into security-gated vector storage",
    description=(
        "Obtains security triage decision for the specified document and routes it "
        "to the appropriate collection: SAFE -> Trusted, QUARANTINE -> Quarantine, "
        "BLOCK -> Rejected from vector storage."
    ),
)
def index_document(
    document_id: str,
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeIndexResult:
    """Index a document into segregated vector storage."""
    result = service.index_document(document_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' not found",
        )
    return result


@router.get(
    "/stats",
    response_model=KnowledgeStatsResult,
    status_code=status.HTTP_200_OK,
    summary="Get vector storage collection statistics",
    description="Returns document counts and segregation statistics for trusted and quarantined collections.",
)
def get_knowledge_stats(
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeStatsResult:
    """Retrieve vector storage collection statistics."""
    return service.get_stats()


@router.get(
    "/{document_id}",
    response_model=KnowledgeDocumentItem,
    status_code=status.HTTP_200_OK,
    summary="Retrieve indexed document by ID from vector storage",
    description="Looks up an indexed document across trusted and quarantine vector collections.",
)
def get_indexed_document(
    document_id: str,
    service: KnowledgeService = Depends(get_knowledge_service),
) -> KnowledgeDocumentItem:
    """Retrieve a document stored in vector collections."""
    item = service.get_document(document_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge document with ID '{document_id}' not found in vector storage",
        )
    return item
