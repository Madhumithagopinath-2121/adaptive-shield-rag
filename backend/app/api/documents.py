"""Document ingestion and retrieval API routes."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.models.document import (
    Document,
    DocumentCreate,
    DocumentStatusUpdate,
)
from app.services.ingestion import IngestionService

router = APIRouter(prefix="/documents", tags=["Documents"])


def get_ingestion_service() -> IngestionService:
    """Dependency provider for IngestionService."""
    return IngestionService()


@router.post(
    "",
    response_model=Document,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new document",
    description="Ingests a new document into local storage with initial status PENDING.",
)
def ingest_document(
    payload: DocumentCreate,
    service: IngestionService = Depends(get_ingestion_service),
) -> Document:
    """Ingest a new incoming document with initial PENDING status."""
    return service.ingest_document(payload)


@router.get(
    "",
    response_model=List[Document],
    summary="List recent documents",
    description="Retrieve recent documents ordered by ingestion timestamp descending.",
)
def list_documents(
    limit: int = Query(50, ge=1, le=500, description="Max documents to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    service: IngestionService = Depends(get_ingestion_service),
) -> List[Document]:
    """Retrieve recent documents with pagination."""
    return service.list_documents(limit=limit, offset=offset)


@router.get(
    "/{document_id}",
    response_model=Document,
    summary="Retrieve document by ID",
    description="Retrieve details and content for a single document by unique identifier.",
)
def get_document(
    document_id: str,
    service: IngestionService = Depends(get_ingestion_service),
) -> Document:
    """Retrieve a single document by ID or return 404 if not found."""
    doc = service.get_document(document_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' not found",
        )
    return doc


@router.patch(
    "/{document_id}/status",
    response_model=Document,
    summary="Update document status",
    description="Update a document's verification status for testing persistence.",
)
def update_status(
    document_id: str,
    payload: DocumentStatusUpdate,
    service: IngestionService = Depends(get_ingestion_service),
) -> Document:
    """Update document status or return 404 if not found."""
    doc = service.update_document_status(document_id, payload.status)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' not found",
        )
    return doc
