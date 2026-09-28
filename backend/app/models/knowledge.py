"""Knowledge storage and vector indexing models."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from app.models.security_decision import SecurityDecision


class StorageDestination(str, Enum):
    """Destination store for knowledge documents based on security triage."""

    TRUSTED = "trusted"
    QUARANTINE = "quarantine"
    NONE = "none"


class KnowledgeIndexResult(BaseModel):
    """Response returned when indexing a document into vector storage."""

    document_id: str = Field(
        ...,
        description="Unique identifier of the indexed document",
    )
    decision: SecurityDecision = Field(
        ...,
        description="Security decision evaluated for the document (SAFE, QUARANTINE, BLOCK)",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite risk score evaluated for the document",
    )
    storage_destination: str = Field(
        ...,
        description="Storage destination: 'trusted', 'quarantine', or 'none'",
    )
    indexed: bool = Field(
        ...,
        description="Whether the document was successfully added to vector storage",
    )
    reason: str = Field(
        ...,
        description="Explanation of indexing decision or rejection reason",
    )


class KnowledgeStatsResult(BaseModel):
    """Aggregate statistics for vector collections and knowledge segregation."""

    trusted_count: int = Field(
        ...,
        ge=0,
        description="Number of SAFE documents indexed in trusted vector store",
    )
    quarantine_count: int = Field(
        ...,
        ge=0,
        description="Number of QUARANTINE documents stored in isolated quarantine store",
    )
    total_indexed: int = Field(
        ...,
        ge=0,
        description="Total documents across all vector collections",
    )
    storage_backend: str = Field(
        default="chromadb",
        description="Vector database backend provider",
    )
    embedding_model: str = Field(
        ...,
        description="Embedding model used for vectorization",
    )
    trusted_collection: str = Field(
        ...,
        description="Identifier of the trusted collection",
    )
    quarantine_collection: str = Field(
        ...,
        description="Identifier of the isolated quarantine collection",
    )


class KnowledgeDocumentItem(BaseModel):
    """Record retrieved from vector storage collections."""

    document_id: str = Field(..., description="Unique document identifier")
    storage_destination: str = Field(
        ...,
        description="Collection where document is stored ('trusted' or 'quarantine')",
    )
    title: str = Field(..., description="Document title")
    content: str = Field(..., description="Document content text")
    source: str = Field(..., description="Document source identifier")
    source_type: str = Field(..., description="Document source type category")
    timestamp: str = Field(..., description="Ingestion or assessment timestamp")
    decision: str = Field(..., description="Security decision associated with document")
    risk_score: float = Field(..., description="Composite risk score associated with document")
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Raw metadata stored alongside vector embedding",
    )
