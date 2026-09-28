"""Document models and status enums for ingestion."""

from datetime import datetime, timezone
from enum import Enum
import uuid
from pydantic import BaseModel, ConfigDict, Field


class DocumentStatus(str, Enum):
    """Lifecycle status of an ingested document."""

    PENDING = "PENDING"
    SAFE = "SAFE"
    QUARANTINE = "QUARANTINE"
    BLOCKED = "BLOCKED"


class DocumentCreate(BaseModel):
    """Schema for ingesting an incoming document."""

    title: str = Field(..., min_length=1, description="Title of the incoming document")
    content: str = Field(
        ...,
        min_length=1,
        description="Raw untrusted content of the document",
    )
    source: str = Field(
        ...,
        min_length=1,
        description="Origin identifier (e.g., URL, file path, feed ID)",
    )
    source_type: str = Field(
        ...,
        min_length=1,
        description="Type of source (e.g., 'web', 'wiki', 'ticket', 'api')",
    )


class DocumentStatusUpdate(BaseModel):
    """Schema for updating a document's lifecycle status."""

    status: DocumentStatus


class Document(BaseModel):
    """Schema representing a stored document record."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique document identifier",
    )
    title: str
    content: str
    source: str
    source_type: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC ingestion timestamp",
    )
    status: DocumentStatus = Field(
        default=DocumentStatus.PENDING,
        description="Current verification status. Initial status is always PENDING.",
    )

    model_config = ConfigDict(from_attributes=True)
