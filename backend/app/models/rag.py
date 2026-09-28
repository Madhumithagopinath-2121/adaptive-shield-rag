"""Pydantic data models for trust-aware retrieval and RAG query pipeline."""

from typing import List, Optional
from pydantic import BaseModel, Field


class RetrievalRequest(BaseModel):
    """Request payload for trust-aware knowledge retrieval."""

    query: str = Field(
        ...,
        min_length=1,
        description="Natural-language search query to retrieve relevant trusted knowledge.",
        examples=["What is the corporate MFA policy?"],
    )
    top_k: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum number of trusted documents to retrieve.",
    )


class RetrievalResultItem(BaseModel):
    """Individual retrieved document item from the trusted knowledge collection."""

    document_id: str
    title: str
    content: str
    source: str
    source_type: str
    timestamp: str
    decision: str = "SAFE"
    risk_score: float
    distance: Optional[float] = None


class RetrievalResponse(BaseModel):
    """Response payload containing trusted retrieval results."""

    query: str
    retrieved_count: int
    results: List[RetrievalResultItem]


class RAGQueryRequest(BaseModel):
    """Request payload for RAG question answering."""

    query: str = Field(
        ...,
        min_length=1,
        description="Natural-language question to be answered using trusted knowledge.",
        examples=["What is the employee MFA requirement?"],
    )
    top_k: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum number of trusted documents to retrieve as context.",
    )


class RAGSourceItem(BaseModel):
    """Source reference included in a RAG answer."""

    document_id: str
    title: str
    content: str
    source: str
    source_type: str
    timestamp: str
    decision: str = "SAFE"
    risk_score: float
    distance: Optional[float] = None


class RAGQueryResponse(BaseModel):
    """Response payload containing generated answer and cited trusted sources."""

    query: str
    answer: str
    sources: List[RAGSourceItem]
    retrieved_count: int
