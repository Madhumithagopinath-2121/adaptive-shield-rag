"""Security analysis models and schema definitions."""

from typing import List
from pydantic import BaseModel, Field


class SecurityAnalysisResult(BaseModel):
    """Normalized security signal analysis result for an ingested document.

    Note: This schema represents intermediate heuristic security indicators.
    It does not compute an overall risk score or render triage decisions
    (SAFE / QUARANTINE / BLOCK).
    """

    document_id: str = Field(
        ...,
        description="Unique identifier of the analyzed document",
    )
    injection_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Heuristic prompt-injection / instruction-like content score (0.0=none, 1.0=strong)",
    )
    source_risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Source risk score based on source provenance and type (0.0=high trust, 1.0=untrusted)",
    )
    content_anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Heuristic structural and content anomaly score (0.0=typical text, 1.0=anomalous structure)",
    )
    signals: List[str] = Field(
        default_factory=list,
        description="List of detected signal category codes",
    )
    explanations: List[str] = Field(
        default_factory=list,
        description="Human-readable explanations of detected security signals",
    )
