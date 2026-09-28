"""Security decision models and triage schemas."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class SecurityDecision(str, Enum):
    """Triage decision resulting from composite risk evaluation."""

    SAFE = "SAFE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class SecurityDecisionResult(BaseModel):
    """Composite risk assessment and triage decision result.

    Preserves individual security signal components while providing the
    normalized composite risk score and explainable decision outcome.
    """

    document_id: str = Field(
        ...,
        description="Unique identifier of the assessed document",
    )
    injection_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Heuristic prompt-injection / instruction indicator score",
    )
    source_risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Source provenance risk score",
    )
    content_anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Structural and content anomaly score",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite risk score normalized to [0.0, 1.0]",
    )
    decision: SecurityDecision = Field(
        ...,
        description="Triage decision: SAFE, QUARANTINE, or BLOCK",
    )
    signals: List[str] = Field(
        default_factory=list,
        description="Aggregated signal categories from detectors",
    )
    explanations: List[str] = Field(
        default_factory=list,
        description="Human-readable explanations of risk contributions and final decision",
    )
