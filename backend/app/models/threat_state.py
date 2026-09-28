"""Adaptive threat state and stream observation models."""

from enum import Enum
from pydantic import BaseModel, Field


class ThreatState(str, Enum):
    """Observable operational threat state of the incoming knowledge stream."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatStateResult(BaseModel):
    """Rolling window threat state observation and attack-velocity metrics.

    Note: This is an observation of stream conditions and does NOT dynamically
    alter decision thresholds or document status in this MVP phase.
    """

    state: ThreatState = Field(
        ...,
        description="Current observable stream threat state",
    )
    window_size: int = Field(
        ...,
        ge=0,
        description="Number of assessments observed in the active rolling window",
    )
    total_assessed: int = Field(
        ...,
        ge=0,
        description="Total assessments evaluated in the active rolling window",
    )
    safe_count: int = Field(
        ...,
        ge=0,
        description="Number of SAFE assessments in the window",
    )
    quarantine_count: int = Field(
        ...,
        ge=0,
        description="Number of QUARANTINE assessments in the window",
    )
    block_count: int = Field(
        ...,
        ge=0,
        description="Number of BLOCK assessments in the window",
    )
    block_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Proportion of BLOCK decisions within window [0.0, 1.0]",
    )
    quarantine_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Proportion of QUARANTINE decisions within window [0.0, 1.0]",
    )
    attack_velocity: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Proportion of suspicious (QUARANTINE + BLOCK) decisions within window [0.0, 1.0]",
    )
    average_risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Average composite risk score across assessments in window [0.0, 1.0]",
    )
    state_reason: str = Field(
        ...,
        description="Human-readable explanation of current threat state metrics",
    )
