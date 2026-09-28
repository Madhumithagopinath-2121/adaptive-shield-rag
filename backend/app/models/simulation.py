"""Pydantic data models for the attack simulator and live stream simulation."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SimulationMode(str, Enum):
    """Operation mode for synthetic knowledge stream generation."""

    NORMAL = "normal"
    ATTACK = "attack"
    MIXED = "mixed"


class SimulationRequest(BaseModel):
    """Request payload to initiate a controlled stream simulation."""

    mode: SimulationMode = Field(
        default=SimulationMode.MIXED,
        description="Stream simulation mode: 'normal' (mostly safe), 'attack' (mostly suspicious/blocked), 'mixed' (balanced).",
        examples=["attack"],
    )
    document_count: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of synthetic documents to generate and stream through the pipeline.",
    )
    attack_ratio: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Proportion of suspicious/attack documents (0.0 to 1.0). If omitted, standard ratio for the mode is used.",
    )
    delay_ms: int = Field(
        default=0,
        ge=0,
        le=5000,
        description="Delay in milliseconds between successive documents to simulate arrival cadence.",
    )


class SimulationDocumentItem(BaseModel):
    """Summary of an individual simulated document's triage outcome."""

    document_id: str
    title: str
    source: str
    decision: str
    risk_score: float
    storage_destination: str


class SimulationResult(BaseModel):
    """Comprehensive summary of a completed simulation run."""

    simulation_id: str
    mode: str
    total_generated: int
    safe_count: int
    quarantine_count: int
    block_count: int
    average_risk_score: float
    current_threat_state: str
    attack_velocity: float
    duration_ms: float
    documents: List[SimulationDocumentItem] = []


class SimulationStatusResponse(BaseModel):
    """Status indicating whether a simulation is running and the latest result."""

    is_running: bool
    latest_simulation: Optional[SimulationResult] = None
