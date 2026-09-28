"""Attack simulation and synthetic knowledge stream API routes."""

from typing import Optional
from fastapi import APIRouter, Depends, status

from app.api.documents import get_ingestion_service
from app.api.knowledge import get_knowledge_service
from app.api.security import get_threat_state_engine
from app.models.simulation import (
    SimulationRequest,
    SimulationResult,
    SimulationStatusResponse,
)
from app.services.ingestion import IngestionService
from app.services.knowledge.knowledge_service import KnowledgeService
from app.services.security.threat_state import ThreatStateEngine
from app.services.simulation.simulator import AttackSimulatorService

router = APIRouter(prefix="/simulation", tags=["Attack Simulator"])

_shared_simulator: Optional[AttackSimulatorService] = None


def get_simulation_service(
    ingestion_service: IngestionService = Depends(get_ingestion_service),
    knowledge_service: KnowledgeService = Depends(get_knowledge_service),
    threat_engine: ThreatStateEngine = Depends(get_threat_state_engine),
) -> AttackSimulatorService:
    """Dependency provider maintaining shared simulator state across requests."""
    global _shared_simulator
    if _shared_simulator is None or _shared_simulator.db_path != ingestion_service.db_path:
        _shared_simulator = AttackSimulatorService(
            ingestion_service=ingestion_service,
            knowledge_service=knowledge_service,
            threat_state_engine=threat_engine,
            db_path=ingestion_service.db_path,
        )
    else:
        _shared_simulator.ingestion_service = ingestion_service
        _shared_simulator.knowledge_service = knowledge_service
        _shared_simulator.threat_state_engine = threat_engine
    return _shared_simulator


@router.post(
    "/start",
    response_model=SimulationResult,
    status_code=status.HTTP_200_OK,
    summary="Start synthetic stream attack simulation",
    description=(
        "Generates a controlled sequence of synthetic documents (normal, attack, or mixed) "
        "and routes them through the existing ingestion, security assessment, and "
        "segregated vector indexing pipeline."
    ),
)
def start_simulation(
    payload: SimulationRequest,
    simulator: AttackSimulatorService = Depends(get_simulation_service),
) -> SimulationResult:
    """Execute synthetic stream simulation through the live defense pipeline."""
    return simulator.run_simulation(payload)


@router.get(
    "/status",
    response_model=SimulationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get simulation status and latest summary",
    description="Returns whether a simulation is currently active and the most recent run summary.",
)
def get_simulation_status(
    simulator: AttackSimulatorService = Depends(get_simulation_service),
) -> SimulationStatusResponse:
    """Retrieve current simulator state and the latest available simulation result."""
    return simulator.get_status()
