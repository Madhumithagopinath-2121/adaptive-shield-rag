"""Security signal analysis, risk assessment, and threat state API routes."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.documents import get_ingestion_service
from app.database import record_security_assessment
from app.models.security import SecurityAnalysisResult
from app.models.security_decision import SecurityDecisionResult
from app.models.threat_state import ThreatStateResult
from app.services.ingestion import IngestionService
from app.services.security.decision_engine import DecisionEngine
from app.services.security.security_analyzer import SecurityAnalyzer
from app.services.security.threat_state import ThreatStateEngine

router = APIRouter(prefix="/security", tags=["Security Signals & Decisions"])


def get_security_analyzer() -> SecurityAnalyzer:
    """Dependency provider for SecurityAnalyzer."""
    return SecurityAnalyzer()


def get_decision_engine() -> DecisionEngine:
    """Dependency provider for DecisionEngine."""
    return DecisionEngine()


def get_threat_state_engine(
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> ThreatStateEngine:
    """Dependency provider for ThreatStateEngine bound to active DB path."""
    return ThreatStateEngine(db_path=ingestion_service.db_path)


@router.post(
    "/analyze/{document_id}",
    response_model=SecurityAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze document security signals",
    description=(
        "Executes heuristic security detectors (prompt-injection indicators, "
        "source trust evaluation, structural anomalies) on an existing document. "
        "Does NOT alter document status or apply a triage decision."
    ),
)
def analyze_document_security(
    document_id: str,
    ingestion_service: IngestionService = Depends(get_ingestion_service),
    security_analyzer: SecurityAnalyzer = Depends(get_security_analyzer),
) -> SecurityAnalysisResult:
    """Run security signal analysis against a persisted document."""
    document = ingestion_service.get_document(document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' not found",
        )

    # Perform signal analysis without altering document state or status
    result = security_analyzer.analyze_document(document)
    return result


@router.post(
    "/assess/{document_id}",
    response_model=SecurityDecisionResult,
    status_code=status.HTTP_200_OK,
    summary="Assess document security risk and evaluate triage decision",
    description=(
        "Executes security signal analysis, calculates an explainable composite risk score, "
        "and evaluates the triage decision (SAFE, QUARANTINE, BLOCK). "
        "Records the assessment occurrence in history without modifying document status."
    ),
)
def assess_document_security(
    document_id: str,
    ingestion_service: IngestionService = Depends(get_ingestion_service),
    security_analyzer: SecurityAnalyzer = Depends(get_security_analyzer),
    decision_engine: DecisionEngine = Depends(get_decision_engine),
) -> SecurityDecisionResult:
    """Assess composite security risk, evaluate triage decision, and record assessment."""
    document = ingestion_service.get_document(document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' not found",
        )

    analysis_result = security_analyzer.analyze_document(document)
    decision_result = decision_engine.assess(analysis_result)

    # Record assessment history without mutating document.status
    record_security_assessment(
        document_id=document.id,
        risk_score=decision_result.risk_score,
        decision=decision_result.decision.value,
        db_path=ingestion_service.db_path,
    )

    return decision_result


@router.get(
    "/threat-state",
    response_model=ThreatStateResult,
    status_code=status.HTTP_200_OK,
    summary="Get current stream threat state",
    description=(
        "Returns current observable stream threat state and attack-velocity metrics "
        "evaluated over the configured rolling observation window."
    ),
)
def get_current_threat_state(
    threat_engine: ThreatStateEngine = Depends(get_threat_state_engine),
) -> ThreatStateResult:
    """Retrieve current operational threat state observation for the stream."""
    return threat_engine.get_current_threat_state()
