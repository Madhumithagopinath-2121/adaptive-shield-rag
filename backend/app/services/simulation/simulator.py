"""Attack simulator service generating synthetic streams through the live pipeline."""

import time
import uuid
from typing import List, Optional

from app.models.document import DocumentCreate
from app.models.security_decision import SecurityDecision
from app.models.simulation import (
    SimulationDocumentItem,
    SimulationMode,
    SimulationRequest,
    SimulationResult,
    SimulationStatusResponse,
)
from app.services.ingestion import IngestionService
from app.services.knowledge.knowledge_service import KnowledgeService
from app.services.security.threat_state import ThreatStateEngine
from app.services.simulation.templates import (
    BLOCK_TEMPLATES,
    QUARANTINE_TEMPLATES,
    SAFE_TEMPLATES,
)


class AttackSimulatorService:
    """Orchestrates controlled generation of synthetic knowledge streams.
    
    Feeds synthetic documents into the real, existing ingestion -> security triage ->
    threat state -> vector segregation pipeline without modifying thresholds or
    duplicating security logic.
    """

    def __init__(
        self,
        ingestion_service: Optional[IngestionService] = None,
        knowledge_service: Optional[KnowledgeService] = None,
        threat_state_engine: Optional[ThreatStateEngine] = None,
        db_path: Optional[str] = None,
    ):
        self.db_path = db_path
        self.ingestion_service = ingestion_service or IngestionService(db_path=db_path)
        self.knowledge_service = knowledge_service or KnowledgeService(
            ingestion_service=self.ingestion_service,
            db_path=db_path,
        )
        self.threat_state_engine = threat_state_engine or ThreatStateEngine(
            db_path=db_path
        )
        self._is_running = False
        self._latest_simulation: Optional[SimulationResult] = None

    def get_status(self) -> SimulationStatusResponse:
        """Return the current simulator running state and latest summary."""
        return SimulationStatusResponse(
            is_running=self._is_running,
            latest_simulation=self._latest_simulation,
        )

    def _select_document_sequence(
        self,
        mode: SimulationMode,
        document_count: int,
        attack_ratio: Optional[float] = None,
    ) -> List[dict]:
        """Build deterministic sequence of template dictionaries according to mode and ratio."""
        if attack_ratio is not None:
            ratio = max(0.0, min(1.0, float(attack_ratio)))
        else:
            if mode == SimulationMode.NORMAL:
                ratio = 0.10
            elif mode == SimulationMode.ATTACK:
                ratio = 0.80
            else:
                ratio = 0.50

        num_suspicious = int(round(document_count * ratio))
        num_safe = document_count - num_suspicious

        # Determine breakdown between QUARANTINE and BLOCK
        if mode == SimulationMode.NORMAL:
            num_quarantine = num_suspicious
            num_block = 0
        else:
            num_block = num_suspicious // 2
            num_quarantine = num_suspicious - num_block

        # Gather templates cyclically
        safe_pool = [
            SAFE_TEMPLATES[i % len(SAFE_TEMPLATES)] for i in range(num_safe)
        ]
        quarantine_pool = [
            QUARANTINE_TEMPLATES[i % len(QUARANTINE_TEMPLATES)]
            for i in range(num_quarantine)
        ]
        block_pool = [
            BLOCK_TEMPLATES[i % len(BLOCK_TEMPLATES)] for i in range(num_block)
        ]

        # Interleave realistically
        sequence = []
        if mode == SimulationMode.NORMAL:
            # Mostly safe, occasional quarantine
            s_idx, q_idx = 0, 0
            for i in range(document_count):
                if q_idx < num_quarantine and (i % max(1, document_count // max(1, num_quarantine)) == 0):
                    sequence.append(quarantine_pool[q_idx])
                    q_idx += 1
                elif s_idx < num_safe:
                    sequence.append(safe_pool[s_idx])
                    s_idx += 1
                elif q_idx < num_quarantine:
                    sequence.append(quarantine_pool[q_idx])
                    q_idx += 1
        elif mode == SimulationMode.ATTACK:
            # Attack bursts with high block and quarantine density
            s_idx, q_idx, b_idx = 0, 0, 0
            for i in range(document_count):
                if b_idx < num_block and i % 2 == 0:
                    sequence.append(block_pool[b_idx])
                    b_idx += 1
                elif q_idx < num_quarantine:
                    sequence.append(quarantine_pool[q_idx])
                    q_idx += 1
                elif b_idx < num_block:
                    sequence.append(block_pool[b_idx])
                    b_idx += 1
                elif s_idx < num_safe:
                    sequence.append(safe_pool[s_idx])
                    s_idx += 1
        else:
            # Balanced mixed mode
            s_idx, q_idx, b_idx = 0, 0, 0
            for i in range(document_count):
                if s_idx < num_safe and i % 2 == 0:
                    sequence.append(safe_pool[s_idx])
                    s_idx += 1
                elif q_idx < num_quarantine:
                    sequence.append(quarantine_pool[q_idx])
                    q_idx += 1
                elif b_idx < num_block:
                    sequence.append(block_pool[b_idx])
                    b_idx += 1
                elif s_idx < num_safe:
                    sequence.append(safe_pool[s_idx])
                    s_idx += 1

        return sequence[:document_count]

    def run_simulation(self, request: SimulationRequest) -> SimulationResult:
        """Execute stream simulation sequentially through the existing pipeline."""
        self._is_running = True
        start_time = time.perf_counter()

        sim_id = str(uuid.uuid4())
        mode_val = (
            request.mode.value
            if isinstance(request.mode, SimulationMode)
            else str(request.mode)
        )

        template_sequence = self._select_document_sequence(
            mode=request.mode,
            document_count=request.document_count,
            attack_ratio=request.attack_ratio,
        )

        safe_count = 0
        quarantine_count = 0
        block_count = 0
        total_risk = 0.0
        doc_summaries: List[SimulationDocumentItem] = []

        try:
            for idx, item in enumerate(template_sequence, start=1):
                # 1. Ingest via existing IngestionService
                doc_create = DocumentCreate(
                    title=f"{item['title']} [Sim #{idx}]",
                    content=item["content"],
                    source=item["source"],
                    source_type=item["source_type"],
                )
                document = self.ingestion_service.ingest_document(doc_create)

                # 2. Assess and index via existing KnowledgeService
                # (evaluates security signals, records assessment in DB, and segregates vector store)
                index_result = self.knowledge_service.index_document(document.id)

                if index_result:
                    decision_str = index_result.decision.value
                    risk_val = index_result.risk_score
                    dest_str = index_result.storage_destination

                    total_risk += risk_val
                    if index_result.decision == SecurityDecision.SAFE:
                        safe_count += 1
                    elif index_result.decision == SecurityDecision.QUARANTINE:
                        quarantine_count += 1
                    elif index_result.decision == SecurityDecision.BLOCK:
                        block_count += 1

                    doc_summaries.append(
                        SimulationDocumentItem(
                            document_id=document.id,
                            title=document.title,
                            source=document.source,
                            decision=decision_str,
                            risk_score=round(risk_val, 4),
                            storage_destination=dest_str,
                        )
                    )

                # Cadence delay if requested
                if request.delay_ms > 0:
                    time.sleep(request.delay_ms / 1000.0)

            # 3. Observe resulting stream threat state via existing ThreatStateEngine
            threat_state = self.threat_state_engine.get_current_threat_state()

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            avg_risk = (
                total_risk / len(doc_summaries) if doc_summaries else 0.0
            )

            result = SimulationResult(
                simulation_id=sim_id,
                mode=mode_val,
                total_generated=len(doc_summaries),
                safe_count=safe_count,
                quarantine_count=quarantine_count,
                block_count=block_count,
                average_risk_score=round(avg_risk, 4),
                current_threat_state=threat_state.state.value,
                attack_velocity=round(threat_state.attack_velocity, 4),
                duration_ms=round(duration_ms, 2),
                documents=doc_summaries,
            )

            self._latest_simulation = result
            return result

        finally:
            self._is_running = False
