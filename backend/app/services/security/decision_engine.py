"""Decision engine for composite risk assessment and triage.

Evaluates aggregated security signals, computes normalized composite risk,
and maps the result to SAFE, QUARANTINE, or BLOCK decisions against
configurable thresholds.
"""

from typing import List, Optional

from app.config import settings
from app.models.security import SecurityAnalysisResult
from app.models.security_decision import (
    SecurityDecision,
    SecurityDecisionResult,
)
from app.services.security.risk_scorer import CompositeRiskScorer


class DecisionEngine:
    """Evaluates composite risk scores and produces explainable triage decisions."""

    def __init__(
        self,
        risk_scorer: Optional[CompositeRiskScorer] = None,
        threshold_quarantine: Optional[float] = None,
        threshold_block: Optional[float] = None,
    ):
        self.risk_scorer = risk_scorer or CompositeRiskScorer()
        self.threshold_quarantine = (
            threshold_quarantine
            if threshold_quarantine is not None
            else settings.risk_threshold_quarantine
        )
        self.threshold_block = (
            threshold_block
            if threshold_block is not None
            else settings.risk_threshold_block
        )

        if not (0.0 <= self.threshold_quarantine < self.threshold_block <= 1.0):
            raise ValueError(
                f"Invalid thresholds: must satisfy 0.0 <= quarantine ({self.threshold_quarantine}) "
                f"< block ({self.threshold_block}) <= 1.0"
            )

    def evaluate_decision(self, risk_score: float) -> SecurityDecision:
        """Map composite risk score to triage decision based on configured thresholds."""
        if risk_score >= self.threshold_block:
            return SecurityDecision.BLOCK
        elif risk_score >= self.threshold_quarantine:
            return SecurityDecision.QUARANTINE
        else:
            return SecurityDecision.SAFE

    def assess(
        self, analysis: SecurityAnalysisResult
    ) -> SecurityDecisionResult:
        """Calculate composite risk, evaluate decision, and format explainability log."""
        risk_score = self.risk_scorer.calculate_risk(
            injection_score=analysis.injection_score,
            source_risk_score=analysis.source_risk_score,
            content_anomaly_score=analysis.content_anomaly_score,
        )
        decision = self.evaluate_decision(risk_score)

        explanations: List[str] = list(analysis.explanations)

        # Synthesize component contributions
        if analysis.injection_score >= 0.70:
            explanations.append(
                f"Injection score is high ({analysis.injection_score:.2f}), indicating multiple instruction-like indicators."
            )
        elif analysis.injection_score >= 0.40:
            explanations.append(
                f"Injection score is elevated ({analysis.injection_score:.2f}), indicating instruction-like patterns."
            )

        if analysis.source_risk_score >= 0.80:
            explanations.append(
                f"Source risk is high ({analysis.source_risk_score:.2f}) because the document originated from an unverified or low-trust source."
            )
        elif analysis.source_risk_score <= 0.20:
            explanations.append(
                f"Source risk is low ({analysis.source_risk_score:.2f}) originating from a verified high-trust source."
            )

        if analysis.content_anomaly_score >= 0.35:
            explanations.append(
                f"Content anomaly is elevated ({analysis.content_anomaly_score:.2f}) due to structural markers or repetition."
            )

        # Decision rationale
        if decision == SecurityDecision.BLOCK:
            explanations.append(
                f"Composite risk score ({risk_score:.2f}) met or exceeded the BLOCK threshold ({self.threshold_block:.2f}). Decision: BLOCK."
            )
        elif decision == SecurityDecision.QUARANTINE:
            explanations.append(
                f"Composite risk score ({risk_score:.2f}) reached the QUARANTINE threshold range [{self.threshold_quarantine:.2f}, {self.threshold_block:.2f}). Decision: QUARANTINE."
            )
        else:
            explanations.append(
                f"Composite risk score ({risk_score:.2f}) remained below the QUARANTINE threshold ({self.threshold_quarantine:.2f}). Decision: SAFE."
            )

        return SecurityDecisionResult(
            document_id=analysis.document_id,
            injection_score=analysis.injection_score,
            source_risk_score=analysis.source_risk_score,
            content_anomaly_score=analysis.content_anomaly_score,
            risk_score=risk_score,
            decision=decision,
            signals=analysis.signals,
            explanations=explanations,
        )
