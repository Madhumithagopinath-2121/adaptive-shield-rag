"""Security analyzer coordinator service.

Aggregates individual heuristic detectors (prompt injection, source trust,
content anomalies) into a unified SecurityAnalysisResult.

IMPORTANT:
Does NOT compute a composite risk score.
Does NOT execute SAFE / QUARANTINE / BLOCK decisions.
Does NOT modify document persistence state.
"""

from typing import Optional

from app.models.document import Document
from app.models.security import SecurityAnalysisResult
from app.services.security.anomaly_detector import ContentAnomalyDetector
from app.services.security.injection_detector import PromptInjectionDetector
from app.services.security.source_trust import SourceTrustAnalyzer


class SecurityAnalyzer:
    """Coordinates security signal detectors for incoming documents."""

    def __init__(
        self,
        injection_detector: Optional[PromptInjectionDetector] = None,
        source_trust_analyzer: Optional[SourceTrustAnalyzer] = None,
        anomaly_detector: Optional[ContentAnomalyDetector] = None,
    ):
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.source_trust_analyzer = (
            source_trust_analyzer or SourceTrustAnalyzer()
        )
        self.anomaly_detector = anomaly_detector or ContentAnomalyDetector()

    def analyze_document(self, document: Document) -> SecurityAnalysisResult:
        """Run all signal detectors against a document without altering its state."""
        # 1. Run prompt injection heuristic
        inj_res = self.injection_detector.detect(document.content)

        # 2. Run source trust heuristic
        source_res = self.source_trust_analyzer.evaluate(
            source=document.source,
            source_type=document.source_type,
        )

        # 3. Run content anomaly heuristic
        anom_res = self.anomaly_detector.detect(document.content)

        # Aggregate signal tags and explanations cleanly
        all_signals = inj_res.signals + source_res.signals + anom_res.signals
        all_explanations = (
            inj_res.explanations
            + source_res.explanations
            + anom_res.explanations
        )

        return SecurityAnalysisResult(
            document_id=document.id,
            injection_score=inj_res.score,
            source_risk_score=source_res.score,
            content_anomaly_score=anom_res.score,
            signals=all_signals,
            explanations=all_explanations,
        )
