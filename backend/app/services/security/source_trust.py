"""Configurable source trust evaluation mechanism.

Produces a normalized source risk score based on source_type and source metadata.
Note: A low-trust source is not inherently malicious; it represents a risk factor
for downstream security triage.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SourceTrustResult:
    """Evaluation result for source trust and provenance risk."""

    score: float
    signals: List[str]
    explanations: List[str]


# Source type risk ratings: lower score = higher trust (lower risk)
SOURCE_TYPE_RISK_MAP: Dict[str, float] = {
    # High Trust sources (0.05 - 0.15)
    "internal": 0.10,
    "official": 0.10,
    "verified": 0.10,
    "government": 0.05,
    # Medium Trust sources (0.30 - 0.50)
    "partner": 0.35,
    "known_external": 0.40,
    "wiki": 0.40,
    "ticket": 0.45,
    "documentation": 0.30,
    "file": 0.40,
    # Low Trust sources (0.75 - 0.95)
    "unknown": 0.90,
    "user_submitted": 0.85,
    "unverified": 0.85,
    "anonymous": 0.95,
    "public_forum": 0.85,
}

DEFAULT_UNCLASSIFIED_RISK: float = 0.65


class SourceTrustAnalyzer:
    """Evaluates provenance trust and calculates source risk score."""

    def __init__(
        self,
        risk_map: Optional[Dict[str, float]] = None,
        default_risk: float = DEFAULT_UNCLASSIFIED_RISK,
    ):
        self.risk_map = (
            {k.lower(): v for k, v in (risk_map or SOURCE_TYPE_RISK_MAP).items()}
        )
        self.default_risk = default_risk

    def evaluate(self, source: str, source_type: str) -> SourceTrustResult:
        """Evaluate source metadata and return normalized source risk score."""
        clean_type = (source_type or "").strip().lower()
        clean_source = (source or "").strip().lower()

        signals: List[str] = []
        explanations: List[str] = []

        if not clean_source or clean_source in {"unknown", "none", "n/a"}:
            signals.append("source_missing_or_unknown")
            explanations.append(
                "Source provenance identifier is missing or explicitly unknown."
            )
            return SourceTrustResult(
                score=0.90,
                signals=signals,
                explanations=explanations,
            )

        if clean_type in self.risk_map:
            score = self.risk_map[clean_type]
            if score <= 0.20:
                signals.append("source_high_trust")
                explanations.append(
                    f"Source type '{clean_type}' is recognized as high-trust (low risk factor)."
                )
            elif score <= 0.50:
                signals.append("source_medium_trust")
                explanations.append(
                    f"Source type '{clean_type}' is categorized as medium-trust."
                )
            else:
                signals.append("source_low_trust")
                explanations.append(
                    f"Source type '{clean_type}' is categorized as low-trust (elevated risk factor)."
                )
        else:
            score = self.default_risk
            signals.append("source_unclassified")
            explanations.append(
                f"Source type '{clean_type or 'unspecified'}' is unclassified; assigned default baseline risk."
            )

        normalized_score = round(min(1.0, max(0.0, score)), 2)
        return SourceTrustResult(
            score=normalized_score,
            signals=signals,
            explanations=explanations,
        )
