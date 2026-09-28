"""Composite risk scoring service.

Combines available deterministic security signals into an interpretable
normalized composite risk score [0.0, 1.0].

Prototype weight distribution:
- Prompt Injection:   0.40
- Source Risk:         0.20
- Content Anomaly:     0.20
- Reserved signals:    0.20 (Contradiction & Attack Velocity, planned for future streaming phase)

In this MVP phase, active weights are normalized across the three active signals:
active_weight = 0.40 + 0.20 + 0.20 = 0.80
risk_score = (0.40 * injection + 0.20 * source + 0.20 * anomaly) / 0.80
"""

from typing import Dict


class CompositeRiskScorer:
    """Calculates weighted normalized composite risk scores."""

    DEFAULT_WEIGHT_INJECTION = 0.40
    DEFAULT_WEIGHT_SOURCE_RISK = 0.20
    DEFAULT_WEIGHT_CONTENT_ANOMALY = 0.20
    DEFAULT_WEIGHT_RESERVED = 0.20  # Reserved for contradiction & velocity

    def __init__(
        self,
        weight_injection: float = DEFAULT_WEIGHT_INJECTION,
        weight_source_risk: float = DEFAULT_WEIGHT_SOURCE_RISK,
        weight_content_anomaly: float = DEFAULT_WEIGHT_CONTENT_ANOMALY,
    ):
        self.weight_injection = weight_injection
        self.weight_source_risk = weight_source_risk
        self.weight_content_anomaly = weight_content_anomaly

        self.active_weight = (
            self.weight_injection
            + self.weight_source_risk
            + self.weight_content_anomaly
        )
        if self.active_weight <= 0.0:
            raise ValueError("Active weights sum must be strictly positive.")

    def calculate_risk(
        self,
        injection_score: float,
        source_risk_score: float,
        content_anomaly_score: float,
    ) -> float:
        """Calculate composite risk score normalized to [0.0, 1.0]."""
        raw_weighted_sum = (
            self.weight_injection * injection_score
            + self.weight_source_risk * source_risk_score
            + self.weight_content_anomaly * content_anomaly_score
        )
        normalized = raw_weighted_sum / self.active_weight
        clamped = min(1.0, max(0.0, normalized))
        return round(clamped, 2)

    def get_weights_summary(self) -> Dict[str, float]:
        """Return the current weighting breakdown."""
        return {
            "injection_weight": self.weight_injection,
            "source_risk_weight": self.weight_source_risk,
            "content_anomaly_weight": self.weight_content_anomaly,
            "reserved_weight": self.DEFAULT_WEIGHT_RESERVED,
            "active_weight_sum": self.active_weight,
        }
