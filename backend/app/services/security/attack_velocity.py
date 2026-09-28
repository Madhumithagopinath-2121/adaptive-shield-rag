"""Attack velocity calculation service.

Measures the proportion and velocity of suspicious triage events (QUARANTINE + BLOCK)
within a rolling observation window of the incoming knowledge stream.

Note: This is a stream-level suspicious-event rate metric, not a network packet rate.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class VelocityMetrics:
    """Calculated stream velocity and decision rate metrics."""

    total_assessed: int
    safe_count: int
    quarantine_count: int
    block_count: int
    block_rate: float
    quarantine_rate: float
    attack_velocity: float
    average_risk_score: float


class AttackVelocityCalculator:
    """Calculates stream-level decision rates and attack velocity."""

    def calculate_metrics(
        self, assessments: List[Dict[str, Any]]
    ) -> VelocityMetrics:
        """Compute normalized velocity metrics across a list of assessment records."""
        total = len(assessments)
        if total == 0:
            return VelocityMetrics(
                total_assessed=0,
                safe_count=0,
                quarantine_count=0,
                block_count=0,
                block_rate=0.0,
                quarantine_rate=0.0,
                attack_velocity=0.0,
                average_risk_score=0.0,
            )

        safe_count = sum(1 for a in assessments if a.get("decision") == "SAFE")
        quarantine_count = sum(
            1 for a in assessments if a.get("decision") == "QUARANTINE"
        )
        block_count = sum(1 for a in assessments if a.get("decision") == "BLOCK")

        suspicious_count = quarantine_count + block_count

        attack_velocity = round(
            min(1.0, max(0.0, suspicious_count / total)), 2
        )
        block_rate = round(min(1.0, max(0.0, block_count / total)), 2)
        quarantine_rate = round(
            min(1.0, max(0.0, quarantine_count / total)), 2
        )

        total_risk = sum(float(a.get("risk_score", 0.0)) for a in assessments)
        average_risk_score = round(min(1.0, max(0.0, total_risk / total)), 2)

        return VelocityMetrics(
            total_assessed=total,
            safe_count=safe_count,
            quarantine_count=quarantine_count,
            block_count=block_count,
            block_rate=block_rate,
            quarantine_rate=quarantine_rate,
            attack_velocity=attack_velocity,
            average_risk_score=average_risk_score,
        )
