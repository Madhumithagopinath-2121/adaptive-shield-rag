"""Threat state observation engine.

Determines the current operational threat state (NORMAL, ELEVATED, HIGH, CRITICAL)
of the incoming knowledge stream based on attack velocity and block rates over
a rolling time window.

IMPORTANT ARCHITECTURAL RULE:
This layer strictly OBSERVES stream conditions. It does NOT automatically mutate
decision thresholds or alter document statuses in this MVP phase.
"""

from typing import Optional, Tuple

from app.config import settings
from app.database import get_recent_assessments
from app.models.threat_state import ThreatState, ThreatStateResult
from app.services.security.attack_velocity import (
    AttackVelocityCalculator,
    VelocityMetrics,
)


class ThreatStateEngine:
    """Evaluates recent security assessments to determine stream threat state."""

    def __init__(
        self,
        velocity_calculator: Optional[AttackVelocityCalculator] = None,
        db_path: Optional[str] = None,
        window_seconds: Optional[int] = None,
        elevated_velocity: Optional[float] = None,
        elevated_block_rate: Optional[float] = None,
        high_velocity: Optional[float] = None,
        high_block_rate: Optional[float] = None,
        critical_velocity: Optional[float] = None,
        critical_block_rate: Optional[float] = None,
    ):
        self.velocity_calculator = (
            velocity_calculator or AttackVelocityCalculator()
        )
        self.db_path = db_path
        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else settings.attack_velocity_window_seconds
        )
        self.elevated_velocity = (
            elevated_velocity
            if elevated_velocity is not None
            else settings.threat_threshold_elevated_velocity
        )
        self.elevated_block_rate = (
            elevated_block_rate
            if elevated_block_rate is not None
            else settings.threat_threshold_elevated_block_rate
        )
        self.high_velocity = (
            high_velocity
            if high_velocity is not None
            else settings.threat_threshold_high_velocity
        )
        self.high_block_rate = (
            high_block_rate
            if high_block_rate is not None
            else settings.threat_threshold_high_block_rate
        )
        self.critical_velocity = (
            critical_velocity
            if critical_velocity is not None
            else settings.threat_threshold_critical_velocity
        )
        self.critical_block_rate = (
            critical_block_rate
            if critical_block_rate is not None
            else settings.threat_threshold_critical_block_rate
        )

    def determine_state(
        self, metrics: VelocityMetrics
    ) -> Tuple[ThreatState, str]:
        """Determine ThreatState and explanatory reason evaluating from highest severity downward."""
        if metrics.total_assessed == 0:
            return (
                ThreatState.NORMAL,
                "No security assessments are currently available.",
            )

        if (
            metrics.attack_velocity >= self.critical_velocity
            or metrics.block_rate >= self.critical_block_rate
        ):
            return (
                ThreatState.CRITICAL,
                f"A sustained high proportion of suspicious assessments (velocity: {metrics.attack_velocity:.2f}, block rate: {metrics.block_rate:.2f}) indicates critical stream activity.",
            )
        elif (
            metrics.attack_velocity >= self.high_velocity
            or metrics.block_rate >= self.high_block_rate
        ):
            return (
                ThreatState.HIGH,
                f"Recent stream activity contains a high concentration of suspicious assessments (velocity: {metrics.attack_velocity:.2f}, block rate: {metrics.block_rate:.2f}).",
            )
        elif (
            metrics.attack_velocity >= self.elevated_velocity
            or metrics.block_rate >= self.elevated_block_rate
        ):
            return (
                ThreatState.ELEVATED,
                f"Suspicious assessment velocity has increased above the elevated threshold (velocity: {metrics.attack_velocity:.2f}, block rate: {metrics.block_rate:.2f}).",
            )
        else:
            return (
                ThreatState.NORMAL,
                "Recent stream activity contains a low proportion of suspicious assessments.",
            )

    def get_current_threat_state(self) -> ThreatStateResult:
        """Fetch assessments within the rolling window and compute current threat state."""
        assessments = get_recent_assessments(
            window_seconds=self.window_seconds,
            db_path=self.db_path,
        )
        metrics = self.velocity_calculator.calculate_metrics(assessments)
        state, reason = self.determine_state(metrics)

        return ThreatStateResult(
            state=state,
            window_size=metrics.total_assessed,
            total_assessed=metrics.total_assessed,
            safe_count=metrics.safe_count,
            quarantine_count=metrics.quarantine_count,
            block_count=metrics.block_count,
            block_rate=metrics.block_rate,
            quarantine_rate=metrics.quarantine_rate,
            attack_velocity=metrics.attack_velocity,
            average_risk_score=metrics.average_risk_score,
            state_reason=reason,
        )
