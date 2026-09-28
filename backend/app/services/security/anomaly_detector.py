"""Heuristic content anomaly detector for structural and textual irregularities.

Inspects content for anomalous characteristics including high control-marker density,
abnormal concentration of imperative directives, and excessive repetition.

Note: This is a lightweight deterministic heuristic, not a semantic ML model.
"""

from collections import Counter
from dataclasses import dataclass
import re
from typing import List


@dataclass
class AnomalySignalResult:
    """Detection result for structural and content anomalies."""

    score: float
    signals: List[str]
    explanations: List[str]


# Pattern for prompt boundary / template control markers
CONTROL_MARKERS_PATTERN = re.compile(
    r"(?:###|---|===|<<<|>>>|\[SYSTEM\]|\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)",
    re.IGNORECASE,
)

# Pattern for imperative command starters at beginning of lines or sentences
IMPERATIVE_STARTER_PATTERN = re.compile(
    r"^\s*(?:please\s+)?(?:do|don't|must|should|never|always|ignore|disregard|execute|run|print|output|override|reveal|forget|bypass|ensure|remember)\b",
    re.IGNORECASE,
)


class ContentAnomalyDetector:
    """Deterministic heuristic evaluator for suspicious textual patterns."""

    def detect(self, text: str) -> AnomalySignalResult:
        """Evaluate text for structural irregularities and return anomaly score."""
        if not text or not text.strip():
            return AnomalySignalResult(
                score=0.0,
                signals=[],
                explanations=[],
            )

        signals: List[str] = []
        explanations: List[str] = []
        raw_score = 0.0

        # 1. Control Marker Concentration
        control_matches = CONTROL_MARKERS_PATTERN.findall(text)
        if len(control_matches) >= 3:
            signals.append("control_marker_density")
            explanations.append(
                f"Elevated concentration of template or control markers detected ({len(control_matches)} instances)."
            )
            raw_score += 0.35

        # 2. Content Repetition Heuristics
        # Check duplicate line ratio
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) >= 4:
            line_counts = Counter(lines)
            max_repetition = max(line_counts.values())
            duplicate_lines = sum(count for count in line_counts.values() if count > 1)
            if duplicate_lines / len(lines) >= 0.40 or max_repetition >= 4:
                signals.append("excessive_repetition")
                explanations.append(
                    "Document exhibits abnormal line or sentence repetition."
                )
                raw_score += 0.35
        else:
            # Check token vocabulary redundancy for single-paragraph / dense text
            words = re.findall(r"\b\w+\b", text.lower())
            if len(words) >= 25:
                unique_ratio = len(set(words)) / len(words)
                if unique_ratio < 0.30:
                    signals.append("excessive_repetition")
                    explanations.append(
                        f"Abnormally low vocabulary diversity detected (unique word ratio {unique_ratio:.2f})."
                    )
                    raw_score += 0.35

        # 3. Imperative Directive Density
        # Split into sentence candidates
        sentences = [
            s.strip()
            for s in re.split(r"[.!?\n]+", text)
            if len(s.strip().split()) >= 3
        ]
        if len(sentences) >= 3:
            imperative_count = sum(
                1 for s in sentences if IMPERATIVE_STARTER_PATTERN.search(s)
            )
            imperative_ratio = imperative_count / len(sentences)
            if imperative_ratio >= 0.60:
                signals.append("abnormal_imperative_density")
                explanations.append(
                    f"High proportion of sentences structured as imperative directives ({imperative_ratio:.0%})."
                )
                raw_score += 0.35

        normalized_score = round(min(1.0, max(0.0, raw_score)), 2)
        return AnomalySignalResult(
            score=normalized_score,
            signals=signals,
            explanations=explanations,
        )
