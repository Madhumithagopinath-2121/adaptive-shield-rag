"""Deterministic, explainable heuristic detector for prompt-injection indicators.

Analyzes text for patterns associated with indirect prompt injection, including
instruction overrides, system directives, role manipulation, prompt leakage,
and embedded control tokens.

Note: This is a deterministic heuristic signal generator, not an LLM guardrail.
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Pattern, Tuple


@dataclass
class InjectionSignalResult:
    """Detection result from prompt injection heuristics."""

    score: float
    signals: List[str]
    explanations: List[str]


# Pattern definitions by category
INJECTION_PATTERNS: Dict[str, Tuple[List[Pattern[str]], str, float]] = {
    "instruction_override": (
        [
            re.compile(
                r"\b(?:ignore|disregard|forget|overwrite|cancel)\s+(?:all\s+)?(?:previous|prior|above|existing)\s+(?:instructions|directives|prompts|commands|rules|context)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:do\s+not\s+follow|stop\s+following)\s+(?:previous|prior|above)\s+(?:instructions|rules)\b",
                re.IGNORECASE,
            ),
        ],
        "Document contains phrasing attempting to override or cancel prior instructions.",
        0.40,
    ),
    "system_directive": (
        [
            re.compile(
                r"\b(?:ignore|bypass|disable|override|disregard)\s+(?:system|developer|safety|guardrail|security)\s+(?:prompts?|instructions?|rules?|policy|filters?)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:bypass|evade)\s+(?:all\s+)?(?:content\s+filters|safety\s+checks|guardrails)\b",
                re.IGNORECASE,
            ),
        ],
        "Document contains directives attempting to bypass system or developer safety constraints.",
        0.40,
    ),
    "role_assumption": (
        [
            re.compile(
                r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+to\s+be)\s+(?:a|an)?\s*(?:unrestricted|unfiltered|jailbroken|dan|evil|adversarial|assistant\s+without)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:switch|enter)\s+(?:into\s+)?(?:jailbreak|dan|unfiltered|developer)\s+mode\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:your\s+new\s+role\s+is|you\s+must\s+act\s+as)\b",
                re.IGNORECASE,
            ),
        ],
        "Document contains language attempting to alter model persona, role, or operating mode.",
        0.35,
    ),
    "prompt_leakage": (
        [
            re.compile(
                r"\b(?:reveal|repeat|output|print|show|expose)\s+(?:your\s+|the\s+)?(?:initial|system|developer|hidden|original)\s+(?:prompt|instructions?|rules?)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:output\s+all\s+text\s+above|repeat\s+everything\s+above)\b",
                re.IGNORECASE,
            ),
        ],
        "Document contains requests attempting to leak or output internal system prompts.",
        0.35,
    ),
    "embedded_command": (
        [
            re.compile(
                r"(?:\[(?:system|instruction|developer|inst)\]|<\|im_start\|>|<<sys>>|<sys>)",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:new\s+instructions?:|system\s+directive:|important:\s*execute\s+the\s+following|admin\s+override:)\b",
                re.IGNORECASE,
            ),
        ],
        "Document contains simulated control tokens or explicit instruction headers.",
        0.35,
    ),
}


class PromptInjectionDetector:
    """Heuristic detector for prompt injection and instruction-like language."""

    def __init__(
        self,
        patterns: Dict[str, Tuple[List[Pattern[str]], str, float]] = INJECTION_PATTERNS,
    ):
        self.patterns = patterns

    def detect(self, text: str) -> InjectionSignalResult:
        """Analyze text and generate prompt injection risk score and signals."""
        if not text or not text.strip():
            return InjectionSignalResult(
                score=0.0,
                signals=[],
                explanations=[],
            )

        matched_signals: List[str] = []
        matched_explanations: List[str] = []
        raw_score = 0.0

        for category, (regex_list, explanation, weight) in self.patterns.items():
            category_matched = False
            for pattern in regex_list:
                if pattern.search(text):
                    category_matched = True
                    break

            if category_matched:
                matched_signals.append(category)
                matched_explanations.append(explanation)
                raw_score += weight

        # Multi-category reinforcement bonus: if multiple distinct categories match,
        # it indicates concentrated intent rather than isolated phrasing.
        if len(matched_signals) > 1:
            raw_score += 0.10 * (len(matched_signals) - 1)

        normalized_score = round(min(1.0, max(0.0, raw_score)), 2)

        return InjectionSignalResult(
            score=normalized_score,
            signals=matched_signals,
            explanations=matched_explanations,
        )
