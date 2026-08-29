import re
from dataclasses import dataclass


@dataclass
class PromptRiskResult:
    score: int
    level: str
    reasons: list[str]


# Risk levels
def _get_risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


# Suspicious prompt indicators
RISK_PATTERNS = [
    (
        r"\b(ignore|disregard|forget)\s+(all|any|previous|prior)\s+instructions?\b",
        35,
        "Instruction override attempt",
    ),
    (
        r"\b(system prompt|system message|hidden prompt)\b",
        25,
        "System prompt probing",
    ),
    (
        r"\b(reveal|show|print|leak|expose)\b.{0,50}\b(prompt|instructions?|secrets?|credentials?)\b",
        30,
        "Sensitive information extraction attempt",
    ),
    (
        r"\b(jailbreak|bypass|evade|disable)\b.{0,50}\b(safety|security|filter|policy|rules?)\b",
        40,
        "Security control bypass attempt",
    ),
    (
        r"\b(api[_ -]?key|password|secret|token|credential)\b",
        20,
        "Credential-related request",
    ),
    (
        r"\b(do anything|no restrictions?|without restrictions?)\b",
        20,
        "Restriction removal attempt",
    ),
]


def calculate_prompt_risk(prompt: str) -> PromptRiskResult:
    """
    Calculate a deterministic 0-100 security risk score
    for an incoming LLM prompt.
    """

    score = 0
    reasons = []

    normalized_prompt = prompt.lower().strip()

    for pattern, weight, reason in RISK_PATTERNS:
        if re.search(pattern, normalized_prompt, re.IGNORECASE):
            score += weight
            reasons.append(reason)

    # Additional heuristic checks

    # Very long repeated instruction-like text
    if len(normalized_prompt) > 3000:
        score += 10
        reasons.append("Unusually long prompt")

    # Excessive special characters can indicate obfuscation
    special_chars = sum(
        1 for char in normalized_prompt
        if not char.isalnum() and not char.isspace()
    )

    if len(normalized_prompt) > 0:
        special_ratio = special_chars / len(normalized_prompt)

        if special_ratio > 0.30:
            score += 10
            reasons.append("Possible prompt obfuscation")

    # Keep score within 0-100
    score = min(score, 100)

    return PromptRiskResult(
        score=score,
        level=_get_risk_level(score),
        reasons=reasons,
    )