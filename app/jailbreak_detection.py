"""
Jailbreak Detection Module

Detects common jailbreak and instruction-bypass attempts
in user prompts.
"""

from dataclasses import dataclass
import re


@dataclass
class JailbreakDetectionResult:
    detected: bool
    score: int
    reasons: list[str]


JAILBREAK_PATTERNS = [
    (
        r"\bignore\s+(all\s+)?previous\s+instructions\b",
        "Instruction override attempt",
        35,
    ),
    (
        r"\bignore\s+(all\s+)?prior\s+instructions\b",
        "Instruction override attempt",
        35,
    ),
    (
        r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
        "Instruction override attempt",
        35,
    ),
    (
        r"\bforget\s+(all\s+)?previous\s+instructions\b",
        "Instruction override attempt",
        30,
    ),
    (
        r"\b(system\s+prompt|hidden\s+prompt|secret\s+instructions)\b",
        "System prompt extraction attempt",
        25,
    ),
    (
        r"\breveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions)\b",
        "System prompt extraction attempt",
        30,
    ),
    (
        r"\bpretend\s+(you\s+are|to\s+be)\b",
        "Role-play jailbreak attempt",
        20,
    ),
    (
        r"\bact\s+as\s+(an?\s+)?(unrestricted|uncensored|evil)\b",
        "Unrestricted role-play attempt",
        30,
    ),
    (
        r"\bdeveloper\s+mode\b",
        "Developer mode jailbreak attempt",
        30,
    ),
    (
        r"\bdo\s+anything\s+now\b",
        "DAN jailbreak attempt",
        40,
    ),
    (
        r"\bno\s+rules\b",
        "Safety rule bypass attempt",
        25,
    ),
    (
        r"\bbypass\s+(your\s+)?(safety|security|restrictions|filters)\b",
        "Safety control bypass attempt",
        35,
    ),
    (
        r"\bdisable\s+(your\s+)?(safety|security|filters)\b",
        "Safety control disable attempt",
        35,
    ),
]


def detect_jailbreak(prompt: str) -> JailbreakDetectionResult:
    """
    Detect jailbreak patterns in a prompt.

    Returns:
        JailbreakDetectionResult containing:
        - detected: whether a jailbreak was detected
        - score: risk score from 0 to 100
        - reasons: matched detection reasons
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string")

    normalized_prompt = re.sub(r"\s+", " ", prompt.strip().lower())

    if not normalized_prompt:
        return JailbreakDetectionResult(
            detected=False,
            score=0,
            reasons=[],
        )

    score = 0
    reasons = []

    for pattern, reason, pattern_score in JAILBREAK_PATTERNS:
        if re.search(pattern, normalized_prompt):
            score += pattern_score

            if reason not in reasons:
                reasons.append(reason)

    score = min(score, 100)

    return JailbreakDetectionResult(
        detected=score > 0,
        score=score,
        reasons=reasons,
    )