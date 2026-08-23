import logging
import re


logger = logging.getLogger("llm-security-gateway")


# ============================================================
# Unsafe Output Filtering
# ============================================================

UNSAFE_OUTPUT_PATTERNS = {
    "SYSTEM_PROMPT_LEAK": [
        re.compile(
            r"\b(?:system prompt|system message|developer message|"
            r"hidden instructions|internal instructions)\b",
            re.IGNORECASE,
        ),
    ],

    "SECRET_LEAK": [
        re.compile(
            r"\b(?:api[_ -]?key|secret[_ -]?key|access[_ -]?token|"
            r"private[_ -]?key|password)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ],

    "CREDENTIAL_LEAK": [
        re.compile(
            r"\bauthorization\s*:\s*bearer\s+\S+",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bbearer\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bauthorization\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ],

    "DANGEROUS_INSTRUCTION": [
        re.compile(
            r"\b(?:disable|bypass|remove)\s+"
            r"(?:security|safety|authentication|authorization)"
            r"(?:\s+(?:controls|filters|restrictions|checks))?\b",
            re.IGNORECASE,
        ),
    ],

    "MALICIOUS_CODE_OUTPUT": [
        re.compile(
            r"(?:\brm\s+-rf\s+/)"
            r"|(?:\bformat\s+c:)"
            r"|(?:\bdel\s+/f\s+/s\s+/q\s+c:\\)"
            r"|(?:\bdrop\s+database\b)"
            r"|(?:\bdrop\s+table\b)",
            re.IGNORECASE,
        ),
    ],
}


def detect_unsafe_output(output: str) -> list[str]:
    """
    Detect potentially unsafe or sensitive information
    appearing in an LLM response.
    """

    detected_types = []

    for category, patterns in UNSAFE_OUTPUT_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(output):
                detected_types.append(category)
                break

    if detected_types:
        logger.warning(
            "Unsafe output detected | types=%s",
            ",".join(detected_types),
        )

    return detected_types


def redact_unsafe_output(output: str) -> str:
    """
    Redact secrets and credentials from LLM output.
    """

    sanitized_output = output

    replacements = {
        "SYSTEM_PROMPT_LEAK": "[REDACTED_SYSTEM_INSTRUCTION]",
        "SECRET_LEAK": "[REDACTED_SECRET]",
        "CREDENTIAL_LEAK": "[REDACTED_CREDENTIAL]",
        "DANGEROUS_INSTRUCTION": "[REDACTED_UNSAFE_INSTRUCTION]",
        "MALICIOUS_CODE_OUTPUT": "[REDACTED_MALICIOUS_CONTENT]",
    }

    for category, patterns in UNSAFE_OUTPUT_PATTERNS.items():
        for pattern in patterns:
            sanitized_output = pattern.sub(
                replacements[category],
                sanitized_output,
            )

    return sanitized_output


def filter_unsafe_output(output: str) -> tuple[str, list[str]]:
    """
    Detect and sanitize unsafe output.

    Returns:
        sanitized_output, detected_categories
    """

    detected_types = detect_unsafe_output(output)

    if not detected_types:
        return output, []

    sanitized_output = redact_unsafe_output(output)

    return sanitized_output, detected_types