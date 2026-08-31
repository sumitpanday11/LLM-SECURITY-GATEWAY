"""
Secret and credential leak detection for LLM outputs.

Detects common API keys, tokens, passwords, private keys,
and other credential-like patterns and supports redaction.
"""

import re
from dataclasses import dataclass


@dataclass
class SecretDetectionResult:
    detected: bool
    secrets: list[str]
    redacted_text: str


SECRET_PATTERNS = {
    "OpenAI API Key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Bearer Token": re.compile(
        r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"
    ),
    "Private Key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "Password Assignment": re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]+"
    ),
    "API Key Assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)"
        r"\s*[:=]\s*[A-Za-z0-9_\-./+=]{12,}"
    ),
}


def detect_secrets(text: str) -> SecretDetectionResult:
    """
    Detect credential-like values in text.

    Args:
        text: Text that should be inspected.

    Returns:
        SecretDetectionResult containing detection status,
        matched secret values, and redacted text.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    secrets: list[str] = []
    redacted_text = text

    for pattern in SECRET_PATTERNS.values():
        matches = pattern.findall(text)

        for match in matches:
            value = match if isinstance(match, str) else match[0]

            if value and value not in secrets:
                secrets.append(value)

            if value:
                redacted_text = redacted_text.replace(
                    value,
                    "[REDACTED_SECRET]",
                )

    return SecretDetectionResult(
        detected=bool(secrets),
        secrets=secrets,
        redacted_text=redacted_text,
    )


def redact_secrets(text: str) -> str:
    """
    Convenience function that returns text with detected secrets redacted.
    """
    return detect_secrets(text).redacted_text