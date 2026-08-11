import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("llm-security-gateway")


SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "system prompt",
    "reveal your instructions",
    "show your system prompt",
    "jailbreak",
]


def detect_prompt_injection(prompt: str) -> bool:
    prompt_lower = prompt.lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in prompt_lower:
            logger.warning(
                "Prompt injection detected: pattern='%s'",
                pattern,
            )
            return True

    return False