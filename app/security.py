import logging
import os
import secrets
from typing import Dict


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


# API Key Management
API_KEYS: Dict[str, bool] = {
    os.getenv("LLM_GATEWAY_API_KEY", "dev-secret-key"): True,
}


def verify_api_key(api_key: str) -> bool:
    if not api_key:
        return False

    for stored_key, is_active in API_KEYS.items():
        if secrets.compare_digest(api_key, stored_key):
            return is_active

    return False


def generate_api_key() -> str:
    return f"llm_{secrets.token_urlsafe(32)}"


def add_api_key(api_key: str) -> None:
    API_KEYS[api_key] = True


def revoke_api_key(api_key: str) -> bool:
    if api_key in API_KEYS:
        API_KEYS[api_key] = False
        logger.warning("API key revoked")
        return True

    return False


def rotate_api_key(old_api_key: str) -> str | None:
    if not revoke_api_key(old_api_key):
        return None

    new_api_key = generate_api_key()
    add_api_key(new_api_key)

    logger.info("API key rotated successfully")
    return new_api_key