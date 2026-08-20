import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Dict

from app.api_key_store import (
    get_api_key,
    save_api_key,
    update_api_key_status,
)


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
API_KEYS: Dict[str, Dict[str, object]] = {
    os.getenv("LLM_GATEWAY_API_KEY", "dev-secret-key"): {
        "key_id": "default",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    },
}


def verify_api_key(api_key: str) -> bool:
    if not api_key:
        return False

    # First check Redis for persistent API keys.
    metadata = get_api_key(api_key)

    if metadata is not None:
        return bool(metadata.get("active", False))

    # Keep the default environment API key working.
    for stored_key, local_metadata in API_KEYS.items():
        if secrets.compare_digest(api_key, stored_key):
            return bool(local_metadata["active"])

    return False


def generate_api_key() -> str:
    return f"llm_{secrets.token_urlsafe(32)}"


def add_api_key(api_key: str) -> None:
    key_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    API_KEYS[api_key] = {
        "key_id": key_id,
        "created_at": created_at,
        "active": True,
    }

    save_api_key(
        api_key=api_key,
        key_id=key_id,
        created_at=created_at,
        active=True,
    )

    logger.info(
        "API key added | key_id=%s",
        key_id,
    )


def revoke_api_key(api_key: str) -> bool:
    metadata = get_api_key(api_key)

    if metadata is not None:
        if not update_api_key_status(api_key, False):
            return False

        if api_key in API_KEYS:
            API_KEYS[api_key]["active"] = False

        logger.warning(
            "API key revoked | key_id=%s",
            metadata.get("key_id"),
        )

        return True

    if api_key in API_KEYS:
        API_KEYS[api_key]["active"] = False

        logger.warning(
            "API key revoked | key_id=%s",
            API_KEYS[api_key]["key_id"],
        )

        return True

    return False


def rotate_api_key(old_api_key: str) -> str | None:
    if not revoke_api_key(old_api_key):
        return None

    new_api_key = generate_api_key()
    add_api_key(new_api_key)

    metadata = get_api_key(new_api_key)

    logger.info(
        "API key rotated successfully | new_key_id=%s",
        metadata.get("key_id") if metadata else "unknown",
    )

    return new_api_key


def get_api_key_metadata(api_key: str) -> dict | None:
    metadata = get_api_key(api_key)

    if metadata is not None:
        return {
            "key_id": metadata.get("key_id"),
            "created_at": metadata.get("created_at"),
            "active": metadata.get("active"),
        }

    local_metadata = API_KEYS.get(api_key)

    if local_metadata is None:
        return None

    return {
        "key_id": local_metadata["key_id"],
        "created_at": local_metadata["created_at"],
        "active": local_metadata["active"],
    }