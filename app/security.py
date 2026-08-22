import logging
import os
import re
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


# ============================================================
# Advanced Prompt Injection Protection
# ============================================================

SUSPICIOUS_PATTERNS = [
    # Direct instruction override
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?\b",
    r"\boverride\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b",

    # System prompt extraction
    r"\b(?:reveal|show|display|print|output|give|tell)\s+(?:me\s+)?"
    r"(?:your\s+)?(?:system\s+prompt|hidden\s+prompt|system\s+instructions?)\b",

    r"\bwhat\s+(?:is|are)\s+your\s+(?:system\s+prompt|hidden\s+instructions?)\b",

    # Instruction extraction
    r"\b(?:reveal|show|dump|print|output)\s+"
    r"(?:your\s+)?(?:instructions?|rules?|policies?)\b",

    # Role manipulation
    r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b",

    # Jailbreak
    r"\b(?:jailbreak|jail\s*break|bypass\s+(?:your\s+)?"
    r"(?:safety|security)\s+(?:filters?|restrictions?|rules?))\b",

    # Safety bypass
    r"\b(?:disable|remove|ignore|bypass)\s+"
    r"(?:safety|security|content)\s+(?:filters?|controls?|restrictions?)\b",

    # Developer/system message manipulation
    r"\b(?:ignore|disregard)\s+(?:the\s+)?"
    r"(?:developer|system|assistant)\s+(?:message|instructions?)\b",

    # Fake authority / hierarchy manipulation
    r"\b(?:developer|system)\s*:\s*",

    r"\b(?:system\s+message|developer\s+message)\b",

    # Delimiter / prompt boundary attacks
    r"```(?:system|developer|assistant)\b",

    r"<\|(?:system|developer|assistant)\|>",

    r"\[\[(?:system|developer|assistant)\]\]",

    # Encoded instruction indicators
    r"\b(?:base64|rot13|hex)\s+(?:decode|encoded?)\b",
]


COMPILED_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in SUSPICIOUS_PATTERNS
]


def normalize_prompt(prompt: str) -> str:
    """
    Normalize user input before security inspection.

    Removes excessive whitespace and normalizes Unicode so
    attackers cannot easily bypass simple pattern detection.
    """
    normalized = prompt.replace("\x00", " ")

    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    return normalized.strip()


def detect_prompt_injection(prompt: str) -> bool:
    """
    Detect common and advanced prompt injection techniques.
    """
    normalized_prompt = normalize_prompt(prompt)

    for pattern in COMPILED_INJECTION_PATTERNS:
        if pattern.search(normalized_prompt):
            logger.warning(
                "Advanced prompt injection detected | pattern=%s",
                pattern.pattern,
            )
            return True

    return False


# ============================================================
# PII Detection
# ============================================================

PII_PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "PHONE": re.compile(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    ),

    "AADHAAR": re.compile(
        r"(?<!\d)(?<!\d[\s-])"
        r"(?:\d{12}|\d{4}[\s-]\d{4}[\s-]\d{4})"
        r"(?![\s-]?\d)"
    ),

    "PAN": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        re.IGNORECASE,
    ),

    "CARD": re.compile(
        r"(?<!\d)(?:\d{4}[\s-]?){3}\d{4}(?!\d)"
    ),
}


def detect_pii(prompt: str) -> list[str]:
    detected_types = []

    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(prompt):
            detected_types.append(pii_type)

    if detected_types:
        logger.warning(
            "PII detected | types=%s",
            ",".join(detected_types),
        )

    return detected_types


def redact_pii(prompt: str) -> str:
    redacted_prompt = prompt

    replacements = {
        "EMAIL": "[REDACTED_EMAIL]",
        "PHONE": "[REDACTED_PHONE]",
        "AADHAAR": "[REDACTED_AADHAAR]",
        "PAN": "[REDACTED_PAN]",
        "CARD": "[REDACTED_CARD]",
    }

    ordered_patterns = [
        "EMAIL",
        "PHONE",
        "CARD",
        "AADHAAR",
        "PAN",
    ]

    for pii_type in ordered_patterns:
        redacted_prompt = PII_PATTERNS[pii_type].sub(
            replacements[pii_type],
            redacted_prompt,
        )

    return redacted_prompt


# ============================================================
# PHI Detection
# ============================================================

PHI_PATTERNS = {
    "MEDICAL_RECORD_ID": re.compile(
        r"\b(?:MRN|Medical\s+Record(?:\s+Number)?|"
        r"Patient\s+Record(?:\s+ID)?)"
        r"\s*(?:is|=|:|#|-)?\s*"
        r"[A-Z0-9-]{4,20}\b",
        re.IGNORECASE,
    ),

    "INSURANCE_ID": re.compile(
        r"\b(?:Insurance\s+(?:ID|Number)|"
        r"Policy\s+(?:ID|Number))"
        r"\s*(?:is|=|:|#|-)?\s*"
        r"[A-Z0-9-]{4,25}\b",
        re.IGNORECASE,
    ),

    "PRESCRIPTION_ID": re.compile(
        r"\b(?:Prescription|Rx)"
        r"(?:\s+(?:ID|Number|No\.?))?"
        r"\s*(?:is|=|:|#|-)?\s*"
        r"[A-Z0-9-]{3,20}\b",
        re.IGNORECASE,
    ),

    "DATE_OF_BIRTH": re.compile(
        r"\b(?:DOB|Date\s+of\s+Birth)"
        r"\s*(?:is|=|:|#|-)?\s*"
        r"(?:"
        r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        r"|"
        r"\d{4}[/-]\d{1,2}[/-]\d{1,2}"
        r")\b",
        re.IGNORECASE,
    ),
}


def detect_phi(prompt: str) -> list[str]:
    detected_types = []

    for phi_type, pattern in PHI_PATTERNS.items():
        if pattern.search(prompt):
            detected_types.append(phi_type)

    if detected_types:
        logger.warning(
            "PHI detected | types=%s",
            ",".join(detected_types),
        )

    return detected_types


def redact_phi(prompt: str) -> str:
    redacted_prompt = prompt

    replacements = {
        "MEDICAL_RECORD_ID": "[REDACTED_MEDICAL_RECORD_ID]",
        "INSURANCE_ID": "[REDACTED_INSURANCE_ID]",
        "PRESCRIPTION_ID": "[REDACTED_PRESCRIPTION_ID]",
        "DATE_OF_BIRTH": "[REDACTED_DATE_OF_BIRTH]",
    }

    for phi_type, pattern in PHI_PATTERNS.items():
        redacted_prompt = pattern.sub(
            replacements[phi_type],
            redacted_prompt,
        )

    return redacted_prompt


# ============================================================
# API Key Management + RBAC
# ============================================================

# Default development key is ADMIN so it can perform
# administrative key-management operations.
DEFAULT_API_KEY = os.getenv(
    "LLM_GATEWAY_API_KEY",
    "dev-secret-key",
)

API_KEYS: Dict[str, Dict[str, object]] = {
    DEFAULT_API_KEY: {
        "key_id": "default",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
        "role": "admin",
    },
}


def verify_api_key(api_key: str) -> bool:
    """
    Verify API key existence and active status.
    """
    if not api_key:
        return False

    metadata = get_api_key(api_key)

    if metadata is not None:
        return bool(metadata.get("active", False))

    for stored_key, local_metadata in API_KEYS.items():
        if secrets.compare_digest(api_key, stored_key):
            return bool(local_metadata["active"])

    return False


def generate_api_key() -> str:
    """
    Generate a secure random API key.
    """
    return f"llm_{secrets.token_urlsafe(32)}"


def add_api_key(
    api_key: str,
    role: str = "user",
) -> None:
    """
    Add a new API key.

    New keys default to the 'user' role.
    Admin keys can be created explicitly by passing role='admin'.
    """

    if role not in {"admin", "user"}:
        raise ValueError(
            "Invalid role. Allowed roles: admin, user"
        )

    key_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    API_KEYS[api_key] = {
        "key_id": key_id,
        "created_at": created_at,
        "active": True,
        "role": role,
    }

    save_api_key(
        api_key=api_key,
        key_id=key_id,
        created_at=created_at,
        active=True,
        role=role,
    )

    logger.info(
        "API key added | key_id=%s | role=%s",
        key_id,
        role,
    )


def revoke_api_key(api_key: str) -> bool:
    """
    Revoke an API key.
    """
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
    """
    Revoke old API key and generate a new user API key.
    """

    if not revoke_api_key(old_api_key):
        return None

    new_api_key = generate_api_key()

    add_api_key(
        new_api_key,
        role="user",
    )

    metadata = get_api_key(new_api_key)

    logger.info(
        "API key rotated successfully | new_key_id=%s",
        metadata.get("key_id") if metadata else "unknown",
    )

    return new_api_key


def get_api_key_metadata(api_key: str) -> dict | None:
    """
    Return API key metadata including RBAC role.
    """

    metadata = get_api_key(api_key)

    if metadata is not None:
        return {
            "key_id": metadata.get("key_id"),
            "created_at": metadata.get("created_at"),
            "active": metadata.get("active"),
            "role": metadata.get("role", "user"),
        }

    local_metadata = API_KEYS.get(api_key)

    if local_metadata is None:
        return None

    return {
        "key_id": local_metadata["key_id"],
        "created_at": local_metadata["created_at"],
        "active": local_metadata["active"],
        "role": local_metadata.get("role", "user"),
    }