import hashlib
import json
import logging
import os
from datetime import datetime, timezone

import redis


logger = logging.getLogger("llm-security-gateway")


REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

API_KEY_PREFIX = "api_key:"


redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _redis_key(api_key: str) -> str:
    return f"{API_KEY_PREFIX}{hash_api_key(api_key)}"


def save_api_key(
    api_key: str,
    key_id: str,
    created_at: str | None = None,
    active: bool = True,
    role: str = "user",
) -> None:
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    metadata = {
        "key_id": key_id,
        "created_at": created_at,
        "active": active,
        "role": role,
    }

    redis_client.set(
        _redis_key(api_key),
        json.dumps(metadata),
    )


def get_api_key(api_key: str) -> dict | None:
    try:
        data = redis_client.get(_redis_key(api_key))

        if data is None:
            return None

        return json.loads(data)

    except (redis.RedisError, json.JSONDecodeError):
        logger.exception("Failed to retrieve API key metadata")
        return None


def update_api_key_status(
    api_key: str,
    active: bool,
) -> bool:
    metadata = get_api_key(api_key)

    if metadata is None:
        return False

    metadata["active"] = active

    try:
        redis_client.set(
            _redis_key(api_key),
            json.dumps(metadata),
        )
        return True

    except redis.RedisError:
        logger.exception("Failed to update API key status")
        return False