import hashlib
import json
import logging
import os
import time

import redis


logger = logging.getLogger("llm-security-gateway")


# ============================================================
# SEMANTIC CACHE CONFIGURATION
# ============================================================

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

SEMANTIC_CACHE_PREFIX = "semantic_cache:"
SEMANTIC_CACHE_TTL_SECONDS = int(
    os.getenv("SEMANTIC_CACHE_TTL_SECONDS", "300")
)


redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)


# ============================================================
# PROMPT NORMALIZATION
# ============================================================

def normalize_prompt(prompt: str) -> str:
    """
    Normalize prompts so equivalent prompts generate
    the same cache key.
    """
    return " ".join(
        prompt.lower().strip().split()
    )


def generate_cache_key(prompt: str) -> str:
    """
    Generate a deterministic Redis cache key.
    """
    normalized_prompt = normalize_prompt(prompt)

    prompt_hash = hashlib.sha256(
        normalized_prompt.encode("utf-8")
    ).hexdigest()

    return f"{SEMANTIC_CACHE_PREFIX}{prompt_hash}"


# ============================================================
# CACHE LOOKUP
# ============================================================

def get_cached_response(prompt: str) -> dict | None:
    """
    Retrieve a cached response for an equivalent prompt.
    """
    cache_key = generate_cache_key(prompt)

    try:
        cached_data = redis_client.get(cache_key)

        if cached_data is None:
            return None

        logger.info(
            "Semantic cache hit | cache_key=%s",
            cache_key,
        )

        return json.loads(cached_data)

    except (redis.RedisError, json.JSONDecodeError):

        logger.exception(
            "Failed to retrieve semantic cache entry"
        )

        return None


# ============================================================
# CACHE STORAGE
# ============================================================

def save_cached_response(
    prompt: str,
    response: dict,
) -> bool:
    """
    Store a response in Redis with a TTL.
    """
    cache_key = generate_cache_key(prompt)

    cache_entry = {
        "response": response,
        "cached_at": int(time.time()),
    }

    try:
        redis_client.set(
            cache_key,
            json.dumps(cache_entry),
            ex=SEMANTIC_CACHE_TTL_SECONDS,
        )

        logger.info(
            "Semantic cache stored | cache_key=%s | ttl=%s",
            cache_key,
            SEMANTIC_CACHE_TTL_SECONDS,
        )

        return True

    except redis.RedisError:

        logger.exception(
            "Failed to store semantic cache entry"
        )

        return False