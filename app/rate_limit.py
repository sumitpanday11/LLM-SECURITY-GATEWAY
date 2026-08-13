import logging
import os

import redis


logger = logging.getLogger("llm-security-gateway")


MAX_REQUESTS = 5
WINDOW_SECONDS = 60

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)


def is_rate_limited(api_key: str) -> bool:
    key = f"rate_limit:{api_key}"

    try:
        request_count = redis_client.incr(key)

        if request_count == 1:
            redis_client.expire(key, WINDOW_SECONDS)

        if request_count > MAX_REQUESTS:
            logger.warning(
                "Rate limit exceeded for API key"
            )
            return True

        return False

    except redis.RedisError:
        logger.exception("Redis rate limiter error")
        return True