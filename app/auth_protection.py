import logging
import os

import redis


logger = logging.getLogger("llm-security-gateway")


MAX_FAILED_ATTEMPTS = 5
BLOCK_SECONDS = 60

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)


def is_auth_blocked(client_id: str) -> bool:
    key = f"auth_block:{client_id}"

    try:
        return redis_client.exists(key) == 1

    except redis.RedisError:
        logger.exception("Redis authentication protection error")
        return True


def record_failed_attempt(client_id: str) -> bool:
    key = f"auth_fail:{client_id}"

    try:
        attempts = redis_client.incr(key)

        if attempts == 1:
            redis_client.expire(key, BLOCK_SECONDS)

        if attempts >= MAX_FAILED_ATTEMPTS:
            block_key = f"auth_block:{client_id}"

            redis_client.setex(
                block_key,
                BLOCK_SECONDS,
                "1",
            )

            logger.warning(
                "Authentication temporarily blocked | client_id=%s",
                client_id,
            )

            return True

        return False

    except redis.RedisError:
        logger.exception("Redis authentication protection error")
        return True


def clear_failed_attempts(client_id: str) -> None:
    key = f"auth_fail:{client_id}"

    try:
        redis_client.delete(key)

    except redis.RedisError:
        logger.exception("Redis authentication counter reset error")