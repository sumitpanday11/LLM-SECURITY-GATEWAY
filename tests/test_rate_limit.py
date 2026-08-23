import redis
from unittest.mock import patch

from app.rate_limit import (
    MAX_REQUESTS,
    WINDOW_SECONDS,
    is_rate_limited,
)


def test_request_within_limit_is_allowed():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.return_value = 1

        result = is_rate_limited("test-api-key")

        assert result is False
        redis_mock.incr.assert_called_once_with(
            "rate_limit:test-api-key"
        )
        redis_mock.expire.assert_called_once_with(
            "rate_limit:test-api-key",
            WINDOW_SECONDS,
        )


def test_requests_within_limit_remain_allowed():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.return_value = MAX_REQUESTS

        result = is_rate_limited("test-api-key")

        assert result is False


def test_request_above_limit_is_blocked():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.return_value = MAX_REQUESTS + 1

        result = is_rate_limited("test-api-key")

        assert result is True


def test_rate_limit_key_uses_api_key():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.return_value = 1

        is_rate_limited("my-test-key")

        redis_mock.incr.assert_called_once_with(
            "rate_limit:my-test-key"
        )


def test_expiry_is_set_only_for_first_request():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.return_value = 2

        result = is_rate_limited("test-api-key")

        assert result is False
        redis_mock.expire.assert_not_called()


def test_redis_error_fails_closed():
    with patch("app.rate_limit.redis_client") as redis_mock:
        redis_mock.incr.side_effect = redis.RedisError(
            "Redis connection failed"
        )

        result = is_rate_limited("test-api-key")

        assert result is True