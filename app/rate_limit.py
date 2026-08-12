import time

request_log = {}

MAX_REQUESTS = 5
WINDOW_SECONDS = 60


def is_rate_limited(api_key: str) -> bool:
    now = time.time()

    if api_key not in request_log:
        request_log[api_key] = []

    request_log[api_key] = [
        timestamp
        for timestamp in request_log[api_key]
        if now - timestamp < WINDOW_SECONDS
    ]

    if len(request_log[api_key]) >= MAX_REQUESTS:
        return True

    request_log[api_key].append(now)
    return False