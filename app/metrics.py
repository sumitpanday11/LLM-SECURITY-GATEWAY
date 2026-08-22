from prometheus_client import Counter, Histogram


REQUESTS_TOTAL = Counter(
    "llm_gateway_requests_total",
    "Total number of HTTP requests",
    ["method", "path", "status"],
)


REQUEST_DURATION = Histogram(
    "llm_gateway_request_duration_seconds",
    "HTTP request processing time in seconds",
    ["method", "path"],
)


SECURITY_EVENTS_TOTAL = Counter(
    "llm_gateway_security_events_total",
    "Total number of security events",
    ["event"],
)


AUTH_FAILURES_TOTAL = Counter(
    "llm_gateway_auth_failures_total",
    "Total number of failed authentication attempts",
)


BLOCKED_REQUESTS_TOTAL = Counter(
    "llm_gateway_blocked_requests_total",
    "Total number of blocked requests",
    ["reason"],
)


RATE_LIMIT_EXCEEDED_TOTAL = Counter(
    "llm_gateway_rate_limit_exceeded_total",
    "Total number of rate limit violations",
)