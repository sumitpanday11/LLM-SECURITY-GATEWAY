import logging
import os
from logging.handlers import RotatingFileHandler

from app.database import get_db_connection

from app.metrics import (
    SECURITY_EVENTS_TOTAL,
    AUTH_FAILURES_TOTAL,
    BLOCKED_REQUESTS_TOTAL,
    RATE_LIMIT_EXCEEDED_TOTAL,
)


LOG_DIR = "logs"
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "security_audit.log")

MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 5


os.makedirs(LOG_DIR, exist_ok=True)


audit_logger = logging.getLogger("security-audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False


if not audit_logger.handlers:
    file_handler = RotatingFileHandler(
        AUDIT_LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler.setFormatter(formatter)
    audit_logger.addHandler(file_handler)


def log_security_event(
    event: str,
    request_id: str,
    details: str = "",
    severity: str = "WARNING",
):
    """
    Store security events in:
    1. Rotating audit log file
    2. PostgreSQL database
    3. Prometheus security metrics
    """

    # ========================================================
    # PROMETHEUS SECURITY METRICS
    # ========================================================

    SECURITY_EVENTS_TOTAL.labels(
        event=event
    ).inc()

    if event in {
        "UNAUTHORIZED_REQUEST",
        "AUTHENTICATION_BLOCKED",
    }:
        AUTH_FAILURES_TOTAL.inc()

    if event in {
        "THREAT_INTELLIGENCE_BLOCK",
        "PROMPT_INJECTION_DETECTED",
        "PAYLOAD_TOO_LARGE",
        "INVALID_CONTENT_TYPE",
        "UNSAFE_OUTPUT_DETECTED",
    }:
        BLOCKED_REQUESTS_TOTAL.labels(
            reason=event
        ).inc()

    if event == "RATE_LIMIT_EXCEEDED":
        RATE_LIMIT_EXCEEDED_TOTAL.inc()

    # ========================================================
    # FILE-BASED AUDIT LOGGING
    # ========================================================

    audit_logger.warning(
        "SECURITY_EVENT | event=%s | request_id=%s | details=%s",
        event,
        request_id,
        details,
    )

    # ========================================================
    # POSTGRESQL AUDIT STORAGE
    # ========================================================

    try:
        with get_db_connection() as conn:

            with conn.cursor() as cursor:

                cursor.execute(
                    """
                    INSERT INTO security_audit_events
                    (
                        event,
                        request_id,
                        details,
                        severity
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        event,
                        request_id,
                        details,
                        severity,
                    ),
                )

            conn.commit()

    except Exception as exc:

        audit_logger.error(
            "AUDIT_DATABASE_ERROR | error=%s",
            str(exc),
        )