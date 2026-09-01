from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import get_db_connection


# ============================================================
# INCIDENT CORRELATION CONFIGURATION
# ============================================================

CORRELATION_WINDOW_MINUTES = 10
MIN_SUSPICIOUS_EVENTS = 3


# Security events that can contribute to an incident.
SUSPICIOUS_EVENTS = {
    "UNAUTHORIZED_REQUEST",
    "AUTHENTICATION_BLOCKED",
    "THREAT_INTELLIGENCE_BLOCK",
    "PROMPT_INJECTION_DETECTED",
    "JAILBREAK_DETECTED",
    "UNSAFE_OUTPUT_DETECTED",
    "SECRET_DETECTED",
    "RATE_LIMIT_EXCEEDED",
    "PAYLOAD_TOO_LARGE",
    "INVALID_CONTENT_TYPE",
}


@dataclass
class IncidentCorrelationResult:
    """Result produced by the incident correlation engine."""

    incident_detected: bool
    event_count: int
    risk_level: str
    correlated_events: list[dict[str, Any]]
    correlation_reason: str


def _calculate_risk_level(event_count: int) -> str:
    """Calculate incident risk level from event count."""

    if event_count >= 7:
        return "CRITICAL"

    if event_count >= 5:
        return "HIGH"

    if event_count >= 3:
        return "MEDIUM"

    return "LOW"


def _build_correlation_reason(
    events: list[dict[str, Any]],
) -> str:
    """Build a readable explanation for the correlated incident."""

    event_names = sorted(
        {
            event.get("event", "UNKNOWN")
            for event in events
        }
    )

    return (
        "Multiple suspicious security events detected "
        "within the correlation window: "
        + ", ".join(event_names)
    )


def correlate_security_events(
    api_key: str | None = None,
    client_ip: str | None = None,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> IncidentCorrelationResult:
    """
    Correlate suspicious events belonging to the same
    API key or client IP within a time window.

    Correlation identity is searched inside the existing
    PostgreSQL 'details' column.
    """

    if not api_key and not client_ip:
        return IncidentCorrelationResult(
            incident_detected=False,
            event_count=0,
            risk_level="LOW",
            correlated_events=[],
            correlation_reason=(
                "No correlation identity provided"
            ),
        )

    cutoff_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=window_minutes)
    )

    identity_patterns = []

    if api_key:
        identity_patterns.append(
            f"%api_key={api_key}%"
        )

    if client_ip:
        identity_patterns.append(
            f"%client_ip={client_ip}%"
        )

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        event,
                        request_id,
                        details,
                        severity,
                        created_at
                    FROM security_audit_events
                    WHERE created_at >= %s
                      AND event = ANY(%s)
                      AND details ILIKE ANY(%s)
                    ORDER BY created_at DESC
                    """,
                    (
                        cutoff_time,
                        list(SUSPICIOUS_EVENTS),
                        identity_patterns,
                    ),
                )

                events = cursor.fetchall()

    except Exception:
        return IncidentCorrelationResult(
            incident_detected=False,
            event_count=0,
            risk_level="LOW",
            correlated_events=[],
            correlation_reason=(
                "Unable to query audit events"
            ),
        )

    event_count = len(events)

    incident_detected = (
        event_count >= MIN_SUSPICIOUS_EVENTS
    )

    risk_level = _calculate_risk_level(event_count)

    if incident_detected:
        reason = _build_correlation_reason(events)
    else:
        reason = (
            "No correlated security incident detected"
        )

    return IncidentCorrelationResult(
        incident_detected=incident_detected,
        event_count=event_count,
        risk_level=risk_level,
        correlated_events=events,
        correlation_reason=reason,
    )