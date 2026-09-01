from datetime import datetime, timezone
from unittest.mock import patch

from app.incident_correlation import (
    IncidentCorrelationResult,
    _calculate_risk_level,
    correlate_security_events,
)


def test_risk_level_low():
    assert _calculate_risk_level(0) == "LOW"
    assert _calculate_risk_level(2) == "LOW"


def test_risk_level_medium():
    assert _calculate_risk_level(3) == "MEDIUM"
    assert _calculate_risk_level(4) == "MEDIUM"


def test_risk_level_high():
    assert _calculate_risk_level(5) == "HIGH"
    assert _calculate_risk_level(6) == "HIGH"


def test_risk_level_critical():
    assert _calculate_risk_level(7) == "CRITICAL"
    assert _calculate_risk_level(10) == "CRITICAL"


def test_no_identity_does_not_create_incident():
    result = correlate_security_events()

    assert isinstance(result, IncidentCorrelationResult)
    assert result.incident_detected is False
    assert result.event_count == 0
    assert result.risk_level == "LOW"


@patch("app.incident_correlation.get_db_connection")
def test_no_incident_for_two_events(mock_db):
    events = [
        {
            "id": 1,
            "event": "PROMPT_INJECTION_DETECTED",
            "request_id": "req-1",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        },
        {
            "id": 2,
            "event": "RATE_LIMIT_EXCEEDED",
            "request_id": "req-2",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        },
    ]

    mock_cursor = mock_db.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    mock_cursor.fetchall.return_value = events

    result = correlate_security_events(
        api_key="test-key",
        client_ip="127.0.0.1",
    )

    assert result.incident_detected is False
    assert result.event_count == 2
    assert result.risk_level == "LOW"


@patch("app.incident_correlation.get_db_connection")
def test_incident_detected_for_three_events(mock_db):
    events = [
        {
            "id": 1,
            "event": "PROMPT_INJECTION_DETECTED",
            "request_id": "req-1",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        },
        {
            "id": 2,
            "event": "JAILBREAK_DETECTED",
            "request_id": "req-2",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        },
        {
            "id": 3,
            "event": "UNSAFE_OUTPUT_DETECTED",
            "request_id": "req-3",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        },
    ]

    mock_cursor = mock_db.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    mock_cursor.fetchall.return_value = events

    result = correlate_security_events(
        api_key="test-key",
        client_ip="127.0.0.1",
    )

    assert result.incident_detected is True
    assert result.event_count == 3
    assert result.risk_level == "MEDIUM"
    assert len(result.correlated_events) == 3
    assert "JAILBREAK_DETECTED" in result.correlation_reason


@patch("app.incident_correlation.get_db_connection")
def test_high_risk_incident(mock_db):
    events = [
        {
            "id": index,
            "event": "PROMPT_INJECTION_DETECTED",
            "request_id": f"req-{index}",
            "details": "api_key=test-key client_ip=127.0.0.1",
            "severity": "WARNING",
            "created_at": datetime.now(timezone.utc),
        }
        for index in range(1, 6)
    ]

    mock_cursor = mock_db.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    mock_cursor.fetchall.return_value = events

    result = correlate_security_events(
        api_key="test-key",
        client_ip="127.0.0.1",
    )

    assert result.incident_detected is True
    assert result.event_count == 5
    assert result.risk_level == "HIGH"