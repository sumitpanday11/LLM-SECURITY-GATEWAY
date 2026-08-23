from unittest.mock import MagicMock, patch

from app.audit_log import log_security_event


def test_security_event_is_written_to_postgresql():
    mock_cursor = MagicMock()
    mock_connection = MagicMock()

    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ) as security_events, patch(
        "app.audit_log.audit_logger"
    ):

        log_security_event(
            event="PROMPT_INJECTION_DETECTED",
            request_id="test-request-001",
            details="Test prompt injection",
            severity="WARNING",
        )

    mock_cursor.execute.assert_called_once()

    query = mock_cursor.execute.call_args.args[0]
    params = mock_cursor.execute.call_args.args[1]

    assert "INSERT INTO security_audit_events" in query
    assert "event" in query
    assert "request_id" in query
    assert "details" in query
    assert "severity" in query

    assert params == (
        "PROMPT_INJECTION_DETECTED",
        "test-request-001",
        "Test prompt injection",
        "WARNING",
    )

    mock_connection.commit.assert_called_once()

    security_events.labels.assert_called_once_with(
        event="PROMPT_INJECTION_DETECTED"
    )


def test_authentication_failure_increments_auth_metric():
    mock_connection = MagicMock()

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ), patch(
        "app.audit_log.AUTH_FAILURES_TOTAL"
    ) as auth_failures, patch(
        "app.audit_log.audit_logger"
    ):

        log_security_event(
            event="UNAUTHORIZED_REQUEST",
            request_id="auth-test-001",
        )

    auth_failures.inc.assert_called_once()


def test_rate_limit_event_increments_rate_limit_metric():
    mock_connection = MagicMock()

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ), patch(
        "app.audit_log.RATE_LIMIT_EXCEEDED_TOTAL"
    ) as rate_limit_metric, patch(
        "app.audit_log.audit_logger"
    ):

        log_security_event(
            event="RATE_LIMIT_EXCEEDED",
            request_id="rate-test-001",
        )

    rate_limit_metric.inc.assert_called_once()


def test_blocked_security_event_increments_blocked_metric():
    mock_connection = MagicMock()

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ), patch(
        "app.audit_log.BLOCKED_REQUESTS_TOTAL"
    ) as blocked_metric, patch(
        "app.audit_log.audit_logger"
    ):

        log_security_event(
            event="PAYLOAD_TOO_LARGE",
            request_id="payload-test-001",
        )

    blocked_metric.labels.assert_called_once_with(
        reason="PAYLOAD_TOO_LARGE"
    )


def test_audit_database_failure_does_not_crash_request():
    mock_connection = MagicMock()

    mock_connection.__enter__.side_effect = Exception(
        "PostgreSQL unavailable"
    )

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ), patch(
        "app.audit_log.audit_logger"
    ) as audit_logger:

        log_security_event(
            event="AUTHENTICATION_BLOCKED",
            request_id="db-failure-test-001",
            details="Database failure test",
        )

    audit_logger.error.assert_called_once()


def test_default_severity_is_warning():
    mock_cursor = MagicMock()
    mock_connection = MagicMock()

    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

    with patch(
        "app.audit_log.get_db_connection",
        return_value=mock_connection,
    ), patch(
        "app.audit_log.SECURITY_EVENTS_TOTAL"
    ), patch(
        "app.audit_log.audit_logger"
    ):

        log_security_event(
            event="TEST_EVENT",
            request_id="severity-test-001",
        )

    params = mock_cursor.execute.call_args.args[1]

    assert params[3] == "WARNING"