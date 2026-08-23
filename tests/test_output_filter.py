import pytest

from app.output_filter import (
    detect_unsafe_output,
    redact_unsafe_output,
    filter_unsafe_output,
)


# ============================================================
# Safe Output Tests
# ============================================================


def test_safe_output_is_not_flagged():
    output = "Hello, this is a normal response."

    detected = detect_unsafe_output(output)

    assert detected == []


# ============================================================
# Unsafe Output Detection Tests
# ============================================================


def test_system_prompt_leak_is_detected():
    output = "Here is the system prompt used by the assistant."

    detected = detect_unsafe_output(output)

    assert "SYSTEM_PROMPT_LEAK" in detected


def test_secret_leak_is_detected():
    output = "api_key: test-secret-12345"

    detected = detect_unsafe_output(output)

    assert "SECRET_LEAK" in detected


def test_credential_leak_is_detected():
    output = "authorization: Bearer abc123secret"

    detected = detect_unsafe_output(output)

    assert "CREDENTIAL_LEAK" in detected


def test_dangerous_instruction_is_detected():
    output = "Disable security controls before continuing."

    detected = detect_unsafe_output(output)

    assert "DANGEROUS_INSTRUCTION" in detected


def test_malicious_code_output_is_detected():
    output = "Run rm -rf / immediately."

    detected = detect_unsafe_output(output)

    assert "MALICIOUS_CODE_OUTPUT" in detected


# ============================================================
# Redaction Tests
# ============================================================


def test_system_prompt_is_redacted():
    output = "The system prompt contains confidential rules."

    redacted = redact_unsafe_output(output)

    assert "[REDACTED_SYSTEM_INSTRUCTION]" in redacted
    assert "system prompt" not in redacted.lower()


def test_secret_is_redacted():
    output = "api_key: test-secret-12345"

    redacted = redact_unsafe_output(output)

    assert "[REDACTED_SECRET]" in redacted
    assert "test-secret-12345" not in redacted


def test_credential_is_redacted():
    output = "authorization: Bearer abc123secret"

    redacted = redact_unsafe_output(output)

    assert "[REDACTED_CREDENTIAL]" in redacted
    assert "abc123secret" not in redacted


def test_dangerous_instruction_is_redacted():
    output = "Disable security controls immediately."

    redacted = redact_unsafe_output(output)

    assert "[REDACTED_UNSAFE_INSTRUCTION]" in redacted


def test_malicious_code_is_redacted():
    output = "Please run rm -rf / on the server."

    redacted = redact_unsafe_output(output)

    assert "[REDACTED_MALICIOUS_CONTENT]" in redacted
    assert "rm -rf /" not in redacted


# ============================================================
# Combined Filter Tests
# ============================================================


def test_filter_safe_output_returns_original_output():
    output = "Everything is working correctly."

    sanitized_output, detected_types = filter_unsafe_output(output)

    assert sanitized_output == output
    assert detected_types == []


def test_filter_unsafe_output_returns_sanitized_output():
    output = "api_key: test-secret-12345"

    sanitized_output, detected_types = filter_unsafe_output(output)

    assert "SECRET_LEAK" in detected_types
    assert "[REDACTED_SECRET]" in sanitized_output
    assert "test-secret-12345" not in sanitized_output


def test_filter_detects_multiple_unsafe_categories():
    output = (
        "system prompt: confidential instructions. "
        "api_key: secret123"
    )

    sanitized_output, detected_types = filter_unsafe_output(output)

    assert "SYSTEM_PROMPT_LEAK" in detected_types
    assert "SECRET_LEAK" in detected_types

    assert "[REDACTED_SYSTEM_INSTRUCTION]" in sanitized_output
    assert "[REDACTED_SECRET]" in sanitized_output


def test_filter_preserves_safe_text():
    output = (
        "Hello user. "
        "Your request was processed successfully."
    )

    sanitized_output, detected_types = filter_unsafe_output(output)

    assert sanitized_output == output
    assert detected_types == []