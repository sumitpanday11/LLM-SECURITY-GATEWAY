from app.secret_detection import detect_secrets, redact_secrets


def test_clean_text_has_no_secret():
    result = detect_secrets("Hello, how are you?")

    assert result.detected is False
    assert result.secrets == []
    assert result.redacted_text == "Hello, how are you?"


def test_openai_api_key_is_detected():
    text = "API key: sk-abcdefghijklmnopqrstuvwxyz123456"

    result = detect_secrets(text)

    assert result.detected is True
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" in result.secrets
    assert "[REDACTED_SECRET]" in result.redacted_text


def test_github_token_is_detected():
    text = "token: ghp_abcdefghijklmnopqrstuvwxyz123456"

    result = detect_secrets(text)

    assert result.detected is True
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" in result.secrets


def test_aws_access_key_is_detected():
    text = "AWS key: AKIA1234567890ABCDEF"

    result = detect_secrets(text)

    assert result.detected is True
    assert "AKIA1234567890ABCDEF" in result.secrets


def test_bearer_token_is_detected():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"

    result = detect_secrets(text)

    assert result.detected is True
    assert "[REDACTED_SECRET]" in result.redacted_text


def test_password_is_detected():
    text = "password: SuperSecretPassword123"

    result = detect_secrets(text)

    assert result.detected is True
    assert "[REDACTED_SECRET]" in result.redacted_text


def test_api_key_assignment_is_detected():
    text = "api_key = abcdefghijklmnopqrstuvwxyz123456"

    result = detect_secrets(text)

    assert result.detected is True
    assert "[REDACTED_SECRET]" in result.redacted_text


def test_redact_secrets_helper():
    text = "password: MySecretPassword123"

    result = redact_secrets(text)

    assert result == "[REDACTED_SECRET]"


def test_llm_output_secret_is_redacted():
    llm_output = (
        "The API key is "
        "sk-abcdefghijklmnopqrstuvwxyz123456"
    )

    result = detect_secrets(llm_output)

    assert result.detected is True
    assert result.redacted_text == (
        "The API key is [REDACTED_SECRET]"
    )
    assert (
        "sk-abcdefghijklmnopqrstuvwxyz123456"
        not in result.redacted_text
    )