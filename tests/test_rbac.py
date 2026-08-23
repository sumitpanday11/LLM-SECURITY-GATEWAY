from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.rbac import (
    get_api_key_role,
    require_permission,
)


# ============================================================
# get_api_key_role Tests
# ============================================================


def test_admin_api_key_returns_admin_role():
    metadata = {
        "key_id": "admin-key",
        "active": True,
        "role": "admin",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = get_api_key_role("admin-api-key")

    assert result == "admin"


def test_user_api_key_returns_user_role():
    metadata = {
        "key_id": "user-key",
        "active": True,
        "role": "user",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = get_api_key_role("user-api-key")

    assert result == "user"


def test_missing_api_key_returns_401():
    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=None,
    ):
        with pytest.raises(HTTPException) as exc_info:
            get_api_key_role("missing-api-key")

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "API key not found"


# ============================================================
# Permission Tests
# ============================================================


def test_admin_can_generate_key():
    metadata = {
        "key_id": "admin-key",
        "active": True,
        "role": "admin",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = require_permission(
            "admin-api-key",
            "key_generate",
        )

    assert result == "admin"


def test_admin_can_revoke_key():
    metadata = {
        "key_id": "admin-key",
        "active": True,
        "role": "admin",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = require_permission(
            "admin-api-key",
            "key_revoke",
        )

    assert result == "admin"


def test_user_can_access_chat():
    metadata = {
        "key_id": "user-key",
        "active": True,
        "role": "user",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = require_permission(
            "user-api-key",
            "chat",
        )

    assert result == "user"


def test_user_can_access_key_info():
    metadata = {
        "key_id": "user-key",
        "active": True,
        "role": "user",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        result = require_permission(
            "user-api-key",
            "key_info",
        )

    assert result == "user"


def test_user_cannot_generate_key():
    metadata = {
        "key_id": "user-key",
        "active": True,
        "role": "user",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        with pytest.raises(HTTPException) as exc_info:
            require_permission(
                "user-api-key",
                "key_generate",
            )

    assert exc_info.value.status_code == 403
    assert "does not have permission" in exc_info.value.detail


def test_unknown_role_cannot_access_permission():
    metadata = {
        "key_id": "unknown-key",
        "active": True,
        "role": "unknown",
    }

    with patch(
        "app.rbac.get_api_key_metadata",
        return_value=metadata,
    ):
        with pytest.raises(HTTPException) as exc_info:
            require_permission(
                "unknown-api-key",
                "chat",
            )

    assert exc_info.value.status_code == 403