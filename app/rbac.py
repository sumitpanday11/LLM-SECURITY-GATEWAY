from fastapi import HTTPException

from app.security import get_api_key_metadata


ROLE_PERMISSIONS = {
    "admin": {
        "chat",
        "key_generate",
        "key_revoke",
        "key_rotate",
        "key_info",
    },
    "user": {
        "chat",
        "key_info",
    },
}


def get_api_key_role(api_key: str) -> str:
    metadata = get_api_key_metadata(api_key)

    if metadata is None:
        raise HTTPException(
            status_code=401,
            detail="API key not found",
        )

    return metadata.get("role", "user")


def require_permission(
    api_key: str,
    permission: str,
) -> str:
    role = get_api_key_role(api_key)

    permissions = ROLE_PERMISSIONS.get(role, set())

    if permission not in permissions:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Role '{role}' does not have permission "
                f"for '{permission}'"
            ),
        )

    return role