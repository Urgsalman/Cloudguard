
import secrets

from fastapi import Header, HTTPException, status

from app.core.config import settings


def require_api_token(
    authorization: str | None = Header(default=None),
) -> None:
    configured_token = settings.api_token

    if not configured_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured.",
        )

    scheme, separator, supplied_token = (
        authorization.partition(" ")
        if authorization
        else ("", "", "")
    )

    if (
        scheme.lower() != "bearer"
        or not separator
        or not supplied_token
        or not secrets.compare_digest(
            supplied_token,
            configured_token,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
