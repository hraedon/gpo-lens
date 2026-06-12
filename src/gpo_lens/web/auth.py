from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable

from fastapi import Depends, Header, HTTPException


class Permission(Enum):
    VIEW = "view"
    INGEST = "ingest"
    NARRATE = "narrate"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "viewer": {Permission.VIEW},
    "operator": {Permission.VIEW, Permission.INGEST},
    "admin": {Permission.VIEW, Permission.INGEST, Permission.NARRATE, Permission.ADMIN},
}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    permissions: frozenset[Permission]

    def has(self, perm: Permission) -> bool:
        return perm in self.permissions


LOCAL_PRINCIPAL = Principal(
    name="local-analyst",
    role="admin",
    permissions=frozenset(Permission),
)

def _get_auth_token() -> str:
    return os.environ.get("GPO_LENS_AUTH_TOKEN", "")


def get_principal(
    authorization: str | None = Header(default=None),
) -> Principal:
    auth_token = _get_auth_token()
    # If no token configured, allow all (local dev mode)
    if not auth_token:
        return LOCAL_PRINCIPAL
    # Validate bearer token
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")
    if not hmac.compare_digest(token, auth_token):
        raise HTTPException(status_code=401, detail="Invalid token")
    return LOCAL_PRINCIPAL


def requires(permission: Permission) -> Callable[..., Awaitable[Principal]]:
    async def _check(
        principal: Principal = Depends(get_principal),
    ) -> Principal:
        if not principal.has(permission):
            raise HTTPException(status_code=403, detail="Forbidden")
        return principal

    _check._required_permission = permission  # type: ignore[attr-defined]
    return _check
