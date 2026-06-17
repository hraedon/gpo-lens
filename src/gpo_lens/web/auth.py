from __future__ import annotations

import hmac
import ipaddress
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable

from fastapi import Depends, Header, HTTPException, Request


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

# The web server refuses to bind to a non-loopback address without an auth
# token (see cli/_serve.py), so "no token configured" implies a single local
# operator on their own machine. That operator gets the full local analyst
# capability set (view + ingest + narrate) — withholding ADMIN keeps "admin"
# meaning "explicitly authenticated via token".
LOOPBACK_PRINCIPAL = Principal(
    name="local-analyst",
    role="local",
    permissions=frozenset(
        {Permission.VIEW, Permission.INGEST, Permission.NARRATE}
    ),
)


def _get_auth_token() -> str:
    return os.environ.get("GPO_LENS_AUTH_TOKEN", "")


def _is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    # IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped.is_loopback
    return False


def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Principal:
    auth_token = _get_auth_token()
    # If no token configured, allow loopback only (local dev mode)
    if not auth_token:
        if _is_loopback(request.client.host if request.client else None):
            return LOOPBACK_PRINCIPAL
        raise HTTPException(
            status_code=401,
            detail="Unauthorized. Authentication required.",
        )
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
