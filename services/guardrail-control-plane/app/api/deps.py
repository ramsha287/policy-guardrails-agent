from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, Request

from ..domain.rbac import Principal
from .container import Container


def container(request: Request) -> Container:
    return request.app.state.container


async def principal(
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
    c: Container = Depends(container),
) -> Principal:
    p = await c.admin_keys.authenticate(x_admin_key)
    if p is None:
        raise HTTPException(status_code=401, detail="Missing, invalid or revoked admin key")
    return p


async def internal(
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
    c: Container = Depends(container),
) -> None:
    if not x_internal_token or not hmac.compare_digest(x_internal_token, c.internal_token):
        raise HTTPException(status_code=401, detail="Invalid internal token")
