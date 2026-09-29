"""Authentication and permission dependencies (docs/11 §1, SEMANTICS 'Permissions')."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from ..auth import PERMISSIONS, Principal, authenticate
from .errors import ApiError

WRITE_PERMISSIONS = tuple(sorted(PERMISSIONS - {"READ"}))


def require(*any_of: str) -> Any:
    """FastAPI dependency: bearer token -> principal holding at least one of `any_of`."""

    def dependency(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ApiError(401, "UNAUTHENTICATED", "bearer token required")
        found = authenticate(request.app.state.principals, token)
        if found is None:
            raise ApiError(401, "UNAUTHENTICATED", "unknown token")
        if not found.permissions.intersection(any_of):
            raise ApiError(403, "FORBIDDEN", "permission required",
                           required=any_of[0] if len(any_of) == 1 else list(any_of))
        return found

    return Depends(dependency)


def need_all(principal: Principal, permissions: tuple[str, ...]) -> None:
    missing = [p for p in permissions if p not in principal.permissions]
    if missing:
        raise ApiError(403, "FORBIDDEN", "permission required", required=missing)
