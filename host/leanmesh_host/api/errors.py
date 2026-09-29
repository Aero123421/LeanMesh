"""The OpenAPI Error envelope. `code` uses the registry status names (protocol/registry.json)."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    def __init__(self, http_status: int, code: str, message: str,
                 retry_after_ms: int | None = None, **details: Any) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.retry_after_ms = retry_after_ms
        self.details = details


def invalid(message: str, **details: Any) -> ApiError:
    return ApiError(400, "INVALID_ARGUMENT", message, **details)


def not_found(what: str) -> ApiError:
    # One message for "absent" and "owned by another principal": no information leaks by ID guessing.
    return ApiError(404, "NOT_FOUND", f"{what} not found")


def no_capacity(resource: str, http_status: int = 507, retry_after_ms: int | None = None) -> ApiError:
    return ApiError(http_status, "NO_CAPACITY", f"{resource} capacity exhausted",
                    retry_after_ms=retry_after_ms, resource=resource)
