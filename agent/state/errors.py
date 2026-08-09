"""Safe domain errors shared by the state service and HTTP layer."""

from __future__ import annotations

from typing import Any


class StateError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}


class StateNotFound(StateError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=404)


class StateConflict(StateError):
    def __init__(self, code: str, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(code, message, status_code=409, detail=detail)


class StatePermission(StateError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=403)

