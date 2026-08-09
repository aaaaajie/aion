"""Typed exceptions raised by the Challenges SDK."""

from typing import Any


class ChallengesSDKError(Exception):
    """Base class for all SDK-specific errors."""


class ChallengesAPIError(ChallengesSDKError):
    """An HTTP response containing an API or framework-level error."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str | None,
        message: str,
        detail: Any = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail
        super().__init__(self._safe_message())

    def _safe_message(self) -> str:
        error_code = self.code or "http_error"
        return f"{error_code}: {self.message} (HTTP {self.status_code})"


class ChallengesTransportError(ChallengesSDKError):
    """A request could not be sent or completed because of a network error."""

    def __init__(self, *, operation: str, cause: Exception) -> None:
        self.operation = operation
        self.cause = cause
        # Do not include the original exception string: URL strings can contain
        # deployment-specific data and should not be emitted by default.
        super().__init__(f"transport error while performing {operation}")


class ChallengesResponseError(ChallengesSDKError):
    """A successful response did not match the documented response model."""

    def __init__(self, *, operation: str, errors: Any) -> None:
        self.operation = operation
        self.errors = errors
        # Keep response payloads out of the exception string and logs.
        super().__init__(f"invalid response received for {operation}")
