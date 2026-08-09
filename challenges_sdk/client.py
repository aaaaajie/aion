"""Async HTTP client for the TSec Benchmark Challenges API."""

from collections.abc import Mapping
from typing import Any, TypeVar

import httpx
from pydantic import SecretStr, TypeAdapter, ValidationError

from .config import ChallengesSettings
from .exceptions import (
    ChallengesAPIError,
    ChallengesResponseError,
    ChallengesTransportError,
)
from .models import (
    Challenge,
    ChallengeCloseResponse,
    ChallengeHintResponse,
    ChallengeStartResponse,
    SubmitFlagRequest,
    SubmitFlagResponse,
)

ResponseModel = TypeVar("ResponseModel")


class ChallengesClient:
    """An async client for all documented Challenges API operations.

    The client owns its internally-created ``httpx.AsyncClient``. An existing
    client can be injected for tests or for callers that need to manage the
    HTTP client's lifecycle themselves.
    """

    API_PREFIX = "/openapi/v1/challenges"

    def __init__(
        self,
        base_url: str,
        token: str | SecretStr,
        *,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float | httpx.Timeout = 30.0,
    ) -> None:
        if client is not None and transport is not None:
            raise ValueError("client and transport are mutually exclusive")

        normalized_base_url = str(base_url).rstrip("/")
        if not normalized_base_url:
            raise ValueError("base_url must not be empty")

        token_value = token.get_secret_value() if isinstance(token, SecretStr) else token
        if not token_value:
            raise ValueError("token must not be empty")

        self._base_url = normalized_base_url
        self._token = token_value
        self._client = client or httpx.AsyncClient(transport=transport, timeout=timeout)
        self._owns_client = client is None

    @classmethod
    def from_settings(
        cls,
        settings: ChallengesSettings,
        **kwargs: Any,
    ) -> "ChallengesClient":
        """Build a client from validated settings without exposing the token."""

        return cls(
            str(settings.benchmark_base_url),
            settings.benchmark_token,
            **kwargs,
        )

    @classmethod
    def from_env(cls, **kwargs: Any) -> "ChallengesClient":
        """Build a client from ``BENCHMARK_*`` environment settings."""

        return cls.from_settings(ChallengesSettings(), **kwargs)

    async def __aenter__(self) -> "ChallengesClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the internally-owned HTTP client."""

        if self._owns_client:
            await self._client.aclose()

    async def list_challenges(self) -> list[Challenge]:
        return await self._request("GET", "", list[Challenge])

    async def start_challenge(self, unique_code: str) -> ChallengeStartResponse:
        return await self._request(
            "POST",
            "/start",
            ChallengeStartResponse,
            params={"unique_code": self._require_unique_code(unique_code)},
        )

    async def get_hint(self, unique_code: str) -> ChallengeHintResponse:
        return await self._request(
            "GET",
            "/hint",
            ChallengeHintResponse,
            params={"unique_code": self._require_unique_code(unique_code)},
        )

    async def submit_flag(self, unique_code: str, flag: str) -> SubmitFlagResponse:
        request = SubmitFlagRequest(unique_code=unique_code, flag=flag)
        return await self._request(
            "POST",
            "/submit",
            SubmitFlagResponse,
            json_body=request.model_dump(mode="json"),
        )

    async def close_challenge(self, unique_code: str) -> ChallengeCloseResponse:
        return await self._request(
            "POST",
            "/close",
            ChallengeCloseResponse,
            params={"unique_code": self._require_unique_code(unique_code)},
        )

    @staticmethod
    def _require_unique_code(unique_code: str) -> str:
        if not isinstance(unique_code, str) or not unique_code.strip():
            raise ValueError("unique_code must not be empty")
        return unique_code

    async def _request(
        self,
        method: str,
        suffix: str,
        response_model: Any,
        *,
        params: Mapping[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        operation = f"{method} {self.API_PREFIX}{suffix}"
        url = f"{self._base_url}{self.API_PREFIX}{suffix}"

        try:
            response = await self._client.request(
                method,
                url,
                headers={"BENCHMARK_TOKEN": self._token},
                params=params,
                json=json_body,
            )
        except httpx.HTTPError as exc:
            raise ChallengesTransportError(operation=operation, cause=exc) from exc

        if not 200 <= response.status_code < 300:
            raise self._api_error(response)

        try:
            payload = response.json()
            return TypeAdapter(response_model).validate_python(payload)
        except (ValueError, ValidationError) as exc:
            errors = exc.errors() if isinstance(exc, ValidationError) else None
            raise ChallengesResponseError(operation=operation, errors=errors) from exc

    @staticmethod
    def _api_error(response: httpx.Response) -> ChallengesAPIError:
        code: str | None = None
        message = "request failed"
        detail: Any = None

        try:
            payload = response.json()
        except ValueError:
            payload = None

        if isinstance(payload, dict):
            code = payload.get("code")
            message = payload.get("message") or message
            detail = payload.get("detail")
        elif payload is not None:
            detail = payload

        return ChallengesAPIError(
            status_code=response.status_code,
            code=code,
            message=str(message),
            detail=detail,
        )
