"""Async HTTP client for the TSec Benchmark Challenges API."""

from collections.abc import Mapping
from contextvars import ContextVar
import json
import logging
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
from .recovery import (
    BenchmarkOperationContract,
    ContractRecoveryContext,
    ContractRecoverer,
    DEFAULT_OPERATION_CONTRACTS,
    OperationName,
    ResponseRecoveryContext,
    ResponseRecoverer,
    default_operation_contracts,
    normalize_response_payload,
    openapi_candidates,
    payload_is_truncated,
    parse_openapi_contracts,
    response_digest,
    sanitize_payload,
    validate_contract_mapping,
)

ResponseModel = TypeVar("ResponseModel")
LOGGER = logging.getLogger("aion.benchmark_sdk")


_CALL_EVENTS: ContextVar[list[dict[str, Any]] | None] = ContextVar(
    "aion_benchmark_call_events", default=None
)


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
        start_timeout: float = 960.0,
        response_recoverer: ResponseRecoverer | None = None,
        contract_recoverer: ContractRecoverer | None = None,
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
        self._start_timeout = start_timeout
        self._owns_client = client is None
        self._response_recoverer = response_recoverer
        self._contract_recoverer = contract_recoverer
        self._contracts: dict[OperationName, BenchmarkOperationContract] = (
            default_operation_contracts()
        )
        self._contract_lock = None
        self._contract_ready = contract_recoverer is None
        self._contract_source = "fixed"

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

    def take_call_events(self) -> list[dict[str, Any]]:
        """Return and clear recovery metadata for the current async call."""

        events = list(_CALL_EVENTS.get() or [])
        _CALL_EVENTS.set([])
        return events

    @property
    def contracts(self) -> dict[OperationName, BenchmarkOperationContract]:
        return dict(self._contracts)

    @property
    def contract_source(self) -> str:
        return self._contract_source

    async def list_challenges(self) -> list[Challenge]:
        self._begin_call()
        return await self._request("list_challenges", list[Challenge])

    async def start_challenge(self, unique_code: str) -> ChallengeStartResponse:
        self._begin_call()
        return await self._request(
            "start_challenge",
            ChallengeStartResponse,
            unique_code=self._require_unique_code(unique_code),
            timeout=self._start_timeout,
        )

    async def get_hint(self, unique_code: str) -> ChallengeHintResponse:
        self._begin_call()
        return await self._request(
            "get_hint",
            ChallengeHintResponse,
            unique_code=self._require_unique_code(unique_code),
        )

    async def submit_flag(self, unique_code: str, flag: str) -> SubmitFlagResponse:
        self._begin_call()
        request = SubmitFlagRequest(unique_code=unique_code, flag=flag)
        return await self._request(
            "submit_flag",
            SubmitFlagResponse,
            body=request.model_dump(mode="json"),
            unique_code=unique_code,
            secrets=(flag,),
        )

    async def close_challenge(self, unique_code: str) -> ChallengeCloseResponse:
        self._begin_call()
        return await self._request(
            "close_challenge",
            ChallengeCloseResponse,
            unique_code=self._require_unique_code(unique_code),
        )

    @staticmethod
    def _require_unique_code(unique_code: str) -> str:
        if not isinstance(unique_code, str) or not unique_code.strip():
            raise ValueError("unique_code must not be empty")
        return unique_code

    async def _request(
        self,
        operation: OperationName,
        response_model: Any,
        *,
        body: dict[str, Any] | None = None,
        unique_code: str | None = None,
        secrets: tuple[str, ...] = (),
        timeout: float | None = None,
    ) -> Any:
        await self._ensure_contract()
        contract = self._contracts[operation]
        params, json_body = self._request_payload(
            contract, unique_code=unique_code, body=body
        )
        operation_label = f"{contract.method} {contract.path}"
        url = self._url(contract.path)

        response = await self._send_request(
            contract,
            url,
            params=params,
            json_body=json_body,
            operation_label=operation_label,
            timeout=timeout,
        )
        alternate = self._alternate_request_payload(
            operation,
            contract,
            response,
            unique_code=unique_code,
        )
        if alternate is not None:
            alternate_params, alternate_body = alternate
            self._event(
                "benchmark_request_contract_adapted",
                operation=operation,
                from_query=bool(params and "unique_code" in params),
                to_query=bool(alternate_params and "unique_code" in alternate_params),
                status_code=response.status_code,
            )
            response = await self._send_request(
                contract,
                url,
                params=alternate_params,
                json_body=alternate_body,
                operation_label=operation_label,
                timeout=timeout,
            )

        if not 200 <= response.status_code < 300:
            if response.status_code in {404, 405, 501}:
                self._event(
                    "benchmark_capability_unavailable",
                    operation=operation,
                    status_code=response.status_code,
                    response_size=len(response.content),
                )
            raise self._api_error(response)

        raw_size = len(response.content)
        try:
            payload = response.json()
        except ValueError:
            payload = response.text

        adapter = TypeAdapter(response_model)
        for strategy, candidate in (
            ("exact", payload),
            (
                "deterministic_normalization",
                normalize_response_payload(
                    operation,
                    payload,
                    unique_code=unique_code,
                ),
            ),
        ):
            try:
                value = adapter.validate_python(candidate)
                if not _response_candidate_has_signal(operation, value):
                    continue
                if strategy != "exact":
                    self._event(
                        "benchmark_response_normalized",
                        operation=operation,
                        strategy=strategy,
                        status_code=response.status_code,
                        response_size=raw_size,
                        response_digest=response_digest(payload),
                    )
                    if operation in {
                        "start_challenge",
                        "submit_flag",
                        "close_challenge",
                    }:
                        raise ChallengesResponseError(
                            operation=operation_label,
                            errors=None,
                            status_code=response.status_code,
                            response_size=raw_size,
                            recovery_attempted=False,
                            requires_reconciliation=True,
                        )
                return value
            except ValidationError:
                continue

        if self._response_recoverer is not None:
            decision = await self._recover_response(
                operation,
                contract,
                response,
                payload,
                response_model,
                secrets=secrets + (self._token,),
            )
            if decision is not None:
                try:
                    value = adapter.validate_python(decision.data)
                    if (
                        decision.recoverable
                        and decision.confidence >= 0.9
                        and _response_candidate_has_signal(operation, value)
                    ):
                        self._event(
                            "benchmark_response_llm_recovered",
                            operation=operation,
                            status_code=response.status_code,
                            response_size=raw_size,
                            response_digest=response_digest(payload),
                            confidence=decision.confidence,
                        )
                        if operation in {
                            "start_challenge",
                            "submit_flag",
                            "close_challenge",
                        }:
                            raise ChallengesResponseError(
                                operation=operation_label,
                                errors=None,
                                status_code=response.status_code,
                                response_size=raw_size,
                                recovery_attempted=True,
                                requires_reconciliation=True,
                            )
                        return value
                except ValidationError:
                    pass
            self._event(
                "benchmark_response_recovery_failed",
                operation=operation,
                status_code=response.status_code,
                response_size=raw_size,
                response_digest=response_digest(payload),
            )
        errors = None
        try:
            adapter.validate_python(payload)
        except ValidationError as exc:
            errors = exc.errors()
        raise ChallengesResponseError(
            operation=operation_label,
            errors=errors,
            status_code=response.status_code,
            response_size=raw_size,
            recovery_attempted=self._response_recoverer is not None,
            requires_reconciliation=False,
        )

    async def _recover_response(
        self,
        operation: OperationName,
        contract: BenchmarkOperationContract,
        response: httpx.Response,
        payload: Any,
        response_model: Any,
        *,
        secrets: tuple[str, ...],
    ) -> Any:
        sanitized_payload = sanitize_payload(payload, secrets=secrets)
        if payload_is_truncated(sanitized_payload):
            return None
        context = ResponseRecoveryContext(
            operation=operation,
            method=contract.method,
            path=contract.path,
            status_code=response.status_code,
            content_type=response.headers.get("content-type"),
            payload=sanitized_payload,
            expected_schema=TypeAdapter(response_model).json_schema(),
            response_size=len(response.content),
        )
        try:
            return await self._response_recoverer.recover(context)
        except Exception:
            LOGGER.exception("benchmark response recoverer failed operation=%s", operation)
            return None

    async def _ensure_contract(self) -> None:
        if self._contract_ready:
            return
        # The first benchmark call is already after VPN setup in production.
        # Avoid adding an asyncio lock dependency to direct SDK-only usage.
        if self._contract_lock is None:
            import asyncio

            self._contract_lock = asyncio.Lock()
        async with self._contract_lock:
            if self._contract_ready:
                return
            self._contract_ready = True
            try:
                response = await self._client.get(
                    self._url("/openapi.json"),
                    headers={"BENCHMARK_TOKEN": self._token},
                    timeout=5.0,
                )
                if 200 <= response.status_code < 300:
                    document = response.json()
                    discovered = parse_openapi_contracts(document)
                    candidates = openapi_candidates(document)
                    missing = tuple(
                        operation
                        for operation in DEFAULT_OPERATION_CONTRACTS
                        if operation not in discovered
                    )
                    if missing and self._contract_recoverer is not None and candidates:
                        try:
                            recovered = await self._contract_recoverer.recover_contract(
                                ContractRecoveryContext(candidates, missing)
                            )
                        except Exception:
                            LOGGER.exception("benchmark OpenAPI recoverer failed")
                            recovered = None
                        discovered.update(validate_contract_mapping(recovered))
                    self._contracts.update(discovered)
                    self._contract_source = (
                        "llm_openapi"
                        if any(item.source == "llm_openapi" for item in discovered.values())
                        else "openapi"
                    )
                    self._event(
                        "benchmark_contract_discovered",
                        source=self._contract_source,
                        operations=sorted(discovered),
                    )
            except (httpx.HTTPError, ValueError, TypeError):
                # The fixed contract remains authoritative when discovery is absent.
                LOGGER.info("benchmark OpenAPI discovery unavailable; using fixed contract")

    def _request_payload(
        self,
        contract: BenchmarkOperationContract,
        *,
        unique_code: str | None,
        body: dict[str, Any] | None,
    ) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
        params: dict[str, str] = {}
        json_body = dict(body or {}) if body is not None else None
        if unique_code is not None:
            if "unique_code" in contract.query_fields or (
                not contract.body_fields and contract.operation != "submit_flag"
            ):
                params["unique_code"] = unique_code
            elif json_body is None:
                json_body = {"unique_code": unique_code}
            elif "unique_code" in contract.body_fields:
                json_body.setdefault("unique_code", unique_code)
        if json_body is not None and contract.operation != "submit_flag":
            allowed = set(contract.body_fields)
            if allowed:
                json_body = {key: value for key, value in json_body.items() if key in allowed}
        return params or None, json_body

    async def _send_request(
        self,
        contract: BenchmarkOperationContract,
        url: str,
        *,
        params: dict[str, str] | None,
        json_body: dict[str, Any] | None,
        operation_label: str,
        timeout: float | None = None,
    ) -> httpx.Response:
        try:
            return await self._client.request(
                contract.method,
                url,
                headers={"BENCHMARK_TOKEN": self._token},
                params=params,
                json=json_body,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise ChallengesTransportError(operation=operation_label, cause=exc) from exc

    @staticmethod
    def _alternate_request_payload(
        operation: OperationName,
        contract: BenchmarkOperationContract,
        response: httpx.Response,
        *,
        unique_code: str | None,
    ) -> tuple[dict[str, str] | None, dict[str, Any] | None] | None:
        """Allow one safe query/body correction only after explicit validation failure."""

        if (
            operation not in {"start_challenge", "close_challenge"}
            or contract.source != "fixed"
            or response.status_code not in {400, 415, 422}
            or not unique_code
        ):
            return None
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        text = json.dumps(payload, ensure_ascii=False, default=str).casefold()
        if "unique_code" not in text and "uniquecode" not in text:
            return None
        if not any(
            marker in text
            for marker in (
                "required",
                "missing",
                "query",
                "body",
                "unprocessable",
                "unsupported media",
            )
        ):
            return None
        if "unique_code" in contract.query_fields:
            return None, {"unique_code": unique_code}
        if "unique_code" in contract.body_fields:
            return {"unique_code": unique_code}, None
        return {"unique_code": unique_code}, None

    def _url(self, path: str) -> str:
        return f"{self._base_url}/{path.lstrip('/')}"

    @staticmethod
    def _begin_call() -> None:
        _CALL_EVENTS.set([])

    @staticmethod
    def _event(event_type: str, **payload: Any) -> None:
        events = _CALL_EVENTS.get()
        if events is not None:
            events.append({"code": event_type, "details": payload})

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


def _response_candidate_has_signal(operation: OperationName, value: Any) -> bool:
    """Reject structurally valid but semantically empty operation responses."""

    if operation == "list_challenges":
        return isinstance(value, list) and all(
            isinstance(item, Challenge) and bool(item.unique_code.strip())
            for item in value
        )
    if operation == "get_hint":
        return isinstance(value, ChallengeHintResponse) and bool(
            (value.hint or "").strip()
        )
    if operation == "start_challenge":
        return isinstance(value, ChallengeStartResponse) and bool(
            value.unique_code.strip()
        )
    if operation == "close_challenge":
        return isinstance(value, ChallengeCloseResponse) and bool(value.closed)
    if operation == "submit_flag":
        return isinstance(value, SubmitFlagResponse) and (
            value.correct is not None
            or value.correct_flag_count > 0
            or value.total_flag_count > 0
        )
    return False
