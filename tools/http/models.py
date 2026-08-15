"""Strict Agent-facing models for generic HTTP interactions."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HttpModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HttpAuth(HttpModel):
    type: Literal["basic", "bearer"]
    username: str | None = None
    password: str | None = None
    token: str | None = None

    @model_validator(mode="after")
    def validate_fields(self) -> "HttpAuth":
        if self.type == "basic" and (self.username is None or self.password is None):
            raise ValueError("basic authentication requires username and password")
        if self.type == "bearer" and self.token is None:
            raise ValueError("bearer authentication requires token")
        return self


class HttpBody(HttpModel):
    type: Literal["json", "form", "raw", "base64", "multipart"]
    value: Any
    content_type: str | None = None


class HttpRequestSpec(HttpModel):
    request_intent: str = Field(
        min_length=1,
        description="Why this request is being made, such as page_probe, api_validation, parameter_analysis, or status_check. Informational only; it does not change execution.",
    )
    method: str = Field(default="GET", min_length=1, description="HTTP method for this request.")
    url: str = Field(
        min_length=1,
        description="An explicit http:// or https:// target URL. Template placeholders are allowed only when variables are supplied by system_http_probe.",
    )
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    auth: HttpAuth | None = None
    body: HttpBody | None = None
    parent_request_id: str | None = Field(
        default=None,
        description="Optional earlier request in the same Run and Agent. Use this for context lineage, not to build a dynamic request from a response.",
    )
    request_group_id: str | None = Field(
        default=None,
        description="Stable identifier for requests in one interaction chain or validation group. Requests in another Agent cannot be referenced.",
    )
    session_id: str | None = Field(
        default=None,
        description="Agent-private Cookie Jar identifier. Reuse it across separate tool calls when a protocol session must continue.",
    )
    connection_context_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional stable identifier for one ordered interaction chain. Requests in the same context execute serially by sequence_id and survive waiting/resume.",
    )
    sequence_id: int | None = Field(
        default=None,
        ge=0,
        description="Optional per-Agent monotonic position inside connection_context_id. Omitted values are assigned from the context history.",
    )
    update_session: bool = Field(
        default=False,
        description="Persist response cookies into session_id after this request. Set true for login or other session-establishing requests.",
    )
    verify_tls: bool = True
    follow_redirects: bool = False
    proxy: str | None = None
    timeout_seconds: float | None = Field(default=30.0, gt=0)

    @model_validator(mode="after")
    def reject_ambiguous_credentials(self) -> "HttpRequestSpec":
        if "{{" not in self.url and not self.url.lower().startswith(("http://", "https://")):
            raise ValueError("HTTP request URL must use http or https")
        if "{{" not in self.method and not self.method.replace("-", "").isalnum():
            raise ValueError("HTTP method is invalid")
        if self.proxy is not None and not self.proxy.lower().startswith(
            ("http://", "https://", "socks5://")
        ):
            raise ValueError("HTTP proxy URL uses an unsupported scheme")
        lowered = {name.lower() for name in self.headers}
        if "authorization" in lowered and self.auth is not None:
            raise ValueError("auth and Authorization header cannot both be provided")
        if "cookie" in lowered and (self.cookies or self.session_id):
            raise ValueError("Cookie header cannot be combined with cookies or session_id")
        if self.update_session and self.session_id is None:
            raise ValueError("update_session requires session_id")
        return self


class HttpRange(HttpModel):
    start: int = 0
    stop: int
    step: int = 1

    @model_validator(mode="after")
    def nonzero_step(self) -> "HttpRange":
        if self.step == 0:
            raise ValueError("range step cannot be zero")
        return self


class HttpVariableSource(HttpModel):
    values: list[Any] | None = Field(
        default=None, description="Inline finite values for one template variable."
    )
    range: HttpRange | None = Field(
        default=None, description="Finite integer range; use only one source per variable."
    )
    file_path: str | None = Field(
        default=None,
        description="Workspace-relative UTF-8 file with one variable value per line.",
    )
    encoding: Literal["path", "query", "form", "none"] = Field(
        default="none",
        description="Encoding applied at substitution: path, query, form, or none.",
    )
    trim: bool = True
    skip_empty: bool = True

    @model_validator(mode="after")
    def exactly_one_source(self) -> "HttpVariableSource":
        if sum(value is not None for value in (self.values, self.range, self.file_path)) != 1:
            raise ValueError("variable requires exactly one source")
        return self


class HttpProbeCase(HttpModel):
    request: HttpRequestSpec
    variables: dict[str, HttpVariableSource] = Field(default_factory=dict)
    combine: Literal["product", "zip"] = Field(
        default="product",
        description="product tests every value combination; zip pairs values by ordinal and requires equal source lengths.",
    )


class HttpRequestArguments(HttpModel):
    request: HttpRequestSpec
    concurrency: int = Field(default=1, gt=0)
    expected_response_bytes: int | None = Field(
        default=None,
        ge=0,
        description="Optional expected body size used only for Runtime resource admission; it is not a response-size limit.",
    )
    priority: int = Field(default=50, ge=0, le=100)
    wait_seconds: float | None = Field(
        default=20.0,
        ge=0,
        description="20 seconds by default; 0 returns immediately in background; null waits until the request phase ends. Waiting never sends the request again.",
    )
    result_limit: int = Field(default=100, gt=0)


class HttpProbeArguments(HttpModel):
    cases: list[HttpProbeCase] = Field(
        min_length=1,
        description="Use one case for a finite variable matrix. Place variables with exactly {{name}} in method, URL, query, headers, cookies, or body; single-brace {name} is invalid. Do not put response-dependent chained steps in one batch; make separate calls with a Session.",
    )
    concurrency: int = Field(default=8, gt=0)
    rate_limit_per_second: float | None = Field(default=None, gt=0)
    expected_response_bytes: int | None = Field(
        default=None,
        ge=0,
        description="Expected body size for resource estimation only, not a hard limit.",
    )
    priority: int = Field(default=50, ge=0, le=100)
    wait_seconds: float | None = Field(
        default=20.0,
        ge=0,
        description="20 seconds by default; 0 returns immediately; null waits for request execution to finish.",
    )
    result_limit: int = Field(default=10, gt=0)


class HttpOutputFilters(HttpModel):
    request_ids: list[str] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    outcomes: list[str] = Field(default_factory=list)
    request_group_id: str | None = None
    connection_context_id: str | None = None
    sequence_id_min: int | None = Field(default=None, ge=0)
    sequence_id_max: int | None = Field(default=None, ge=0)
    min_body_bytes: int | None = Field(default=None, ge=0)
    max_body_bytes: int | None = Field(default=None, ge=0)
    header_contains: dict[str, str] = Field(default_factory=dict)
    header_regex: dict[str, str] = Field(default_factory=dict)
    body_contains: str | None = None
    body_regex: str | None = None

    @model_validator(mode="after")
    def validate_regexes(self) -> "HttpOutputFilters":
        try:
            for pattern in self.header_regex.values():
                re.compile(pattern)
            if self.body_regex is not None:
                re.compile(self.body_regex)
        except re.error as exc:
            raise ValueError("HTTP output filter contains an invalid regular expression") from exc
        return self


class HttpOutputArguments(HttpModel):
    interaction_id: str = Field(
        min_length=1,
        description="Interaction ID returned by system_http_request or system_http_probe. Use this to poll; do not resend the request.",
    )
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=100, gt=0)
    wait_seconds: float | None = Field(
        default=0.0,
        ge=0,
        description="0 reads immediately; a positive value long-polls for new results; null waits indefinitely while the interaction is active.",
    )
    filters: HttpOutputFilters = Field(default_factory=HttpOutputFilters)


class HttpResponseArguments(HttpModel):
    interaction_id: str = Field(min_length=1, description="Owning interaction ID.")
    request_id: str = Field(
        min_length=1,
        description="Request ID from the structured output. Use this only when the full response Body is needed as evidence.",
    )
    offset_bytes: int = Field(default=0, ge=0)
    length_bytes: int = Field(default=30_000, gt=0)


class HttpAnalyzeArguments(HttpModel):
    interaction_id: str = Field(
        min_length=1,
        description="Interaction ID returned by a previous HTTP request or probe.",
    )
    request_ids: list[str] = Field(default_factory=list)
    request_group_id: str | None = None
    similarity: bool = True
    features: bool = True
    summary: bool = True
    force: bool = Field(
        default=False,
        description="When true, append a new deterministic analysis revision; never use it to repeat network requests.",
    )
    wait_seconds: float | None = Field(
        default=20.0,
        ge=0,
        description="How long to wait for analysis; null waits until the selected analysis revision finishes.",
    )
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=100, gt=0)


class HttpStopArguments(HttpModel):
    interaction_id: str = Field(min_length=1)


class HttpCleanupArguments(HttpModel):
    interaction_id: str = Field(min_length=1)


class PathProbeArguments(HttpModel):
    url: str = Field(
        min_length=1,
        description="Base http(s) URL to scan. One path probe covers one base URL.",
    )
    profile: Literal["quick", "targeted", "deep"] = Field(
        description=(
            "quick (~300 paths) for a first surface pass, targeted (~9k) after "
            "technology fingerprinting, deep (~16k) for final coverage."
        )
    )
    request_intent: str = Field(
        default="path_discovery",
        min_length=1,
        description="Why this scan is being made; informational only.",
    )
    parent_request_id: str | None = Field(
        default=None,
        description="Optional earlier request in the same Run and Agent for context lineage.",
    )
    request_group_id: str | None = Field(
        default=None,
        description="Stable identifier for this scan chain; defaults to the interaction ID.",
    )
    session_id: str | None = Field(
        default=None,
        description="Agent-private Cookie Jar reused by every request in this scan.",
    )
    extensions: list[str] | None = Field(
        default=None,
        description="Override the profile default extensions, for example php,json.",
    )
    wordlist_paths: list[str] = Field(
        default_factory=list,
        description="Optional workspace files with one path per line, used instead of built-in profiles.",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Optional workspace files whose paths are skipped (one per line).",
    )
    force_extensions: bool = Field(
        default=False,
        description="Append the selected extensions and a slash to extensionless entries.",
    )
    include_status_codes: list[int] = Field(default_factory=list)
    exclude_status_codes: list[int] | None = Field(default=None)
    recursion_depth: int = Field(
        default=0,
        ge=0,
        description="Explicit recursion depth into found directories; 0 disables recursion.",
    )
    recursion_status_codes: list[int] | None = Field(default=None)
    method: Literal["GET", "HEAD"] = Field(
        default="GET",
        description="Only GET and HEAD are supported by path discovery; use system_http_request/probe for other methods.",
    )
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    auth: HttpAuth | None = None
    follow_redirects: bool = False
    verify_tls: bool = False
    timeout_seconds: float | None = Field(default=None, gt=0)
    max_body_bytes: int | None = Field(default=None, ge=1024)
    concurrency: int | None = Field(default=None, gt=0)
    rate_limit_per_second: float | None = Field(default=None, gt=0)
    priority: int = Field(default=50, ge=0, le=100)
    wait_seconds: float | None = Field(default=20.0, ge=0)
    result_limit: int = Field(default=100, gt=0)

    @model_validator(mode="after")
    def validate_url(self) -> "PathProbeArguments":
        if not self.url.lower().startswith(("http://", "https://")):
            raise ValueError("Path probe URL must use http or https")
        return self


class FingerprintArguments(HttpModel):
    url: str = Field(
        min_length=1,
        description="Base http(s) URL to fingerprint.",
    )
    request_intent: str = Field(
        default="technology_fingerprint",
        min_length=1,
        description="Why this fingerprint scan is being made; informational only.",
    )
    parent_request_id: str | None = Field(
        default=None,
        description="Optional earlier request in the same Run and Agent for context lineage.",
    )
    request_group_id: str | None = Field(
        default=None,
        description="Stable identifier for this fingerprint chain; defaults to the interaction ID.",
    )
    session_id: str | None = Field(
        default=None,
        description="Agent-private Cookie Jar reused by fingerprint requests.",
    )
    passive: bool = Field(
        default=True,
        description="Match the homepage (GET / and favicon) against TscanPlus/Yakit passive rules.",
    )
    active: bool = Field(
        default=True,
        description="Probe TscanPlus FingerDir paths and match their rules.",
    )
    minimum_confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="Minimum deterministic fingerprint confidence returned. Low-confidence generic keyword matches are hidden by default.",
    )
    include_favicon: bool = Field(
        default=True,
        description="Fetch favicon and run favicon-hash rules; used only when passive=true.",
    )
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    auth: HttpAuth | None = None
    follow_redirects: bool = False
    verify_tls: bool = False
    timeout_seconds: float | None = Field(default=None, gt=0)
    concurrency: int | None = Field(default=None, gt=0)
    priority: int = Field(default=50, ge=0, le=100)
    wait_seconds: float | None = Field(default=20.0, ge=0)
    result_limit: int = Field(default=100, gt=0)

    @model_validator(mode="after")
    def validate_url(self) -> "FingerprintArguments":
        if not self.url.lower().startswith(("http://", "https://")):
            raise ValueError("Fingerprint URL must use http or https")
        return self
