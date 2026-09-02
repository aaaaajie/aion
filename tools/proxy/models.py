"""Strict model-facing arguments for the Caido proxy tool."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProxyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ProxyModifications(ProxyModel):
    """Fields that may be overlaid on a captured request before replay."""

    url: str | None = Field(default=None, max_length=8_000)
    params: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    body: str | None = Field(default=None, max_length=500_000)
    cookies: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_url(self) -> "ProxyModifications":
        if self.url is not None:
            parsed = urlparse(self.url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("replay url must use http or https")
        return self


class ProxyArguments(ProxyModel):
    """Dispatch one capture/replay/sitemap/scope operation to Caido."""

    action: Literal[
        "list_requests",
        "view_request",
        "replay_request",
        "list_sitemap",
        "view_sitemap_entry",
        "scope_rules",
    ]

    # request history
    httpql_filter: str | None = Field(default=None, max_length=8_000)
    first: int = Field(default=50, ge=1, le=100)
    after: str | None = Field(default=None, max_length=2_000)
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp"
    sort_order: Literal["asc", "desc"] = "desc"

    # request detail/replay
    request_id: str | None = Field(default=None, max_length=512)
    part: Literal["request", "response"] = "request"
    search_pattern: str | None = Field(default=None, max_length=2_000)
    page: int = Field(default=1, ge=1, le=10_000)
    page_size: int = Field(default=50, ge=1, le=200)
    modifications: ProxyModifications | None = None

    # sitemap
    scope_id: str | None = Field(default=None, max_length=512)
    parent_id: str | None = Field(default=None, max_length=512)
    depth: Literal["DIRECT", "ALL"] = "DIRECT"
    entry_id: str | None = Field(default=None, max_length=512)

    # scope CRUD
    scope_action: Literal["get", "list", "create", "update", "delete"] | None = None
    allowlist: list[str] | None = Field(default=None, max_length=200)
    denylist: list[str] | None = Field(default=None, max_length=200)
    scope_name: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_operation(self) -> "ProxyArguments":
        if self.action in {"view_request", "replay_request"} and not self.request_id:
            raise ValueError(f"{self.action} requires request_id")
        if self.action == "view_sitemap_entry" and not self.entry_id:
            raise ValueError("view_sitemap_entry requires entry_id")
        if self.action == "scope_rules":
            if self.scope_action is None:
                raise ValueError("scope_rules requires scope_action")
            if self.scope_action in {"get", "update", "delete"} and not self.scope_id:
                raise ValueError(f"scope_rules action={self.scope_action} requires scope_id")
            if self.scope_action in {"create", "update"} and not self.scope_name:
                raise ValueError(f"scope_rules action={self.scope_action} requires scope_name")
        return self
