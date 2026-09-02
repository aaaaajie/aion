"""Strict model-facing arguments for the headless browser tool."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BrowserModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class BrowserArguments(BrowserModel):
    """One structured operation against the Agent-private browser session."""

    action: Literal[
        "open",
        "snapshot",
        "interact",
        "get",
        "eval",
        "wait",
        "screenshot",
        "tabs",
        "network",
        "close",
    ]

    # open
    url: str | None = Field(default=None, max_length=8_000)

    # interact
    interaction: Literal[
        "click",
        "dblclick",
        "hover",
        "focus",
        "fill",
        "type",
        "press",
        "check",
        "uncheck",
        "select",
        "upload",
        "scroll",
        "scrollintoview",
        "drag",
    ] | None = None
    target: str | None = Field(default=None, max_length=4_000)
    value: str | None = Field(default=None, max_length=100_000)
    values: list[str] | None = Field(default=None, max_length=32)
    attribute: str | None = Field(default=None, max_length=256)
    new_tab: bool = False
    direction: Literal["up", "down", "left", "right"] | None = None
    amount: int = Field(default=500, ge=1, le=100_000)

    # snapshot
    snapshot_interactive: bool = True
    snapshot_include_urls: bool = False
    snapshot_compact: bool = False
    snapshot_depth: int | None = Field(default=None, ge=1, le=30)
    snapshot_selector: str | None = Field(default=None, max_length=4_000)
    snapshot_json: bool = False

    # get
    get_kind: Literal["text", "html", "attr", "value", "title", "url", "count"] | None = None

    # eval
    script: str | None = Field(default=None, max_length=500_000)

    # wait
    wait_mode: Literal["element", "ms", "text", "url", "load", "fn"] | None = None
    wait_value: str | None = Field(default=None, max_length=100_000)

    # screenshot and HAR output. Paths are relative to AION_AGENT_WORKDIR.
    path: str | None = Field(default=None, max_length=1_000)
    screenshot_full: bool = False
    screenshot_annotate: bool = False

    # tabs
    tab_action: Literal["list", "new", "switch", "close"] | None = None
    tab_id: str | None = Field(default=None, max_length=256)

    # network
    network_action: Literal["requests", "har_start", "har_stop", "route", "abort"] | None = None
    network_pattern: str | None = Field(default=None, max_length=4_000)
    network_body: str | None = Field(default=None, max_length=500_000)

    timeout_seconds: float = Field(default=60.0, gt=0, le=180.0)
    max_output_chars: int = Field(default=40_000, gt=0, le=200_000)

    @model_validator(mode="after")
    def validate_operation(self) -> "BrowserArguments":
        if self.action == "open":
            _required(self.url, "url")
            if not self.url.lower().startswith(("http://", "https://")):
                raise ValueError("browser URL must use http or https")
        elif self.action == "interact":
            _required(self.interaction, "interaction")
            interaction = self.interaction
            if interaction not in {"press", "scroll"}:
                _required(self.target, "target")
            if interaction in {"fill", "type", "press", "upload"}:
                _required(self.value, "value")
            if interaction == "select" and self.value is None and not self.values:
                raise ValueError("select requires value or values")
            if interaction == "scroll" and self.direction is None:
                raise ValueError("scroll requires direction")
            if interaction == "drag":
                _required(self.value, "value as the destination target")
            if self.new_tab and interaction != "click":
                raise ValueError("new_tab is supported only for click")
        elif self.action == "get":
            _required(self.get_kind, "get_kind")
            if self.get_kind in {"text", "html", "value", "count"}:
                _required(self.target, "target")
            if self.get_kind == "attr":
                _required(self.target, "target")
                _required(self.attribute, "attribute")
        elif self.action == "eval":
            _required(self.script, "script")
        elif self.action == "wait":
            _required(self.wait_mode, "wait_mode")
            _required(self.wait_value, "wait_value")
            if self.wait_mode == "ms" and not self.wait_value.isdecimal():
                raise ValueError("wait_value must be milliseconds when wait_mode is ms")
        elif self.action == "tabs":
            _required(self.tab_action, "tab_action")
            if self.tab_action == "new":
                _required(self.url, "url")
                if not self.url.lower().startswith(("http://", "https://")):
                    raise ValueError("tab URL must use http or https")
            elif self.tab_action in {"switch", "close"}:
                _required(self.tab_id, "tab_id")
        elif self.action == "network":
            _required(self.network_action, "network_action")
            if self.network_action in {"route", "abort"}:
                _required(self.network_pattern, "network_pattern")
            if self.network_action == "route":
                _required(self.network_body, "network_body")

        if self.action in {"screenshot", "network"} and self.path is not None:
            _validate_relative_path(self.path)
        return self


def _required(value: object, name: str) -> None:
    if value is None or (isinstance(value, str) and not value):
        raise ValueError(f"{name} is required for this browser operation")


def _validate_relative_path(value: str) -> None:
    if not value or "\x00" in value:
        raise ValueError("browser output path must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("browser output path must stay inside the Agent workspace")
