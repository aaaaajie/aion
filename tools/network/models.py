"""Agent-facing models for network discovery tasks."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class NetworkModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NetworkDiscoveryArguments(NetworkModel):
    targets: str = Field(
        min_length=1,
        description="One or more targets: single IP, CIDR, 1.2.3.4-20, or comma-separated list.",
    )
    ports: str | None = Field(
        default=None,
        description="Port list, e.g. 22,80,443 or 1-65535. Defaults to the fscan common port set.",
    )
    ping: bool = Field(
        default=True,
        description="Probe liveness (ICMP) before port scanning; set false to scan directly.",
    )
    ping_tcp: bool = Field(
        default=False,
        description="When ping=true, bypass the ICMP pre-filter and use direct TCP scanning of the requested ports for liveness.",
    )
    concurrency: int | None = Field(
        default=None,
        ge=1,
        description="Requested bridge concurrency; Runtime resource admission decides when it can run.",
    )
    timeout_seconds: float | None = Field(default=None, gt=0)
    web_mark: bool = Field(
        default=True,
        description="Collect title/server/status for open web ports (webtitle).",
    )
    scan_intent: str = Field(
        default="network_discovery",
        min_length=1,
        description="Stable purpose label for task correlation; it does not change scan behavior.",
    )
    priority: int = Field(default=50, ge=0, le=100)
    wait_seconds: float | None = Field(
        default=20.0,
        ge=0,
        description="20s by default; 0 returns immediately in the background.",
    )
    result_limit: int = Field(default=100, gt=0)

    @model_validator(mode="after")
    def validate_targets(self) -> "NetworkDiscoveryArguments":
        if not self.targets.strip():
            raise ValueError("Network discovery targets must not be empty")
        return self


class NetworkOutputArguments(NetworkModel):
    task_id: str = Field(min_length=1)
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=100, gt=0)
    wait_seconds: float | None = Field(
        default=20.0,
        ge=0,
        description="Long-poll for new results or a status change; 0 returns immediately and never starts a scan.",
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional filters: status, port, service, host.",
    )


class NetworkStopArguments(NetworkModel):
    task_id: str = Field(min_length=1)


class NetworkCleanupArguments(NetworkModel):
    task_id: str = Field(min_length=1)
