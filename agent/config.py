"""Configuration for the long-running Agent runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import AliasChoices, AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTEXT_WINDOW_TOKENS = 1_000_000
MIN_CONTEXT_WINDOW_TOKENS = 32_000


@dataclass(frozen=True)
class ContextBudget:
    """Token budget used by the Agent loop and compaction layer."""

    context_window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS
    summary_reserved_tokens: int = 20_000
    autocompact_buffer_tokens: int = 13_000
    max_output_tokens: int = 8_192
    session_memory_max_tokens: int = 12_000

    @property
    def effective_context_window(self) -> int:
        return self.context_window_tokens - self.summary_reserved_tokens

    @property
    def autocompact_threshold(self) -> int:
        return self.effective_context_window - self.autocompact_buffer_tokens


class AgentSettings(BaseSettings):
    """LLM settings plus optional runtime overrides.

    The 1M context contract is a code default. ``AION_CONTEXT_WINDOW_TOKENS``
    exists for tests or deployments that use a different endpoint.
    """

    llm_base_url: AnyHttpUrl = Field(validation_alias="LLM_BASE_URL")
    llm_model: str = Field(min_length=1, validation_alias="LLM_MODEL")
    llm_api_key: SecretStr = Field(
        min_length=1,
        validation_alias="LLM_API_KEY",
    )
    context_window_tokens: int = Field(
        default=DEFAULT_CONTEXT_WINDOW_TOKENS,
        validation_alias="AION_CONTEXT_WINDOW_TOKENS",
    )
    run_duration_minutes: int = Field(
        default=360,
        ge=1,
        validation_alias="AION_RUN_DURATION_MINUTES",
    )
    cpu_limit_percent: float = Field(
        default=70.0,
        gt=0,
        le=100,
        validation_alias=AliasChoices(
            "CPU_THRESHOLD",
            "AION_CPU_LIMIT_PERCENT",
        ),
    )
    memory_limit_percent: float = Field(
        default=70.0,
        gt=0,
        le=100,
        validation_alias=AliasChoices(
            "MEMORY_THRESHOLD",
            "AION_MEMORY_LIMIT_PERCENT",
        ),
    )
    agent_start_interval_seconds: float = Field(
        default=5.0,
        ge=0,
        validation_alias="AION_AGENT_START_INTERVAL_SECONDS",
    )
    disk_reserve_bytes: int = Field(
        default=1_073_741_824,
        ge=0,
        validation_alias="AION_DISK_RESERVE_BYTES",
    )
    disk_reserve_percent: float = Field(
        default=5.0,
        ge=0,
        le=100,
        validation_alias="AION_DISK_RESERVE_PERCENT",
    )

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @field_validator("context_window_tokens")
    @classmethod
    def validate_context_window(cls, value: int) -> int:
        if value < MIN_CONTEXT_WINDOW_TOKENS:
            raise ValueError(
                f"AION_CONTEXT_WINDOW_TOKENS must be at least {MIN_CONTEXT_WINDOW_TOKENS}"
            )
        return value

    @property
    def context_budget(self) -> ContextBudget:
        return ContextBudget(context_window_tokens=self.context_window_tokens)

    @property
    def run_root(self) -> Path:
        return PROJECT_ROOT / ".aion" / "runs"


def completions_url(base_url: AnyHttpUrl) -> str:
    """Return an OpenAI-compatible Chat Completions endpoint."""

    base = str(base_url).rstrip("/")
    return base if base.endswith("/chat/completions") else f"{base}/chat/completions"
