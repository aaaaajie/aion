"""Configuration for the long-running Agent runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import AliasChoices, AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTEXT_WINDOW_TOKENS = 1_000_000
MIN_CONTEXT_WINDOW_TOKENS = 32_000
MODEL_CONTEXT_SAFETY_TOKENS = 8_192


@dataclass(frozen=True)
class RoleContextProfile:
    """Fixed competition context policy for one Agent role."""

    soft_prompt_tokens: int
    recent_message_tokens: int
    recovered_event_chars: int
    max_output_tokens: int


ROLE_CONTEXT_PROFILES: dict[str, RoleContextProfile] = {
    "chief": RoleContextProfile(128_000, 32_000, 48_000, 32_768),
    "challenge": RoleContextProfile(96_000, 24_000, 36_000, 32_768),
    "execution": RoleContextProfile(64_000, 8_000, 24_000, 16_384),
}


@dataclass(frozen=True)
class ContextBudget:
    """Token budget used by the Agent loop and compaction layer."""

    context_window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS
    session_memory_max_tokens: int = 12_000

    def profile(self, role: str | None) -> RoleContextProfile:
        return ROLE_CONTEXT_PROFILES.get(
            role or "execution", ROLE_CONTEXT_PROFILES["execution"]
        )

    def max_output_tokens(self, role: str | None, *, bootstrap: bool = False) -> int:
        if bootstrap:
            return 32_768
        return self.profile(role).max_output_tokens

    def absolute_prompt_tokens(
        self, role: str | None = None, *, bootstrap: bool = False
    ) -> int:
        return max(
            1,
            self.context_window_tokens
            - self.max_output_tokens(role, bootstrap=bootstrap)
            - MODEL_CONTEXT_SAFETY_TOKENS,
        )

    @property
    def summary_max_output_tokens(self) -> int:
        return 8_192


def deepseek_agent_request_options(
    *,
    role: str | None,
    bootstrap: bool = False,
    context_budget: ContextBudget | None = None,
) -> dict[str, object]:
    """Return the fixed DeepSeek policy for a primary Agent request."""

    budget = context_budget or ContextBudget()
    return {
        "thinking": {"type": "enabled"},
        "reasoning_effort": "max",
        "max_tokens": budget.max_output_tokens(role, bootstrap=bootstrap),
    }


def deepseek_auxiliary_request_options() -> dict[str, object]:
    """Return deterministic, non-thinking options for maintenance requests."""

    return {
        "thinking": {"type": "disabled"},
        "temperature": 0,
    }


class AgentSettings(BaseSettings):
    """LLM settings plus optional runtime overrides.

    The 1M context contract is a code default. ``AION_CONTEXT_WINDOW_TOKENS``
    exists for tests or deployments that use a different endpoint.
    """

    llm_base_url: AnyHttpUrl = Field(validation_alias="LLM_BASE_URL")
    llm_model: str = Field(min_length=1, validation_alias="LLM_MODEL")
    skill_discovery_model: str | None = Field(
        default=None,
        validation_alias="AION_SKILL_DISCOVERY_MODEL",
    )
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
    bootstrap_enabled: bool = Field(
        default=True,
        validation_alias="AION_BOOTSTRAP_ENABLED",
        description="Start one autonomous Bootstrap Execution for each new Challenge.",
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

    @field_validator("skill_discovery_model")
    @classmethod
    def normalize_skill_discovery_model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

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
