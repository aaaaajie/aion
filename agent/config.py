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
    "solver": RoleContextProfile(96_000, 24_000, 36_000, 32_768),
    "worker": RoleContextProfile(64_000, 8_000, 24_000, 16_384),
}


@dataclass(frozen=True)
class ContextBudget:
    """Token budget used by the Agent loop and compaction layer."""

    context_window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS
    session_memory_max_tokens: int = 12_000

    def profile(self, role: str | None) -> RoleContextProfile:
        return ROLE_CONTEXT_PROFILES.get(
            role or "worker", ROLE_CONTEXT_PROFILES["worker"]
        )

    def max_output_tokens(self, role: str | None) -> int:
        return self.profile(role).max_output_tokens

    def absolute_prompt_tokens(self, role: str | None = None) -> int:
        return max(
            1,
            self.context_window_tokens
            - self.max_output_tokens(role)
            - MODEL_CONTEXT_SAFETY_TOKENS,
        )

    @property
    def summary_max_output_tokens(self) -> int:
        return 4_096


@dataclass(frozen=True)
class StagnationPolicy:
    """Durable intervention thresholds for one active challenge."""

    review_after_seconds: int = 480
    alternate_after_seconds: int = 840
    rotate_after_seconds: int = 1320
    worker_timeout_seconds: int = 480
    poll_interval_seconds: int = 30

    def __post_init__(self) -> None:
        if not (
            0 < self.review_after_seconds
            < self.alternate_after_seconds
            < self.rotate_after_seconds
        ):
            raise ValueError("stagnation thresholds must be positive and ordered")
        if self.worker_timeout_seconds <= 0 or self.poll_interval_seconds <= 0:
            raise ValueError("stagnation timeouts must be positive")


def deepseek_agent_request_options(
    *,
    role: str | None,
    context_budget: ContextBudget | None = None,
    report_recovery: bool = False,
) -> dict[str, object]:
    """Return the fixed DeepSeek policy for a primary Agent request.

    A report recovery is deliberately a small request, but it remains a
    reasoning request because DeepSeek tool calls must include
    ``reasoning_content``.  Normal Agent turns keep the role-specific output
    budget.
    """

    if report_recovery:
        return {
            "thinking": {"type": "enabled"},
            "reasoning_effort": "max",
            "max_tokens": 4_096,
        }

    budget = context_budget or ContextBudget()
    return {
        "thinking": {"type": "enabled"},
        "reasoning_effort": "max",
        "max_tokens": budget.max_output_tokens(role),
    }


def deepseek_auxiliary_request_options() -> dict[str, object]:
    """Return deterministic, non-thinking options for maintenance requests."""

    return {
        "thinking": {"type": "disabled"},
        "temperature": 0,
    }


def normalize_selected_challenge_codes(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise ValueError("selected_challenge_codes must be a non-empty list or null")
    if any(not isinstance(code, str) or not code.strip() or len(code.strip()) > 256 for code in value):
        raise ValueError("selected_challenge_codes must contain non-empty challenge codes")
    return list(dict.fromkeys(code.strip() for code in value))


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
        description=(
            "Optional auxiliary model for Skill Discovery. Leave unset, or use "
            "local/disabled/off, to use the deterministic local catalog without "
            "an extra model request."
        ),
    )
    selected_challenge_codes: list[str] | None = Field(
        default=None, validation_alias="AION_SELECTED_CHALLENGE_CODES"
    )
    compact_tools: bool = Field(default=True, validation_alias="AION_COMPACT_TOOLS")
    solver_observation: bool = Field(
        default=True, validation_alias="AION_SOLVER_OBSERVATION"
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
    stagnation_review_after_seconds: int = Field(
        default=480, ge=1, validation_alias="AION_STAGNATION_REVIEW_AFTER_SECONDS"
    )
    stagnation_alternate_after_seconds: int = Field(
        default=840, ge=1, validation_alias="AION_STAGNATION_ALTERNATE_AFTER_SECONDS"
    )
    stagnation_rotate_after_seconds: int = Field(
        default=1320, ge=1, validation_alias="AION_STAGNATION_ROTATE_AFTER_SECONDS"
    )
    stagnation_worker_timeout_seconds: int = Field(
        default=480, ge=1, validation_alias="AION_STAGNATION_WORKER_TIMEOUT_SECONDS"
    )
    stagnation_poll_interval_seconds: int = Field(
        default=30, ge=1, validation_alias="AION_STAGNATION_POLL_INTERVAL_SECONDS"
    )

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @field_validator("selected_challenge_codes", mode="before")
    @classmethod
    def validate_selected_challenge_codes(cls, value):
        return normalize_selected_challenge_codes(value)

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
    def stagnation_policy(self) -> StagnationPolicy:
        return StagnationPolicy(
            review_after_seconds=self.stagnation_review_after_seconds,
            alternate_after_seconds=self.stagnation_alternate_after_seconds,
            rotate_after_seconds=self.stagnation_rotate_after_seconds,
            worker_timeout_seconds=self.stagnation_worker_timeout_seconds,
            poll_interval_seconds=self.stagnation_poll_interval_seconds,
        )

    @property
    def run_root(self) -> Path:
        return PROJECT_ROOT / ".aion" / "runs"


def completions_url(base_url: AnyHttpUrl) -> str:
    """Return an OpenAI-compatible Chat Completions endpoint."""

    base = str(base_url).rstrip("/")
    return base if base.endswith("/chat/completions") else f"{base}/chat/completions"
