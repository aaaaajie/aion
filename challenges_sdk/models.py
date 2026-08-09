"""Pydantic models matching the Challenges API contract."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _APIModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Challenge(_APIModel):
    unique_code: str
    description: str | None = None
    difficulty: str
    level: int
    total_score: int
    flag_count: int
    correct_flag_count: int
    is_completed: bool
    container_status: str
    container_addr: list[str] = Field(default_factory=list)


class ChallengeStartResponse(_APIModel):
    unique_code: str
    container_addr: list[str] = Field(default_factory=list)


class ChallengeHintResponse(_APIModel):
    unique_code: str
    hint: str | None = None


class SubmitFlagResponse(_APIModel):
    correct: bool
    awarded: int
    cumulative_score: int
    correct_flag_count: int
    total_flag_count: int
    matched_flag_index: int | None = None


class ChallengeCloseResponse(_APIModel):
    unique_code: str
    closed: bool


class SubmitFlagRequest(BaseModel):
    unique_code: str = Field(min_length=1)
    flag: str = Field(min_length=1, max_length=4096)


ErrorDetail = dict[str, Any] | list[Any] | str | None
