"""Environment-backed configuration for the Challenges SDK."""

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ChallengesSettings(BaseSettings):
    """Settings loaded from ``.env`` or the process environment.

    ``extra='ignore'`` is intentional: the project-level ``.env`` also
    contains settings for the future agent and application layers.
    """

    benchmark_base_url: AnyHttpUrl = Field(validation_alias="BENCHMARK_BASE_URL")
    benchmark_token: SecretStr = Field(validation_alias="BENCHMARK_TOKEN")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )
