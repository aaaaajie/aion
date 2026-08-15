"""Configuration loading tests for Runtime resource thresholds."""

from __future__ import annotations

from agent.config import AgentSettings


def test_runtime_accepts_threshold_environment_names(monkeypatch) -> None:
    monkeypatch.setenv("CPU_THRESHOLD", "81")
    monkeypatch.setenv("MEMORY_THRESHOLD", "91")

    settings = AgentSettings()

    assert settings.cpu_limit_percent == 81
    assert settings.memory_limit_percent == 91


def test_runtime_accepts_explicit_aion_threshold_names(monkeypatch) -> None:
    monkeypatch.delenv("CPU_THRESHOLD", raising=False)
    monkeypatch.delenv("MEMORY_THRESHOLD", raising=False)
    monkeypatch.setenv("AION_CPU_LIMIT_PERCENT", "82")
    monkeypatch.setenv("AION_MEMORY_LIMIT_PERCENT", "92")

    settings = AgentSettings()

    assert settings.cpu_limit_percent == 82
    assert settings.memory_limit_percent == 92


def test_runtime_accepts_optional_skill_discovery_model(monkeypatch) -> None:
    monkeypatch.setenv("AION_SKILL_DISCOVERY_MODEL", " lightweight-model ")
    settings = AgentSettings()
    assert settings.skill_discovery_model == "lightweight-model"
