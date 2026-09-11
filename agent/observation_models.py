"""Bounded, revisable observations; these are never authoritative findings."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Literal

from agent.memory.context import rough_token_count


class MapEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claim: str = Field(min_length=1, max_length=160)
    sources: list[int] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def source_ids(self):
        if any(value < 1 for value in self.sources):
            raise ValueError("Sources must be positive event sequence numbers")
        self.sources = list(dict.fromkeys(self.sources))
        return self


class ObservationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    LOCK: list[MapEntry] = Field(default_factory=list)
    DEAD: list[MapEntry] = Field(default_factory=list)
    ANGLES: list[MapEntry] = Field(default_factory=list)
    TENSION: list[MapEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def tension_sources(self):
        if any(len(entry.sources) < 2 for entry in self.TENSION):
            raise ValueError("A tension must cite at least two source events")
        return self

    def source_ids(self) -> set[int]:
        return {source for group in self.model_dump(include={"LOCK", "DEAD", "ANGLES", "TENSION"}).values()
                for entry in group for source in entry["sources"]}


class ObservationMap(ObservationOutput):
    LOCK: list[MapEntry] = Field(default_factory=list, max_length=2)
    DEAD: list[MapEntry] = Field(default_factory=list, max_length=2)
    ANGLES: list[MapEntry] = Field(default_factory=list, max_length=2)
    TENSION: list[MapEntry] = Field(default_factory=list, max_length=2)

    @model_validator(mode="after")
    def bounded(self):
        if rough_token_count(self.model_dump()) > 1500:
            raise ValueError("Observation map exceeds its 1500 estimated-token budget")
        return self


class Correction(MapEntry):
    category: Literal["goal_drift", "invalid_experiment", "repeated_expansion", "condition_confusion"]
    suggestion: str = Field(min_length=1, max_length=160)
    assessment: Literal["open", "uncertain", "resolved", "withdrawn"] = "open"


class ObserverResponse(BaseModel):
    """The only model-facing observation wire format.

    The durable state keeps the map flattened, but model responses always use
    this envelope so the optional correction cannot be confused with map data.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    map: ObservationOutput
    correction: Correction | None = None


def without_revoked(observation, revoked):
    revoked = set(revoked)
    return {key: [entry for entry in entries if not revoked.intersection(entry["sources"])]
            for key, entries in observation.items()}


def validate_observation_output(content: str, old_map: dict, trace: list[dict], *, diagnostics=None, evidence=()) -> dict:
    """Validate every entry and source before applying deterministic capacity limits."""
    candidate = ObserverResponse.model_validate_json(content)
    allowed = {row["sequence"] for row in [*trace, *evidence]} | ObservationMap.model_validate(old_map).source_ids()
    groups = candidate.map.model_dump()
    sources = {s for entries in groups.values() for entry in entries for s in entry["sources"]}
    if candidate.correction:
        sources.update(candidate.correction.sources)
    if not sources <= allowed:
        raise ValueError("Observation cites an unseen source")
    trimmed = {key: max(0, len(entries) - 2) for key, entries in groups.items()}
    bounded = ObservationMap.model_validate({key: entries[:2] for key, entries in groups.items()})
    if diagnostics is not None:
        diagnostics["trimmed_entries"] = trimmed
    result = bounded.model_dump()
    if candidate.correction:
        result["correction"] = candidate.correction.model_dump()
    return result
