"""Independent ephemeral advice, never a source for the factual blackboard."""

from pydantic import BaseModel, ConfigDict, Field


class ObservationReferenceError(ValueError):
    def __init__(self, path, refs):
        super().__init__("Observer cites evidence outside its factual input")
        self.path, self.refs = path, sorted(refs)


class AdviceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    statement: str = Field(min_length=1, max_length=300)
    evidence_refs: list[str] = Field(min_length=1, max_length=6)


class ObservationAdvice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    data_gaps: list[AdviceEntry] = Field(default_factory=list, max_length=3)
    response_differences: list[AdviceEntry] = Field(default_factory=list, max_length=3)
    hypotheses: list[AdviceEntry] = Field(default_factory=list, max_length=3)
    suggested_experiments: list[AdviceEntry] = Field(default_factory=list, max_length=2)


def validate_observation_output(content, evidence_refs):
    advice = ObservationAdvice.model_validate_json(content)
    allowed = set(evidence_refs)
    for field, entries in advice.model_dump().items():
        for index, entry in enumerate(entries):
            extra = set(entry["evidence_refs"]) - allowed
            if extra:
                raise ObservationReferenceError(f"{field}.{index}.evidence_refs", extra)
    return advice.model_dump()
