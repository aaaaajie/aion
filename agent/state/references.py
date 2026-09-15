"""Canonical model-visible references; identifiers are never read references."""

import re
from typing import Annotated

from pydantic import StringConstraints

from .errors import StateError

EvidenceRef = Annotated[str, StringConstraints(pattern=r"^evidence:evidence_[0-9a-f]{32}$")]
ReportRef = Annotated[str, StringConstraints(pattern=r"^report:report_[0-9a-f]{32}$")]
ContextRef = EvidenceRef | ReportRef


def parse_reference(value: str, expected: str | None = None) -> tuple[str, str]:
    match = re.fullmatch(r"(evidence|report):((?:evidence|report)_[0-9a-f]{32})", value) if isinstance(value, str) else None
    if not match or not match[2].startswith(match[1] + "_"):
        raise StateError("invalid_reference", "Copy the exact evidence_ref or report_ref; bare IDs and resource handles are not references", status_code=422)
    kind, ident = match.groups()
    if expected is not None and kind != expected:
        raise StateError("reference_type_mismatch", f"Expected a {expected} reference", status_code=422)
    return kind, ident
