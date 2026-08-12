"""Registry selecting one domain-specific lightweight scanner planner."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent.skills import SkillDefinition, skill_definition

from .ai import AILightScanner
from .binary import BinaryLightScanner
from .blockchain import BlockchainLightScanner
from .contracts import (
    CompetitionDomainName,
    DomainName,
    LightScanner,
    ScannerContext,
    ScannerTaskSpec,
)
from .web import WebLightScanner

COMPETITION_SCANNER_REGISTRY: dict[CompetitionDomainName, LightScanner] = {
    "web": WebLightScanner(),
    "blockchain": BlockchainLightScanner(),
    "ai": AILightScanner(),
    "other": BinaryLightScanner(),
}

SCANNER_REGISTRY: dict[DomainName, LightScanner] = {
    **COMPETITION_SCANNER_REGISTRY,
    "binary": BinaryLightScanner(),
}

SKILL_ID_FOR_DOMAIN: dict[CompetitionDomainName, str] = {
    "web": "web.light_scanner",
    "blockchain": "blockchain.light_scanner",
    "ai": "ai.light_scanner",
    "other": "binary.light_scanner",
}


def scanner_for(domain: DomainName) -> LightScanner:
    try:
        return SCANNER_REGISTRY[domain]
    except KeyError as exc:
        raise ValueError(f"unknown scanner domain: {domain}") from exc


def skill_for_domain(domain: CompetitionDomainName) -> SkillDefinition:
    return skill_definition(SKILL_ID_FOR_DOMAIN[domain])


def skill_instructions_for_domain(domain: CompetitionDomainName) -> str:
    return skill_for_domain(domain).load_instructions()


def build_first_round_tasks(
    domain: DomainName,
    *,
    unique_code: str,
    target_scope: Sequence[str],
    description: str = "",
    evidence_refs: Sequence[str] = (),
    observations: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    context = ScannerContext(
        unique_code=unique_code,
        target_scope=tuple(target_scope),
        description=description,
        evidence_refs=tuple(evidence_refs),
        observations=tuple(observations),
    )
    tasks = scanner_for(domain).build_first_round(context)
    if domain in SKILL_ID_FOR_DOMAIN:
        manifest_tools = set(skill_for_domain(domain).manifest.requires.tools)
        for task in tasks:
            if not set(task.tool_names).issubset(manifest_tools):
                raise ValueError(
                    f"Skill tool contract does not match planner for {domain}"
                )
    return [task.as_dict() for task in tasks]
