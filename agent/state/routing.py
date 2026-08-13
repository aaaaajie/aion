"""Deterministic capability routing from normalized Observations to branches."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class BranchRoute:
    """One generic capability branch produced by an Observation."""

    branch_key: str
    kind: str
    priority: int
    mission: str
    task_stage: str = "validation"
    success_criteria: list[str] = field(default_factory=list)


def _value(observation: Mapping[str, Any], *keys: str) -> Any:
    detail = observation.get("detail") or {}
    for key in keys:
        if key in observation and observation.get(key) not in (None, ""):
            return observation.get(key)
        if key in detail and detail.get(key) not in (None, ""):
            return detail.get(key)
    return None


def _ports(observation: Mapping[str, Any]) -> set[int]:
    raw = _value(observation, "ports", "port")
    if raw is None:
        return set()
    values: set[int] = set()
    if isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        items = [raw]
    for item in items:
        try:
            values.add(int(item))
        except (TypeError, ValueError):
            continue
    return values


def routes_for_observation(observation: Mapping[str, Any]) -> list[BranchRoute]:
    """Return capability branches for one normalized Observation.

    The registry is deliberately generic: it maps service families to
    validation branches and never encodes challenge-specific business logic.
    """

    service = str(_value(observation, "service") or "unknown").lower()
    protocol = str(_value(observation, "protocol") or "").lower()
    framework = str(_value(observation, "framework") or "").lower()
    ports = _ports(observation)
    title = str(_value(observation, "title") or "")
    server = str(_value(observation, "server") or "").lower()

    web = service in {"http", "https", "http-alt"} or protocol in {"http", "https"}
    if web:
        if (
            service == "fastcgi"
            or protocol == "fastcgi"
            or 9000 in ports
            or framework in {"php", "php-fpm"}
            or "php" in server
        ):
            return [
                BranchRoute(
                    branch_key="http:php:fastcgi:validation",
                    kind="web",
                    priority=90,
                    mission=(
                        "Validate the discovered PHP FastCGI service family on the "
                        "reported endpoint using the HTTP interaction engine and "
                        "report deterministic response evidence."
                    ),
                    success_criteria=[
                        "service family confirmed or rejected with structured evidence",
                        "response fingerprints recorded",
                    ],
                )
            ]
        return [
            BranchRoute(
                branch_key="http:web:stack:fingerprint",
                kind="web",
                priority=80,
                mission=(
                    "Identify the web technology stack on the discovered HTTP "
                    "service, then select the matching path profile."
                ),
                success_criteria=[
                    "stack fingerprints recorded",
                    "path profile selected",
                ],
            )
        ]

    if service in {"ssh", "telnet", "ftp"} or protocol in {"ssh", "telnet", "ftp"}:
        return [
            BranchRoute(
                branch_key=f"tcp:{service}:auth:validation",
                kind="credential",
                priority=70,
                mission=(
                    "Validate authentication behavior on the discovered "
                    f"{service} service and record structured observations."
                ),
                success_criteria=[
                    "authentication behavior characterized",
                    "structured observations recorded",
                ],
            )
        ]

    if service in {
        "mysql",
        "postgresql",
        "postgres",
        "redis",
        "mongodb",
        "mssql",
        "oracle",
    } or protocol in {"mysql", "postgresql", "redis", "mongodb", "mssql"}:
        return [
            BranchRoute(
                branch_key=f"tcp:db:{service}:validation",
                kind="credential",
                priority=70,
                mission=(
                    "Characterize the discovered database service version and "
                    "authentication surface with structured observations."
                ),
                success_criteria=[
                    "database service characterized",
                    "structured observations recorded",
                ],
            )
        ]

    return [
        BranchRoute(
            branch_key="service:generic:probe",
            kind="general",
            priority=50,
            mission=(
                "Probe the discovered unknown service and record deterministic "
                "protocol observations."
            ),
            success_criteria=["protocol observations recorded"],
        )
    ]
