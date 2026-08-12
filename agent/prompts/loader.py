"""Load editable prompt templates shipped with the production runtime."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from string import Template


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    """Read one prompt resource and fail clearly when it is missing or empty."""

    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("invalid prompt resource name")
    try:
        content = files("agent.prompts").joinpath(name).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"production prompt resource is missing: {name}") from exc
    content = content.strip()
    if not content:
        raise RuntimeError(f"production prompt resource is empty: {name}")
    return content


def render_prompt(name: str, **values: object) -> str:
    """Render a prompt template using explicit named values."""

    try:
        return Template(load_prompt(name)).substitute(
            {key: str(value) for key, value in values.items()}
        )
    except KeyError as exc:
        raise RuntimeError(
            f"production prompt template has an unresolved variable: {exc.args[0]}"
        ) from exc


def system_prompt(role: str) -> str:
    """Compose the invariant base prompt with one role-specific system prompt."""

    if role not in {"chief", "challenge", "execution"}:
        raise ValueError("unknown Agent role")
    return "\n\n".join(
        (
            load_prompt("base_system.txt"),
            load_prompt(f"{role}_system.txt"),
        )
    )
