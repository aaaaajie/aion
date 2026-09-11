"""Small, stable model tool surface over the existing typed tool registry."""

from __future__ import annotations

import difflib
import re

from pydantic import BaseModel, ConfigDict, Field


class ToolSearchArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str = Field(
        default="",
        max_length=200,
        description="Keywords for a paginated candidate list; does not expose a tool.",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Exact authorized tool name; exposes its native function in the next model turn.",
    )
    offset: int = Field(default=0, ge=0, description="Candidate-list offset; ignored for exact name lookup.")
    limit: int = Field(default=6, ge=1, le=10, description="At most 10 candidate names.")


DIRECT_TOOLS = frozenset(
    {
        "system_read_file",
        "system_write_file",
        "system_edit_file",
        "system_shell",
        "system_task_start",
        "system_task_output",
        "system_task_stop",
        "system_http_output",
        "system_http_response",
        "tool_result_read",
        "evidence_search",
        "evidence_read",
        "report_read",
        "system_glob",
        "system_grep",
        "system_list_directory",
        "solver_observe",
        "solver_delegate",
        "solver_wait",
        "solver_submit_flag",
        "worker_update",
        "worker_report",
    }
)


def search_spec(specs, *, on_exact=None, known_specs=None):
    from .tooling import AccessClaim, ToolSpec, tool_error
    from .tool_examples import examples_for

    def search(args: ToolSearchArguments):
        if args.name is not None:
            spec = specs.get(args.name)
            if spec is None:
                if known_specs is not None and args.name in known_specs:
                    return tool_error(
                        "permission",
                        "tool_not_allowed_for_role",
                        "Tool is known but not allowed for this Agent role",
                        details={"tool": args.name},
                    )
                candidates = difflib.get_close_matches(
                    args.name,
                    [name for name in specs if name != "tool_search"],
                    n=3,
                    cutoff=0.45,
                )
                correction = (
                    {"next_tool": "tool_search", "next_arguments": {"name": candidates[0]}}
                    if candidates
                    else {"next_tool": "tool_search", "next_arguments": {"query": args.name}}
                )
                return tool_error(
                    "schema",
                    "unknown_tool",
                    "Unknown Agent tool",
                    details={"candidates": candidates, **correction},
                )
            if on_exact is not None:
                surface = on_exact(spec.name)
            else:
                surface = {"surfaced": True, "evicted": None, "slots": []}
            return {
                "ok": True,
                "data": {
                    "tool": spec.definition()["function"],
                    "requires_solo": spec.requires_solo,
                    "examples": examples_for(spec.name, spec.input_model),
                    "available_next_turn": True,
                    **surface,
                },
            }
        terms = re.findall(r"[\w]+", args.query.casefold())
        ranked = []
        for name, spec in specs.items():
            if name == "tool_search":
                continue
            searchable = f"{name} {spec.description}".casefold()
            score = sum(
                3 if term in name.casefold() else 1
                for term in terms
                if term in searchable
            )
            if not terms or score:
                ranked.append((-score, name, spec))
        ranked.sort(key=lambda row: (row[0], row[1]))
        rows = ranked[args.offset : args.offset + args.limit]
        end = args.offset + len(rows)
        return {
            "ok": True,
            "data": {
                "tools": [
                    {"name": name, "description": spec.description[:220]}
                    for _, name, spec in rows
                ],
                "next_offset": end if end < len(ranked) else None,
                "total": len(ranked),
            },
        }

    return ToolSpec(
        "tool_search",
        "Search authorized control, evidence, Skill, HTTP, network, binary and SSH tools. Empty or query search only lists names. Use name=exact_tool_name to return its full schema and examples; that tool is available as a native function in the next model turn. Invoke the returned function directly by its exact name; do not wrap one function call inside another.",
        ToolSearchArguments,
        search,
        lambda _: (AccessClaim("read", "tool_catalog"),),
    )
