"""Code-enforced role permissions for subagents."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AgentRole


ROLE_TOOL_NAMES: dict[AgentRole, frozenset[str]] = {
    "chief": frozenset(
        {
            "chief_refresh_challenges",
            "chief_get_core_state",
            "chief_get_schedule",
            "chief_create_challenge_agent",
            "chief_get_challenge_reports",
            "chief_wait_for_state",
            "chief_request_hint",
            "chief_extend_stagnation",
        }
    ),
    "challenge": frozenset(
        {
            "skill_list",
            "skill_read",
            "challenge_get_state",
            "challenge_begin_cycle",
            "challenge_submit_analysis_plan",
            "challenge_commit_cycle",
            "challenge_create_execution_agent",
            "challenge_get_execution_reports",
            "challenge_get_updates",
            "challenge_wait_for_state",
            "challenge_report_status",
            "challenge_submit_flag",
            "challenge_close_challenge",
        }
    ),
    "execution": frozenset(
        {
            "skill_list",
            "skill_read",
            "execution_get_assignment",
            "execution_update_progress",
            "execution_report",
            "system_read_file",
            "system_write_file",
            "system_edit_file",
            "system_create_directory",
            "system_delete_path",
            "system_list_directory",
            "system_glob",
            "system_grep",
            "system_shell",
            "system_task_output",
            "system_task_stop",
            "system_task_cleanup",
            "system_http_request",
            "system_http_probe",
            "system_web_path_probe",
            "system_web_fingerprint",
            "system_http_analyze",
            "system_http_output",
            "system_http_response",
            "system_http_stop",
            "system_http_cleanup",
            "system_network_discovery",
            "system_network_output",
            "system_network_stop",
            "system_network_cleanup",
        }
    ),
}


class AgentPolicy:
    """Immutable allow-list; prompts and model arguments cannot extend it."""

    def __init__(self, role: AgentRole) -> None:
        if role not in ROLE_TOOL_NAMES:
            raise ValueError("unknown Agent role")
        self.role = role
        self.allowed_tools = ROLE_TOOL_NAMES[role]

    def allows(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools

    def filter_definitions(self, definitions: Iterable[dict]) -> list[dict]:
        return [
            definition
            for definition in definitions
            if definition.get("function", {}).get("name") in self.allowed_tools
        ]
