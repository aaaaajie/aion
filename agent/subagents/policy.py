"""Code-enforced role permissions for subagents."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AgentRole


ROLE_TOOL_NAMES: dict[AgentRole, frozenset[str]] = {
    "chief": frozenset(
        {
            "tool_result_read",
            "chief_observe",
            "chief_launch_challenges",
            "chief_wait",
            "chief_request_hint",
        }
    ),
    "challenge": frozenset(
        {
            "tool_result_read",
            "skill_search",
            "skill_invoke",
            "skill_resource_read",
            "challenge_observe",
            "challenge_dispatch",
            "challenge_wait",
            "challenge_submit_flag",
            "challenge_close",
            "evidence_read",
        }
    ),
    "execution": frozenset(
        {
            "skill_search",
            "skill_invoke",
            "skill_resource_read",
            "execution_report",
            "evidence_read",
            "system_read_file",
            "system_write_file",
            "system_edit_file",
            "system_list_directory",
            "system_glob",
            "system_grep",
            "system_shell",
            "system_task_output",
            "system_task_stop",
            "system_http_request",
            "system_http_probe",
            "system_web_path_probe",
            "system_web_fingerprint",
            "system_http_analyze",
            "system_http_output",
            "system_http_response",
            "system_http_stop",
            "system_network_discovery",
            "system_network_output",
            "system_network_stop",
            "bin_identify",
            "bin_strings",
            "bin_checksec",
            "bin_symbols",
            "bin_disassemble",
            "bin_patch_elf",
            "pwn_pack",
            "pwn_rop_search",
            "pwn_libc_offsets",
            "bin_seccomp",
            "bin_debug",
            "pentest_service_probe",
            "pentest_auth_brute",
            "pentest_sqlmap",
            "pentest_dir_fuzz",
            "pentest_credential_lookup",
            "pentest_privesc_check",
            "cloud_enum",
            "evasion_payload_analyze",
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
