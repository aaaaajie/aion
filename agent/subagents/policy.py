"""Code-enforced Agent role and Worker mode permissions."""

from collections.abc import Iterable
from .models import AgentRole

TECH_TOOL_NAMES = frozenset(
    [
        "artifact_abi_summary",
        "artifact_disassemble",
        "artifact_identify",
        "artifact_static_review",
        "bin_checksec",
        "bin_debug",
        "bin_disassemble",
        "bin_identify",
        "bin_seccomp",
        "bin_strings",
        "bin_symbols",
        "evidence_read",
        "pentest_auth_brute",
        "pentest_channel_close",
        "pentest_channel_io",
        "pentest_privesc_check",
        "pentest_service_probe",
        "pentest_sqlmap",
        "pentest_jwt",
        "pentest_arjun",
        "pentest_ssh_close",
        "pentest_ssh_exec",
        "pentest_ssh_open",
        "pentest_ssh_pivot_open",
        "pentest_ssh_transfer",
        "pwn_libc_offsets",
        "pwn_pack",
        "pwn_process_open",
        "pwn_rop_search",
        "pwn_session_close",
        "pwn_session_io",
        "pwn_tcp_open",
        "skill_invoke",
        "skill_resource_read",
        "skill_search",
        "system_edit_file",
        "system_glob",
        "system_grep",
        "system_list_directory",
        "system_fastcgi_request",
        "system_http_output",
        "system_http_plan",
        "system_http_analyze",
        "system_http_probe",
        "system_http_request",
        "system_browser_open",
        "system_browser_action",
        "system_browser_output",
        "system_browser_export_request",
        "system_browser_close",
        "system_source_scan",
        "system_cyberchef",
        "system_http_replay",
        "system_http_compare",
        "system_poc_search",
        "system_poc_inspect",
        "system_poc_run",
        "system_poc_output",
        "system_http_response",
        "system_http_stop",
        "system_network_discovery",
        "system_network_output",
        "system_network_stop",
        "system_read_file",
        "system_shell",
        "system_task_start",
        "system_task_output",
        "system_task_stop",
        "system_web_path_probe",
        "system_write_file",
    ]
)
READ_TOOL_NAMES = frozenset({"evidence_search", "evidence_read", "report_read"})
ROLE_TOOL_NAMES = {
    "chief": frozenset(
        {
            "tool_result_read",
            "chief_observe",
            "chief_launch_challenges",
            "chief_wait",
            "chief_request_hint",
            "chief_pause_challenges",
            "chief_close_challenges",
        }
    ),
    "solver": TECH_TOOL_NAMES
    | READ_TOOL_NAMES
    | frozenset(
        {
            "tool_result_read",
            "solver_observe",
            "solver_delegate",
            "solver_cancel_worker",
            "solver_wait",
            "solver_progress",
            "solver_review",
            "solver_submit_flag",
        }
    ),
    "worker": TECH_TOOL_NAMES
    | READ_TOOL_NAMES
    | frozenset({"tool_result_read", "worker_update", "worker_report"}),
}


class AgentPolicy:
    def __init__(self, role: AgentRole, mode: str = "execute") -> None:
        if role not in ROLE_TOOL_NAMES or mode not in {"execute", "review"}:
            raise ValueError("unknown Agent role or mode")
        self.role = role
        self.allowed_tools = (
            READ_TOOL_NAMES | frozenset({"worker_report"})
            if role == "worker" and mode == "review"
            else ROLE_TOOL_NAMES[role]
        )

    def allows(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools

    def filter_definitions(self, definitions: Iterable[dict]) -> list[dict]:
        return [
            d
            for d in definitions
            if d.get("function", {}).get("name") in self.allowed_tools
        ]
