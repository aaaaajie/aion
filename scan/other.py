"""Other-domain lightweight scanner planner."""

from __future__ import annotations

from .contracts import ScannerContext, ScannerTaskSpec


class OtherLightScanner:
    domain = "other"
    scanner_profile = "other_light"

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        return [
            ScannerTaskSpec(
                task_key="other-light-surface-profile-1",
                hypothesis_key="other:surface-profile",
                branch_key="scanner:other:surface:profile",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="generic_surface_profile",
                verification_question="目标范围中可确认的一类协议或 artifact 线索是什么？",
                objective=(
                    "对一个目标范围执行一次轻量 Other surface profile：优先读取明确的文件、"
                    "目录或题目线索；若目标是单个主机且服务未知，执行一次受限 system_network_discovery。"
                    "只回答协议、artifact、binary、forensics 或 cryptography 线索中的一类。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_read_file",
                    "system_list_directory",
                    "system_glob",
                    "system_grep",
                    "system_network_discovery",
                    "system_network_output",
                    "execution_report",
                ),
                priority=75,
                success_criteria=(
                    "确认一类 Other 方向的协议、artifact、binary、forensics 或 cryptography 线索",
                    "网络任务若被创建，已记录 task_id、服务摘要和终态",
                ),
                failure_criteria=(
                    "目标范围没有可解释的 Other 方向线索",
                    "一次受限网络任务结束但没有服务证据",
                ),
                evidence_requirements=(
                    "记录 exact path、目标、task_id、服务名称、版本或线索摘要",
                ),
                stop_conditions=(
                    "确认一类 Other 方向线索",
                    "一次 system_network_discovery 任务完成后立即报告",
                ),
                scanner_profile="other_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                max_network_tasks=1,
                timeout_seconds=300,
            )
        ]
