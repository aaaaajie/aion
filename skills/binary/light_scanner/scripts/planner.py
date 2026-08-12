"""Deterministic first-round planner for the Binary lightweight scanner Skill."""

from __future__ import annotations

from scan.contracts import ScannerContext, ScannerTaskSpec


class BinaryLightScanner:
    domain = "other"
    scanner_profile = "binary_light"

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        return [
            ScannerTaskSpec(
                task_key="binary-light-artifact-profile-1",
                hypothesis_key="binary:primary-artifact-profile",
                branch_key="scanner:binary:artifact:profile",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="artifact_profile",
                verification_question="目标范围中的主要 artifact 是什么以及其基础格式是什么？",
                objective=(
                    "对一个目标范围执行一次轻量 Binary artifact profile：使用 system_list_directory "
                    "和 system_glob 定位一个主要 artifact，再使用一次受限 system_shell 任务确认其"
                    "文件类型、大小、hash 或架构。只回答主要 artifact 是什么以及其基础格式。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_read_file",
                    "system_list_directory",
                    "system_glob",
                    "system_shell",
                    "system_task_output",
                    "execution_report",
                ),
                priority=85,
                success_criteria=(
                    "确认一个主要 artifact 的 exact path 和基础格式",
                    "记录文件类型、大小、hash、架构或一类明确题型线索",
                ),
                failure_criteria=(
                    "目标范围没有可读取的 Binary artifact",
                    "一次受限 profile 任务结束但没有可解释的 artifact 证据",
                ),
                evidence_requirements=(
                    "记录 exact path、文件类型、大小、hash、架构摘要和 task_id",
                ),
                stop_conditions=(
                    "一个主要 artifact profile 完成",
                    "一次 system_shell 任务达到终态后立即报告",
                ),
                scanner_profile="binary_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                max_shell_tasks=1,
                timeout_seconds=300,
            ),
            ScannerTaskSpec(
                task_key="other-light-subdomain-clues-1",
                hypothesis_key="other:subdomain-clues",
                branch_key="scanner:other:subdomain:clues",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="other_subdomain_classification",
                verification_question="现有 artifact 更符合 binary、pwn、reverse、forensics 还是 cryptography？",
                objective=(
                    "使用 system_list_directory、system_glob 和 system_read_file 执行一次受限只读检查，"
                    "只回答 Other 方向的 subdomain 分类问题。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_read_file",
                    "system_list_directory",
                    "system_glob",
                    "execution_report",
                ),
                priority=80,
                success_criteria=("确认 binary、pwn、reverse、forensics 或 cryptography 中的一类",),
                failure_criteria=("一次受限只读检查没有足够 subdomain 证据",),
                evidence_requirements=("记录 exact path、artifact 类型和分类线索",),
                stop_conditions=("一个 bounded artifact clue pass 完成后立即报告",),
                scanner_profile="binary_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                timeout_seconds=180,
            ),
        ]
