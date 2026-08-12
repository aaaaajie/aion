"""Deterministic first-round planner for the Web lightweight scanner Skill."""

from __future__ import annotations

from scan.contracts import ScannerContext, ScannerTaskSpec


class WebLightScanner:
    domain = "web"
    scanner_profile = "web_light"

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        return [
            ScannerTaskSpec(
                task_key="web-light-fingerprint-1",
                hypothesis_key="web:surface-stack",
                branch_key="scanner:web:surface:fingerprint",
                kind="web",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="web_fingerprint",
                verification_question="该入口是否为 Web 服务，以及可确认的技术栈是什么？",
                objective=(
                    "使用 system_web_fingerprint 对一个目标入口执行被动 Web 指纹识别，"
                    "确认 HTTP 状态、标题、响应头、favicon 和技术栈；只回答目标是否为 Web 服务及其技术栈。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_web_fingerprint",
                    "system_http_output",
                    "system_http_analyze",
                    "execution_report",
                ),
                priority=90,
                success_criteria=(
                    "目标入口的 Web 服务状态和技术栈已确认",
                    "system_web_fingerprint 的 interaction_id 或 task_id 已记录",
                ),
                failure_criteria=(
                    "目标入口不是 HTTP 服务",
                    "一次指纹任务结束但没有可解释的响应证据",
                ),
                evidence_requirements=(
                    "记录 exact URL、HTTP status、title、server/header 摘要和 interaction_id",
                ),
                stop_conditions=(
                    "一次 system_web_fingerprint 任务完成",
                    "使用 system_http_output 获取终态后立即报告",
                ),
                scanner_profile="web_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                max_http_requests=1,
                timeout_seconds=300,
            ),
            ScannerTaskSpec(
                task_key="web-light-artifact-clues-1",
                hypothesis_key="web:local-artifact-clues",
                branch_key="scanner:web:artifact:clues",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="web_artifact_inspection",
                verification_question="本地 artifact 是否包含框架、路由或配置线索？",
                objective=(
                    "使用 system_glob、system_grep 和 system_read_file 执行一次受限只读检查，"
                    "只回答本地 artifact 是否暴露 Web 框架、路由或配置线索。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_read_file",
                    "system_glob",
                    "system_grep",
                    "execution_report",
                ),
                priority=82,
                success_criteria=("确认一类 Web 框架、路由或配置线索",),
                failure_criteria=("一次受限只读检查没有发现 Web artifact 线索",),
                evidence_requirements=("记录 exact path、匹配字段和读取摘要",),
                stop_conditions=("一个 bounded glob/grep/read pass 完成后立即报告",),
                scanner_profile="web_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                timeout_seconds=180,
            ),
        ]
