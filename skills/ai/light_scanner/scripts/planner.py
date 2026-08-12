"""Deterministic first-round planner for the AI lightweight scanner Skill."""

from __future__ import annotations

from scan.contracts import ScannerContext, ScannerTaskSpec


class AILightScanner:
    domain = "ai"
    scanner_profile = "ai_light"

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        return [
            ScannerTaskSpec(
                task_key="ai-light-metadata-1",
                hypothesis_key="ai:model-artifact-surface",
                branch_key="scanner:ai:artifact:metadata",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="ai_artifact_inspection",
                verification_question="本地 artifact 是否包含模型、RAG、embedding 或 system prompt 线索？",
                objective=(
                    "使用 system_read_file、system_glob、system_grep 执行一次受限只读检查，"
                    "只回答模型、RAG、embedding 或 system prompt artifact 是否存在。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_read_file",
                    "system_glob",
                    "system_grep",
                    "execution_report",
                ),
                priority=88,
                success_criteria=(
                    "确认模型、RAG、embedding 或 system prompt 中的一类明确线索",
                ),
                failure_criteria=(
                    "一次受限只读检查没有发现 AI artifact 线索",
                ),
                evidence_requirements=(
                    "记录 exact path、匹配字段和读取摘要",
                ),
                stop_conditions=(
                    "一次 bounded glob/grep/read pass 完成后立即报告",
                ),
                scanner_profile="ai_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                timeout_seconds=300,
            ),
            ScannerTaskSpec(
                task_key="ai-light-api-entry-1",
                hypothesis_key="ai:inference-api-surface",
                branch_key="scanner:ai:api:baseline",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="ai_api_baseline",
                verification_question="已提供的入口是否暴露可解释的 inference API？",
                objective=(
                    "仅在 assignment 提供 exact API URL 时发送一次 system_http_request，"
                    "读取状态和响应摘要；否则报告 API 入口证据不足。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_http_request",
                    "system_http_output",
                    "system_http_analyze",
                    "system_http_response",
                    "execution_report",
                ),
                priority=84,
                success_criteria=("确认一个 inference API 入口及其响应特征",),
                failure_criteria=("没有 exact API URL 或一次请求没有可解释响应",),
                evidence_requirements=("记录 exact URL、status、响应摘要和 request_id",),
                stop_conditions=("一次 API request 达到终态后立即报告",),
                scanner_profile="ai_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                max_http_requests=1,
                timeout_seconds=180,
            ),
        ]
