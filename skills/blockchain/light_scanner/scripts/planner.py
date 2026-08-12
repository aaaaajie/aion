"""Deterministic first-round planner for the Blockchain lightweight scanner Skill."""

from __future__ import annotations

from scan.contracts import ScannerContext, ScannerTaskSpec


class BlockchainLightScanner:
    domain = "blockchain"
    scanner_profile = "blockchain_light"

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        return [
            ScannerTaskSpec(
                task_key="blockchain-light-artifact-1",
                hypothesis_key="blockchain:artifact-surface",
                branch_key="scanner:blockchain:artifact:inspect",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="blockchain_artifact_inspection",
                verification_question="目标范围是否存在 Solidity、ABI 或合约地址 artifact？",
                objective=(
                    "使用 system_read_file、system_glob、system_grep 执行一次受限只读检查，"
                    "只回答 Solidity、ABI、合约地址或链配置 artifact 是否存在。"
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
                    "确认 Solidity、ABI、合约地址或链配置中的至少一类证据",
                ),
                failure_criteria=(
                    "一次受限只读检查没有发现 Blockchain artifact",
                ),
                evidence_requirements=(
                    "记录 exact path、匹配字段和 artifact 摘要",
                ),
                stop_conditions=(
                    "一次 bounded glob/grep/read pass 完成后立即报告",
                ),
                scanner_profile="blockchain_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                timeout_seconds=300,
            ),
            ScannerTaskSpec(
                task_key="blockchain-light-rpc-entry-1",
                hypothesis_key="blockchain:rpc-surface",
                branch_key="scanner:blockchain:rpc:baseline",
                kind="recon",
                task_phase="reconnaissance",
                entry_point=context.target_scope[0],
                capability_class="rpc_baseline",
                verification_question="已提供的入口是否为可解释的 JSON-RPC 服务？",
                objective=(
                    "仅在 assignment 提供 exact RPC URL 时发送一次 system_http_request，"
                    "读取状态和响应摘要；否则报告 RPC 入口证据不足。"
                ),
                target_scope=context.target_scope,
                tool_names=(
                    "execution_get_assignment",
                    "system_http_request",
                    "system_http_output",
                    "system_http_analyze",
                    "execution_report",
                ),
                priority=84,
                success_criteria=("确认一个 JSON-RPC 入口及其响应特征",),
                failure_criteria=("没有 exact RPC URL 或一次请求没有可解释响应",),
                evidence_requirements=("记录 exact URL、RPC method、status 和响应摘要",),
                stop_conditions=("一次 RPC request 达到终态后立即报告",),
                scanner_profile="blockchain_light",
                cost_class="low",
                context_refs=context.evidence_refs,
                max_http_requests=1,
                timeout_seconds=180,
            ),
        ]
