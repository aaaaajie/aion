---
name: blockchain-light-scanner
description: 为已识别为 Blockchain 的比赛题生成两个低成本、可验证、可停止的首轮 artifact 与 RPC 入口任务；仅在 Blockchain 方向已经确定后使用。
---

# Blockchain Light Scanner Skill

## Purpose

确认一个目标范围是否包含 Solidity、ABI、合约地址或 JSON-RPC 入口。

## When to use

Use when:
- `domain=blockchain` 已由 Challenge Agent 确认
- 题目存在合约源码、ABI、链地址或 RPC URL 线索
- 需要首轮低成本入口确认

## Strategy

1. `inspect_metadata`：读取题目元数据和目标范围。
2. `plan_independent_tasks`：拆分 artifact inspection 与 RPC baseline 两个独立问题。
3. `inspect_artifacts`：使用 `system_read_file`、`system_glob`、`system_grep` 检查明确 artifact。
4. `request_one_rpc_entry`：只有存在 exact RPC URL 时发送一次 `system_http_request`。
5. `report`：分别用简体中文报告并立即停止，保留 exact tool names、field names、paths、URLs 和 error codes。

## Classification Signals

- Positive Blockchain signals：Solidity、ABI、contract address、bytecode、JSON-RPC、wallet、nonce、gas、transaction、event、Foundry 或 Hardhat。
- HTTP URL 只表示 RPC transport；必须引用 contract、chain、RPC method 或 transaction evidence 才确认 Blockchain surface。
- 普通 Web CRUD 或模型 API response 属于 cross-domain evidence，记录 exact URL、field 和 response evidence 后报告 Challenge Agent。

## Next-batch Handoff

- 每条 mission 以 `题目方向：Blockchain；subdomain：null；判断状态：confirmed；依据：EVIDENCE_REFS。` 开头。
- 首轮任务保持 `timeout_seconds <= 480`；一次 RPC baseline 达到终态后立即交接。
- 新 contract、function、event、address 或 RPC surface 先形成 terminal report，再由 Challenge Agent 创建一个对应原子任务。
- 本 Skill 只交接下一步假设和 evidence，不在当前 Execution Agent 中发送链上写入或获取 Flag。

## Avoid

- 不进行批量 RPC、漏洞验证、资产转移或 Flag 获取。
- 不在领域未知时启动本 Skill。
- 不扩展到第二类能力或重复请求。
- 调试脚本中的中文注释标记为 debugging-only。

## Success Criteria

成功结果必须包含：
- 一类明确 Blockchain 入口
- exact path、exact URL、RPC method 或 artifact 字段
- 请求发生时的状态和响应摘要
- 明确终态和停止原因
