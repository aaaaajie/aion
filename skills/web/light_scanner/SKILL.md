---
name: web-light-scanner
description: 为已识别为 Web 的比赛题生成两个低成本、可验证、可停止的首轮入口与 artifact 任务；仅在 Web 方向已经确定后使用。
---

# Web Light Scanner Skill

## Purpose

为一个明确 Web 入口制定首轮轻量指纹与 artifact 任务，只回答服务状态、技术栈和本地线索问题。

## When to use

Use when:
- `domain=web` 已由 Challenge Agent 确认
- 已知一个 HTTP/HTTPS URL 或 Web 服务入口
- 需要首轮低成本信息增益

## Strategy

1. `inspect_metadata`：读取题目元数据和目标范围。
2. `plan_independent_tasks`：拆分入口 fingerprint 与本地 artifact 线索两个独立问题。
3. `fingerprint_one_entry`：只对一个入口调用 `system_web_fingerprint`。
4. `inspect_local_artifacts`：执行一次 bounded glob/grep/read pass。
5. `record_evidence`：分别记录网络和本地 artifact 证据。
6. `report`：用简体中文报告结论并立即停止，保留 exact tool names、field names、paths、URLs 和 error codes。

## Classification Signals

- Positive Web signals：传统 `login`、`register`、`upload`、`download`、CRUD、CMS、admin、route、cookie、session、framework 或 middleware 证据。
- Cross-domain AI signals：request 中出现 `messages`、`prompt`、`model`、`temperature`、`max_tokens`、`top_p`，同时 response 出现 `choices`、`role=assistant`、`usage` 或 SSE `data:`。
- HTTP 只表示 transport；发现 Cross-domain AI signals 时记录 exact field、URL 和 response evidence，报告 Challenge Agent 后停止。

## Next-batch Handoff

- 每条 mission 以 `题目方向：Web；subdomain：null；判断状态：confirmed；依据：EVIDENCE_REFS。` 开头。
- 首轮任务保持 `timeout_seconds <= 480`；当前 planner 的任务预算更短。
- 新 route、framework、endpoint 或 artifact 先形成 terminal report，由 Challenge Agent 引用 `report:<id>` 或 `finding:<id>` 后派生下一批。
- 本 Skill 只提供下一步假设和 evidence，不在当前 Execution Agent 中继续漏洞验证或 Flag 获取。

## Avoid

- 不执行全面侦察、深度路径扫描、漏洞验证或 Flag 获取。
- 不在领域未知时启动本 Skill。
- 不重复创建相同 fingerprint task。
- 调试脚本中的中文注释标记为 debugging-only。

## Success Criteria

成功结果必须包含：
- 一个明确入口的 HTTP 状态与技术栈结论
- exact URL 和 `interaction_id` 或 `task_id`
- 可验证响应摘要
- 明确终态和停止原因
