---
name: ai-light-scanner
description: 为已识别为 AI 的比赛题生成两个低成本、可验证、可停止的首轮 artifact 与 inference API 入口任务；仅在 AI 方向已经确定后使用。
---

# AI Light Scanner Skill

## Purpose

确认一个目标范围是否包含模型、RAG、embedding、system prompt 或 inference API 入口。

## When to use

Use when:
- `domain=ai` 已由 Challenge Agent 确认
- 题目存在模型、RAG、embedding、prompt 或 inference API 线索
- 需要首轮低成本入口确认

## Strategy

1. `inspect_metadata`：读取题目元数据和目标范围。
2. `plan_independent_tasks`：拆分 artifact inspection 与 API baseline 两个独立问题。
3. `inspect_ai_surface`：使用只读文件工具检查明确 AI surface 线索。
4. `request_one_api_entry`：只有存在 exact API URL 时发送一次 `system_http_request`。
5. `report`：分别用简体中文报告并立即停止，保留 exact tool names、field names、paths、URLs 和 error codes。

## Classification Signals

- Positive AI paths：`/chat`、`/completions`、`/generate`、`/v1/models`、`/ask`。
- Positive request fields：`messages`、`prompt`、`input`、`system`、`model`、`temperature`、`max_tokens`、`top_p`。
- Positive response fields：`choices`、`role=assistant`、`content`、`usage`，以及 SSE `data:` 增量响应。
- 普通 login、upload、download、CRUD 或 CMS 只表示 Web business surface；必须引用模型字段、模型路径或 response shape 才确认 AI surface。

## Next-batch Handoff

- 每条 mission 以 `题目方向：AI；subdomain：null；判断状态：confirmed；依据：EVIDENCE_REFS。` 开头。
- 首轮任务保持 `timeout_seconds <= 480`；一次 API baseline 达到终态后立即交接。
- 新 model endpoint、RAG source、embedding store、system prompt 或 tool surface 先形成 terminal report，再由 Challenge Agent 创建一个对应原子任务。
- 本 Skill 只交接下一步假设和 evidence，不在当前 Execution Agent 中扩展 prompt 测试或 Flag 获取。

## Avoid

- 不进行批量 prompt、深度行为测试、漏洞验证或 Flag 获取。
- 不在领域未知时启动本 Skill。
- 不扩展到不同模型入口或重复请求。
- 调试脚本中的中文注释标记为 debugging-only。

## Success Criteria

成功结果必须包含：
- 一类明确 AI surface 线索
- exact path、exact URL 和响应分析引用
- 请求发生时的状态和响应摘要
- 明确终态和停止原因
