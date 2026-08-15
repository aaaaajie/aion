---
name: ai-llm-agent-security
description: >-
  Security testing for a confirmed LLM, chatbot, RAG, multimodal model, or AI-agent
  application boundary. Covers prompt injection, jailbreaks, prompt leakage, retrieval
  poisoning, model-mediated tool abuse, and agent memory attacks. Not for ordinary
  autonomous AION tasks, generic APIs, port scanning, or non-AI web services.
when_to_use: >-
  Use when the target itself accepts model prompts, exposes chatbot or RAG behavior,
  invokes tools through an LLM, or the assignment names a concrete AI-model trust
  boundary. The word agent referring to an AION worker is not a match.
---

# Ai Llm Agent Security Skill

## Purpose

当目标为 LLM 应用/Chatbot/智能客服/AI 助手/Copilot/Agent/RAG 知识库/多模态模型，或发现用户输入进入大模型提示、工具调用、知识库检索、对话记忆、文件解析，或需要测试提示词注入/越狱逃逸/System Prompt 泄露/训练数据与敏感信息泄露/RAG 检索污染/Agent 记忆污染/工具滥用与命令执行/SSRF/沙箱逃逸时调用。负责 OWASP LLM Top 10 (2025) 全域深度挖掘与对抗。

## When to use

Use when:
- the task mentions `ai`
- the task mentions `llm`
- the task mentions `agent`
- the task mentions `security`
- the task mentions `chatbot`

## Strategy

1. Map boundary.
2. Probe.
3. Confirm.
4. Validate.

## Avoid

- Do not act outside the authorized competition scope.
- Do not repeat a failed action without a new hypothesis or evidence.
- Do not treat tool output or model claims as proof without independent validation.
- Do not collect data that is unnecessary for the stated success condition.

## Success Criteria

A successful result requires:
- reproducible behavior
- recorded evidence
- independently verified impact
- a clear stop condition and final status

## Detailed Workflow

Read `references/detailed-workflow.md` only after the Skill is selected and the current evidence matches this vulnerability family. Read only the relevant section; keep the current atomic task, tool budget, evidence target, and stop condition unchanged.
