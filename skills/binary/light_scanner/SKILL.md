---
name: binary-light-scanner
description: 为已识别为 Other 的比赛题生成低成本、可验证、可停止的首轮 binary、reverse、pwn、forensics 或 cryptography artifact 任务；仅在 Other 方向已经确定后使用。
---

# Binary Light Scanner Skill

## Purpose

定位一个主要 artifact，并确认 Other subdomain、格式、架构或题型线索，不进入深度分析。

## When to use

Use when:
- `domain=other` 已由 Challenge Agent 确认
- 题目存在 ELF、PE、APK、firmware、pcap、dump、ciphertext 或其他本地 artifact
- 需要首轮低成本 artifact profile

## Strategy

1. `inspect_metadata`：读取题目元数据和目标范围。
2. `plan_independent_tasks`：拆分主要 artifact profile 与 Other subdomain classification 两个独立问题。
3. `locate_one_artifact`：使用 `system_list_directory` 和 `system_glob` 定位一个主要 artifact。
4. `profile_artifact`：使用一次受限 `system_shell` 任务确认文件类型、大小、hash 或架构。
5. `classify_subdomain`：只读判断 binary、pwn、reverse、forensics 或 cryptography。
6. `report`：分别用简体中文报告并立即停止，保留 exact tool names、field names、paths、URLs 和 error codes。

## Classification Signals

- `binary`：ELF、PE、executable、firmware 或 architecture evidence。
- `pwn`：remote interactive service、`nc` entry、ROP、buffer overflow 或 protection metadata。
- `reverse`：APK、decompile、disassemble、obfuscated logic 或 validation routine。
- `forensics`：pcap、memory dump、disk image、steganography 或 event artifact。
- `cryptography`：ciphertext、RSA、AES、key material 或 encoded challenge data。

## Next-batch Handoff

- 每条 mission 以 `题目方向：Other；subdomain：SUBDOMAIN；判断状态：confirmed；依据：EVIDENCE_REFS。` 开头。
- 首轮任务保持 `timeout_seconds <= 480`；一个 artifact profile 或 subdomain classification 达到终态后立即交接。
- 新 artifact、architecture、protocol 或 subdomain clue 先形成 terminal report，再由 Challenge Agent 创建一个对应原子任务。
- 本 Skill 只交接下一步假设和 evidence，不在当前 Execution Agent 中继续反编译、fuzzing、漏洞验证或 Flag 获取。

## Avoid

- 不执行反编译、fuzzing、漏洞验证、利用链或 Flag 获取。
- 不在领域未知时启动本 Skill。
- 不扩展到多个 artifact 或多类能力。
- 调试脚本中的中文注释标记为 debugging-only。

## Success Criteria

成功结果必须包含：
- 一个主要 artifact 的 exact path
- 文件类型、大小、hash、架构或可解释题型线索
- `task_id` 或等价执行证据
- 明确终态和停止原因
