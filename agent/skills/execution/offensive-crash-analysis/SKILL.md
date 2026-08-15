---
name: offensive-crash-analysis
description: 'Week 4 exploit development curriculum. Crash triage and analysis methodology:
  WinDbg/GDB analysis, ASAN/MSAN output interpretation, exploitability assessment,
  register/stack trace reading, root cause identification. Use when analyzing crash
  dumps, assessing exploitability, or understanding fuzzer-generated crashes.'
---

# Offensive Crash Analysis Skill

## Purpose

Week 4 exploit development curriculum. Crash triage and analysis methodology: WinDbg/GDB analysis, ASAN/MSAN output interpretation, exploitability assessment, register/stack trace reading, root cause identification. Use when analyzing crash dumps, assessing exploitability, or understanding fuzzer-generated crashes.

## When to use

Use when:
- the task mentions `binary`
- the task mentions `crash`
- the task mentions `analysis`
- the task mentions `week`
- the task mentions `exploit`

## Strategy

1. Inspect.
2. Analyze.
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
