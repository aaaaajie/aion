---
name: cmdi-command-injection
description: Command injection playbook. Use when user input may reach shell commands, process execution, converters, import pipelines, or blind out-of-band command sinks.
---

# Cmdi Command Injection Skill

## Purpose

Command injection playbook. Use when user input may reach shell commands, process execution, converters, import pipelines, or blind out-of-band command sinks.

## When to use

Use when:
- the task mentions `exploit`
- the task mentions `cmdi`
- the task mentions `command`
- the task mentions `injection`
- the task mentions `playbook.`

## Strategy

1. Identify primitive.
2. Build poc.
3. Stabilize.
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
