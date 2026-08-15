---
name: business-logic-vulnerabilities
description: Business logic vulnerability playbook. Use when reasoning about workflows, race conditions, price manipulation, coupon abuse, state machines, and multi-step authorization gaps.
---

# Business Logic Vulnerabilities Skill

## Purpose

Business logic vulnerability playbook. Use when reasoning about workflows, race conditions, price manipulation, coupon abuse, state machines, and multi-step authorization gaps.

## When to use

Use when:
- the task mentions `web`
- the task mentions `business`
- the task mentions `logic`
- the task mentions `vulnerabilities`
- the task mentions `vulnerability`

## Strategy

1. Detect.
2. Confirm.
3. Exploit.
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
