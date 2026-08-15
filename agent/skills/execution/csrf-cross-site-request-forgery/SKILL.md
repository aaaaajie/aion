---
name: csrf-cross-site-request-forgery
description: CSRF testing playbook. Use when reviewing state-changing web flows, anti-CSRF
  defenses, SameSite behavior, JSON CSRF, login CSRF, and OAuth state handling.
---

# Csrf Cross Site Request Forgery Skill

## Purpose

CSRF testing playbook. Use when reviewing state-changing web flows, anti-CSRF defenses, SameSite behavior, JSON CSRF, login CSRF, and OAuth state handling.

## When to use

Use when:
- the task mentions `web`
- the task mentions `csrf`
- the task mentions `cross`
- the task mentions `site`
- the task mentions `request`

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
