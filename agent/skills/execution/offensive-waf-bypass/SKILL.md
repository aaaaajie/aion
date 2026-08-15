---
name: offensive-waf-bypass
description: 'WAF bypass techniques checklist: encoding bypass (URL/HTML/Unicode/double encoding), case variation, comment injection, HTTP header manipulation, chunked encoding, IP rotation, timing attacks, and payload obfuscation per WAF vendor. Use when WAF is blocking payloads during web app tests.'
---

# Offensive Waf Bypass Skill

## Purpose

WAF bypass techniques checklist: encoding bypass (URL/HTML/Unicode/double encoding), case variation, comment injection, HTTP header manipulation, chunked encoding, IP rotation, timing attacks, and payload obfuscation per WAF vendor. Use when WAF is blocking payloads during web app tests.

## When to use

Use when:
- the task mentions `evasion`
- the task mentions `waf`
- the task mentions `bypass`
- the task mentions `checklist`
- the task mentions `encoding`

## Strategy

1. Identify control.
2. Select bypass.
3. Test.
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
