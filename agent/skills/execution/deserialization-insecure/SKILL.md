---
name: deserialization-insecure
description: Insecure deserialization playbook for unsafe pickle, Python pickle, PHP unserialize and POP chains, Java ObjectInputStream gadget chains, serialized cookies or templates, object injection, magic methods, file write, authentication bypass, and RCE.
---

# Deserialization Insecure Skill

## Purpose

Insecure deserialization playbook. Use when Java, PHP, or Python applications deserialize untrusted data via ObjectInputStream, unserialize, pickle, or similar mechanisms that may lead to RCE, file access, or privilege escalation.

## When to use

Use when:
- the task mentions `web`
- the task mentions `deserialization`
- the task mentions `insecure`
- the task mentions `playbook.`
- the task mentions `use`

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
