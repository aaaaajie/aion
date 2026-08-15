---
name: sqli-sql-injection
description: SQL query and database injection (SQLi) playbook for user input reaching login, search, filtering, sorting, report, export, and SQLite/MySQL/PostgreSQL operations; covers UNION, boolean, time, error, blind, out-of-band, stored, and second-order injection.
---

# Sqli Sql Injection Skill

## Purpose

SQL injection playbook. Use when input reaches SQL queries, authentication logic, sorting, filtering, reporting, or DB-specific blind and out-of-band execution paths.

## When to use

Use when:
- the task mentions `web`
- the task mentions `sqli`
- the task mentions `sql`
- the task mentions `injection`
- the task mentions `playbook.`

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
