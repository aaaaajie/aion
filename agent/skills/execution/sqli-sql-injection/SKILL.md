---
name: sqli-sql-injection
description: Bounded SQL injection playbook for login and authentication forms, request parameters, search, filtering, sorting, reports, exports, and SQLite/MySQL/PostgreSQL operations; covers manual differential checks, sqlmap, boolean, time, error, and blind injection.
when_to_use: Use when the assigned branch names SQLi, SQL injection, sqlmap, blind or time-based SQL, a database error, or a login/authentication form returns a stable 500/5xx that needs SQLi triage. Not for generic Web reconnaissance, default-credential testing, or unrelated command injection.
---

# Sqli Sql Injection Skill

## Purpose

Determine whether an authorized target input reaches SQL queries, especially when a login form is unusable. A stable 500/5xx is evidence of an application failure, not proof of SQL injection or proof that SQL injection is absent; first test whether the response is input-controlled.

## When to use

Use when the task or current evidence includes one of these high-signal conditions:

- an explicit `sqli`, `SQL injection`, `login-sqli`, `sqlmap`, blind-SQL, or time-based-SQL hypothesis;
- a login or authentication form with a stable 500/5xx, database error, or reproducible response/timing differential;
- a request parameter, cookie, header, search, filter, sort, report, or export field suspected to reach a database query.

Do not auto-activate for a generic Web task, ordinary login/default-credential testing, or shell/command injection.

## Fixed workflow

1. Capture the exact request: URL, method, parameter names, form body, content type, relevant headers, cookies, CSRF value, and the baseline status/body hash/latency.
2. Triage the login failure. Compare a baseline with a small number of controlled true/false/error inputs. A constant 500 with no input or timing difference is an application/template/DB failure hypothesis, not a confirmed SQLi result.
3. If there is a concrete parameter and the request is reproducible, call `pentest_sqlmap` once with the exact URL/body and bounded level, risk, status-code handling, and timeout. Do not dump the database or use an unbounded scan.
4. If sqlmap is unavailable, the request format is unsupported, or the result is ambiguous, perform a bounded manual boolean/error/time-differential check. Change the hypothesis or input between attempts; never repeat the same original arguments.
5. Validate the result independently with a clean request and preserve the request metadata, status/body hashes, latency comparison, sqlmap output, and evidence reference. Stop with an explicit `confirmed`, `rejected`, `entry_unreachable`, or `inconclusive` status.

For a login branch, separate the work into `login-sqli-differential` and `login-sqli-sqlmap` hypotheses so the controller can see whether the failure was caused by an unreachable form, a stable server error, or an input-controlled SQL behavior.

## Avoid

- Do not act outside the authorized competition scope.
- Do not call sqlmap without a concrete parameter or exact reproducible request.
- Do not repeat a failed action with the same original arguments.
- Do not perform unbounded brute force, full-database extraction, or unnecessary data collection.
- Do not treat a stable 500, tool output, or model claim as proof without independent validation.

## Success Criteria

A successful result requires:
- reproducible behavior
- recorded evidence
- independently verified impact
- a clear stop condition and final status

## Detailed Workflow

Read `references/detailed-workflow.md` only after the Skill is selected and the current evidence matches this vulnerability family. For sqlmap-specific flags read `references/SQLMAP_ADVANCED.md`; for login/database-error cases read the relevant section of `references/SCENARIOS.md`. Read only the relevant section and keep the current atomic task, tool budget, evidence target, and stop condition unchanged.
