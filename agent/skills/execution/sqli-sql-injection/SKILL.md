---
name: sqli-sql-injection
description: >-
  SQL 注入假设验证、稳定页面错误、请求有效性、阴性结论边界、换工具仍属同一假设。
  Evaluate a concrete SQL-input hypothesis in authorized login, search, filter or
  report requests; distinguish database behavior from stable page errors and
  bound negative results to valid controls and tested inputs.
when_to_use: Use for a concrete SQL hypothesis, database error or reproducible input/timing differential; a stable login 5xx calls for request/layer validation before SQL-specific detection. Not generic reconnaissance.
---

# Bounded SQL-input validation

## Verify the request before the mechanism

Record endpoint, method, parameter, body encoding, headers, identity/CSRF and a
normal control with status, response structure and latency. Verify that the input
reaches the intended handler. Missing prerequisites, an expired session, unread
output or an unvalidated client make the experiment inconclusive.

Separate initial response, redirect, Cookie changes and the later authenticated
business control from page rendering. A stable 500 proves neither SQL execution
nor its absence. A Cookie or redirect alone is not proof of a valid identity.

## Select a distinguishing check

State the specific input-to-query hypothesis and expected observable difference.
Use a bounded controlled pair supported by current evidence; keep other conditions
fixed. A single expression with no delay/difference constrains only that expression
under those conditions, not all SQL mechanisms or every request reaching a database.
Timing interpretation requires a stable normal control, not an isolated duration.

Use manual checks or `pentest_sqlmap` when they can answer this question. sqlmap
is optional, requires the exact reproducible request and bounded scope/budget,
and is not automatically warranted by a form or a constant error. Search its schema
before use. Read output and verify any claimed result with an independent control.
Do not perform full-database extraction as part of detection.

Keep the same hypothesis_id when switching between manual checks and sqlmap for
the same mechanism. Tool choice is not a new hypothesis. After two valid tests add
no information, reassess request validity and the premise; further tests require
new evidence or a condition that can distinguish the remaining possibilities.

## Report and stop

Preserve input, endpoint, client, identity, environment, control/result evidence and
what remains untested. Report confirmed, rejected for the specific tested condition,
or inconclusive with missing prerequisites. Stop when the question is answered or
no distinguishing test is supported; do not turn tool failure into target rejection.

Read `references/detailed-workflow.md` for a matching mechanism, and
`references/SQLMAP_ADVANCED.md` only when sqlmap-specific options are needed.
Use the relevant section of `references/SCENARIOS.md` for request context;
these references do not override the validity and stop conditions above.
