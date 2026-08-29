---
name: binary-fuzz-crash
description: >-
  Run bounded authorized input-variation and crash-triage work against a supported
  Linux binary or protocol target. Curate seeds, enforce limits, minimize and
  reproduce crashes, collect debugger evidence, and state clearly when coverage-
  guided fuzzing dependencies are unavailable.
---

# Binary fuzz and crash triage

This Skill does not claim coverage-guided fuzzing unless the required engine,
instrumentation, and coverage evidence are actually available. A bounded black-box
input loop is a limited test, not a full fuzz campaign.

## Workflow

1. Confirm Linux, architecture, target ownership, input format, reset method, and
   a finite time/iteration/output budget.
2. Establish one valid seed and one invalid control. Record the parser boundary,
   expected exit behavior, and any available sanitizer or coverage signal.
3. Generate small, deterministic mutations that change one structural feature at
   a time. Preserve the seed and mutation parameters with every result.
4. Use an available bounded process or protocol session. Enforce timeout,
   maximum input size, maximum cases, and output caps. Never leave workers running.
5. Group crashes by stable signature: signal/exit class, instruction location,
   top stack frames, sanitizer category, and normalized input digest.
6. Minimize one representative input per group and reproduce it from a clean
   target state. Use `bin_debug` only for a focused root-cause question.
7. Classify the result as reproducible crash, suspected memory-safety issue,
   non-security failure, duplicate, or inconclusive.

## Dependency gate

Before describing the work as automated fuzzing, verify that the assignment has a
usable fuzz engine or harness, a resettable target, and a coverage/crash oracle. If
any are missing, report:

- executed case count and input bounds
- available oracle and missing dependency
- crash groups and reproducibility
- current verification level: limited input testing or crash triage

Do not install packages, fetch a fuzzer, or invent coverage numbers.

## Tool guidance

Use `system_shell` only for bounded local scripts or supplied harnesses. Use
`pwn_process_open`/`pwn_session_io` for an assigned Linux process or protocol when
appropriate, `bin_debug` for focused analysis, and `pwn_session_close` for cleanup.
Finish with one `execution_report` containing the complete evidence references.

## Stop conditions

Stop on platform mismatch, missing reset, repeated identical input, target hang,
resource limit, out-of-scope network behavior, or a crash that cannot be reproduced.
