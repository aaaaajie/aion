---
name: agent-harness-construction
description: Design and optimize AI agent action spaces, tool definitions, and observation
  formatting for higher completion rates.
---

# Agent Harness Construction Skill

## Purpose

Design and optimize AI agent action spaces, tool definitions, and observation formatting for higher completion rates.

## When to use

Use when:
- the task mentions `agent`
- the task mentions `harness`
- the task mentions `construction`
- the task mentions `design`
- the task mentions `optimize`

## Strategy

1. Inspect.
2. Plan.
3. Execute.
4. Verify.

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

# Agent Harness Construction

Use this skill when you are improving how an agent plans, calls tools, recovers from errors, and converges on completion.

## Core Model

Agent output quality is constrained by:
1. Action space quality
2. Observation quality
3. Recovery quality
4. Context budget quality

## Action Space Design

1. Use stable, explicit tool names.
2. Keep inputs schema-first and narrow.
3. Return deterministic output shapes.
4. Avoid catch-all tools unless isolation is impossible.

## Granularity Rules

- Use micro-tools for high-risk operations (deploy, migration, permissions).
- Use medium tools for common edit/read/search loops.
- Use macro-tools only when round-trip overhead is the dominant cost.

## Observation Design

Every tool response should include:
- `status`: success|warning|error
- `summary`: one-line result
- `next_actions`: actionable follow-ups
- `artifacts`: file paths / IDs

## Error Recovery Contract

For every error path, include:
- root cause hint
- safe retry instruction
- explicit stop condition

## Context Budgeting

1. Keep system prompt minimal and invariant.
2. Move large guidance into skills loaded on demand.
3. Prefer references to files over inlining long documents.
4. Compact at phase boundaries, not arbitrary token thresholds.

## Architecture Pattern Guidance

- ReAct: best for exploratory tasks with uncertain path.
- Function-calling: best for structured deterministic flows.
- Hybrid (recommended): ReAct planning + typed tool execution.

## Benchmarking

Track:
- completion rate
- retries per task
- pass@1 and pass@3
- cost per successful task

## Anti-Patterns

- Too many tools with overlapping semantics.
- Opaque tool output with no recovery hints.
- Error-only output without next steps.
- Context overloading with irrelevant references.
