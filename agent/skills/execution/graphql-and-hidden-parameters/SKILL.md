---
name: graphql-and-hidden-parameters
description: GraphQL and hidden parameter testing playbook. Use when exploring introspection,
  batching, undocumented fields, hidden parameters, schema abuse, and GraphQL authorization
  gaps.
---

# Graphql And Hidden Parameters Skill

## Purpose

GraphQL and hidden parameter testing playbook. Use when exploring introspection, batching, undocumented fields, hidden parameters, schema abuse, and GraphQL authorization gaps.

## When to use

Use when:
- the task mentions `web`
- the task mentions `graphql`
- the task mentions `hidden`
- the task mentions `parameters`
- the task mentions `parameter`

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

# SKILL: GraphQL and Hidden Parameters — Introspection, Batching, and Undocumented Fields

> **AI LOAD INSTRUCTION**: Use this skill when GraphQL exists or when REST documentation suggests optional, deprecated, or undocumented fields. Focus on schema discovery, hidden parameter abuse, and batching as a force multiplier.

## 1. GRAPHQL FIRST PASS

```graphql
query { __typename }
query {
  __schema {
    types { name }
  }
}
```

If introspection is restricted, continue with:

- field suggestions and error-based discovery
- known type probes like `__type(name: "User")`
- JS and mobile bundle route extraction

## 2. HIGH-VALUE GRAPHQL TESTS

| Theme | Example |
|---|---|
| IDOR | `user(id: "victim")` |
| batching | array of login or object fetch operations |
| hidden fields | admin-only fields exposed in type definitions |
| nested authz gaps | related object fields with weaker checks |

## 3. HIDDEN PARAMETER DISCOVERY

Look for:

- fields present in admin docs but not public docs
- `additionalProperties` or permissive schemas
- frontend code using richer request bodies than visible UI controls
- mobile endpoints carrying role, org, feature-flag, or internal filter fields

## 4. NEXT ROUTING

- If hidden fields affect privilege: api authorization and bola
- If GraphQL batching changes auth or rate behavior: `api auth and jwt abuse` (related Skill; use skill_list to locate it)
- If endpoint discovery is incomplete: `api recon and docs` (related Skill; use skill_list to locate it)
