---
name: api-recon-and-docs
description: API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, and surface area for API testing.
---

# Api Recon And Docs Skill

## Purpose

API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, and surface area for API testing.

## When to use

Use when:
- the task mentions `web`
- the task mentions `api`
- the task mentions `recon`
- the task mentions `docs`
- the task mentions `reconnaissance`

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

# SKILL: API Recon and Docs — Endpoints, Schemas, and Version Surface

> **AI LOAD INSTRUCTION**: Use this skill first when the target is a REST, mobile, or GraphQL API and you need to enumerate endpoints, documentation, versions, and hidden surface area before exploitation.

## 1. PRIMARY GOALS

1. Discover all reachable API entrypoints.
2. Extract schemas, optional fields, and role differences.
3. Identify old versions, mobile paths, GraphQL endpoints, and undocumented parameters.

## 2. RECON CHECKLIST

### JavaScript and client mining

```bash
curl https://target/app.js | grep -oE '(/api|/rest|/graphql)[^"'\'' ]+' | sort -u
```

### Common documentation and schema paths

```text
/swagger.json
/openapi.json
/api-docs
/docs
/.well-known/
/graphql
/gql
```

### Version and product drift

```text
/api/v1/
/api/v2/
/api/mobile/v1/
/legacy/
```

## 3. WHAT TO EXTRACT FROM DOCS

- optional and undocumented fields
- admin-only request examples
- deprecated endpoints that may still be active
- schema hints like `additionalProperties: true`
- parameter names tied to filtering, sorting, IDs, roles, or tenancy

## 4. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| object IDs everywhere | api authorization and bola |
| JWT, OAuth, role claims | `api auth and jwt abuse` (related Skill; use `skill_list` to locate it) |
| GraphQL or hidden fields | `graphql and hidden parameters` (related Skill; use `skill_list` to locate it) |
| strong auth boundary but suspicious business flow | `business logic vulnerabilities` (related Skill; use `skill_list` to locate it) |
