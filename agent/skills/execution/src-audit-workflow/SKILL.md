---
name: src-audit-workflow
description: >-
  Audit an authorized source repository or extracted application bundle by building
  a bounded inventory, locating routes and trust boundaries, ranking source-level
  vulnerability hypotheses, and validating only high-signal candidates with the
  existing HTTP and evidence tools.
---

# SRC audit workflow

Treat source analysis as hypothesis generation. A code pattern is not a finding
until the relevant input path, guard, sink, and observable impact are connected.

## Preconditions

- Confirm the repository or extracted bundle is inside the assigned workspace.
- Record a bounded file inventory before opening large files.
- Identify languages, frameworks, build files, routes, API clients, and test data.
- Read only files needed for the current hypothesis; use paging for large results.

## Workflow

1. Inventory files, line counts, languages, dependency manifests, and entry points.
2. Extract routes, handlers, controllers, API paths, client-side endpoints, and
   authentication middleware.
3. Search for input sources, authorization checks, dangerous sinks, deserializers,
   file operations, process execution, redirects, and database queries.
4. Build a small candidate table with source location, source, sink, missing guard,
   reachable path, likely impact, confidence, and required validation.
5. Prioritize candidates that have a concrete caller, a reachable sink, and an
   observable effect. Do not report a dangerous function in dead code alone.
6. For one high-signal candidate, use the existing HTTP tools to send the minimum
   authorized verification request. Poll existing interaction IDs; never replay
   traffic merely to inspect output.
7. Compare the verification result with a control request or normal workflow,
   preserve complete evidence references, and mark the candidate verified,
   rejected, or inconclusive.

## Tool guidance

Use `system_glob`, `system_read_file`, and `system_shell` for bounded local
inventory and search. Use `system_http_request` for one known request,
`system_http_analyze` and `system_http_output` for existing interactions, and
`execution_report` for the final evidence-backed result. Use `pentest_sqlmap` or
`pentest_dir_fuzz` only when the assignment supplies a precise target and the
source evidence justifies the check.

## Stop conditions

Stop a branch when the path is unreachable, a guard is confirmed effective, the
same request shape has already been tested, the target is outside scope, or the
required source/tool dependency is unavailable. Report the missing dependency;
do not replace a static observation with an invented exploit result.

## Required report

Include:

- repository fingerprint and bounded audit scope
- files, lines, functions, routes, or endpoints examined
- hypothesis and source-to-sink reasoning
- control and verification request references, when used
- status: `supported`, `rejected`, or `inconclusive`
- exact evidence references and a next step only when new evidence is required
