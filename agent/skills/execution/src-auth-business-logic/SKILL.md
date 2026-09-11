---
name: src-auth-business-logic
description: >-
  Analyze authorized application authentication, authorization, object scope, and
  multi-step business workflows. Build role/state matrices and verify only concrete
  access-control or state-transition hypotheses with controlled request pairs.
---

# SRC authentication and business logic

Model the expected state transition before testing an altered transition. A changed
status code, response length, or client-side flag is only a lead until the server-side
authorization or business effect is demonstrated.

## Workflow

1. Record actors, roles, session material, object identifiers, and the normal workflow.
2. Build a matrix of actor → action → object → expected authorization → observed result.
3. Resolve action URLs and object references from current responses or authorized source. Distinguish an object ID, display filename and storage path. If comments, source and observed behavior conflict, record each source and test the smallest discriminating case; do not invent a hidden endpoint.
4. Trace server-side checks for ownership, role, tenant, state, amount, count, and
   replay protection. Treat client-side checks as untrusted hints.
5. Choose one differential hypothesis: role substitution, object substitution,
   state skip, parameter omission/addition, replay, or concurrent transition.
6. Capture a normal control interaction first. Change one variable at a time and
   preserve the same authentication context where the hypothesis requires it.
7. Use the existing HTTP session/request/output tools to compare status, body,
   side effects, and subsequent reads. Do not repeat identical requests.
8. Verify the impact on the intended object or workflow state, then deduplicate
   against existing findings.

Before interpreting a negative result, verify that the normal control still works and the session has not expired. An unread, timed-out or unexecuted request is inconclusive. Repeated scans without a new source-backed candidate do not resolve a workflow contradiction.

## Required evidence

Report the role/state matrix, request sequence, changed field, control/result
difference, affected object, reproducible verification steps, and false-positive
exclusion. A candidate remains `inconclusive` when the response differs but no
server-side effect or protected-object change is demonstrated.

## Tool guidance

Use `system_read_file` and `system_shell` for source evidence, then
`system_http_request`, `system_http_analyze`, `system_http_output`, and
`system_http_response` for controlled verification. Use `worker_report` (Worker) or `solver_progress` (Solver) once
with the complete evidence references.

## Stop conditions

Stop when the actor is not authorized, the control is missing, the object is not
owned by the assignment, the state change cannot be observed, or a second request
would only repeat an exhausted hypothesis. Never infer an authorization bypass
from a client-side response alone.
