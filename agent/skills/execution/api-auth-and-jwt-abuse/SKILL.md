---
name: api-auth-and-jwt-abuse
description: >-
  认证授权依赖、迁移文档与实际行为冲突、令牌声明与服务端验证、运行时入口前提。
  Validate observed JWT/token and authorization boundaries when migration notes,
  claims and server behavior conflict, or an assumed identity/role prerequisite
  blocks an authorized business or runtime workflow.
---

# Authentication and runtime dependencies

Build a small dependency map from current observations. Identity, authorization,
business actions and runtime capabilities are separate questions; connect them
only where a source relationship or controlled request shows a prerequisite.
Do not make privilege escalation a required step for an independently reachable
runtime entrypoint without evidence of that dependency.

## Establish the normal control

Read the actual login response, credential transport and a subsequent authenticated
request. A decoded claim, Cookie or client-visible role does not prove server trust.
Record identity, expiry and session generation. Revalidate the affected control
after a pause, identity change or target change before reusing dependent conclusions.

Migration notes and configuration describe candidate implementations. Record their
source separately from observed validation behavior. Inspect fields actually present
and locations exposed by this challenge; do not invent required routes or keys.
A rejected request or one timing check cannot exclude all database or token behavior.

## Test a specific boundary

State input, validator, expected permission and observable business effect. Compare
a normal control and a request changing one relevant variable. Preserve initial
responses and later business results separately from failed page rendering.
A rejection constrains only that input, client, identity and environment.

Authentication does not prove authorization, and accepted/stored configuration does
not prove runtime evaluation. Use returned object IDs and a valid session for stages
that need them. Verify other entrypoints on their own evidenced prerequisites.
If a prerequisite fails, mark subsequent untested stages inconclusive. Revisit a
branch only when evidence supports a distinguishing test; switching tools, replaying
token variants or expanding dictionaries alone does not create a new hypothesis.

## Tools and completion

Use pentest_jwt for local token inspection and bounded checks only when relevant.
A locally generated or decoded token is not proof of server acceptance. Its validate
operation requires an assigned target and an evidenced token injection location.
Retrieve schemas as needed; use existing HTTP request/output/analysis tools and exact
returned read handles. No queued, timed-out, expired-session or unread operation
supports a negative conclusion.

Stop when the specific boundary is answered or its prerequisite is unavailable.
Report verified stages and dependencies, conflicting sources, control/result refs,
conclusion scope and the smallest remaining test. Keep raw credentials in evidence,
not summaries. Use solver_progress or worker_report according to your role.
