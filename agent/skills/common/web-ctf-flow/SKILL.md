---
name: web-ctf-flow
description: >-
  页面错误与业务结果分离、认证会话失效、重定向与 Cookie 对照、扫描会话隔离。
  Diagnose authorized Web CTF stateful workflows when page errors, redirects,
  cookies and business results disagree, or scanning invalidates a session.
  Establish controls and the shortest goal check without broad route guessing.
---

# Web state and layered diagnosis

Use current-challenge evidence to connect prerequisites, requests, returned state
and the goal. A page comment is a lead; it does not prove a hidden route exists.

## Establish a small state map

Record known endpoints, method/body schema, identity, CSRF, returned object IDs
and the observed success condition. Use actual returned IDs and links. Distinguish
request parsing, authentication, database/result handling, template rendering and
subsequent business actions; failure in one layer does not establish failure in all.
Do not require a linear business chain unless its dependencies are evidenced.

## Compare controls and layers

- Preserve the initial response before redirects and the final response separately.
  Compare status, Location, Cookie changes and the subsequent business result.
  A Cookie alone does not prove authentication; use it on a known identity or
  read-only business control distinct from the failed rendered page. Do this before
  requiring that page to recover. If no such control is known, locate one from
  observed links or source; do not invent an endpoint.
- For a persistent 5xx, change one relevant variable with a normal/invalid request
  pair and inspect the affected layer. A failed page can coexist with changed state.
  Repeated refreshes or larger route lists do not identify the failing layer.
- A 401/403 may reflect identity, authorization or a gateway; a 404 may reflect the
  route or object. Compare a known control before interpreting an unknown request.
- With an expired session, invalid request or unread output, mark the experiment
  inconclusive. A negative conclusion covers only the input and conditions tested.
- When a new capability is verified, compare a direct goal-related read/check with
  continuing the current business chain. A guessed data location is not a fact.
  If the next uncertainty is where flag content could reside, search for
  `ctf-flag-locator` to prioritize candidate carriers using current evidence.

## Keep scans from changing the control

Keep dependent business steps on the same verified session. Give reconnaissance
its own client/session and Cookie storage; parallel scans must not share a writable
Cookie jar. Exclude known logout, delete and other state-changing routes from
indiscriminate probing. Calibrate a known authenticated request before and after
scan batches. If it stops working, suspend dependent conclusions and revalidate the
session before continuing; do not interpret the batch as missing routes or denied roles.

## Choose and stop a branch

Use existing HTTP request/output/analysis tools and returned read handles; do not
repeat requests merely to inspect results. For uncertain input-to-database behavior,
search the SQLi Skill; for partial source, search the source audit workflow. Load
neither solely because a form exists. For actual delayed template rendering, read
`references/ssti-dialects.md` and validate the rendering route, same session and
returned object ID before interpreting a harmless canary.

After two valid tests of one hypothesis add no information, recheck prerequisites
and choose a distinguishing condition. Changing tools or scale does not reset the
hypothesis. Stop a branch when the goal is verified, evidence excludes the specific
condition, or a required prerequisite is unavailable; record the last case as blocked
or inconclusive, not rejected.

Report the minimum request order, prerequisites, returned references, control and
result evidence, conclusion scope and next uncertainty using solver_progress or
worker_report as appropriate. Keep raw credentials and response bodies in evidence,
not ordinary summaries. Only Solver handles candidate submission.

## 请求证据与工具

先用 skill_search / tool_search 发现已有能力，再获取准确 schema。登录或动态页面难以建立正常请求时使用 system_browser_open/action，捕获后用 system_browser_export_request 转交 system_http_request。已有正常请求用 system_http_replay 单字段替换；用 system_http_compare 比较已有对照响应，不为分析重复发请求。页面 500 不等于认证失败，统一 403 必须与随机不存在路径对照。网络结论必须注明执行来源、地址与实际失败阶段；未知阶段保留未知。浏览器凭据可能过期，不完整上传不能重放。

## POC 检索与验证

对已知产品、CVE 或页面特征，先调用 `system_poc_search`；不要从文件路径猜规则。对返回的 `poc_ref` 调用 `system_poc_inspect`，确认来源、请求、判断条件、支持状态和阻塞原因。`reference_only` 的 Yak/Yakit 记录只用于原文和依赖线索，不能执行。

仅当状态为 `supported` 且目标 origin 明确时调用一次 `system_poc_run`。它会复用当前 Run/Agent 的 HTTP 资源和可指定会话；返回 interaction 后只用 `system_poc_output` 等待或读取，不重复提交。输出中的 `matched` 只表示模板条件满足，`not_matched` 只覆盖这次请求，正文缺失/截断、传输失败或无法确定时为 `inconclusive`。解释时引用 interaction/request 证据、执行来源、地址、状态码、Location、Cookie 和正文完整性；500 页面可与认证成立同时存在，统一 403 必须先做随机路径对照。
