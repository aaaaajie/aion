---
name: src-audit-workflow
description: >-
  局部源码审计、文件读取后沿入口引用配置与路径拼接收敛、部分文件覆盖范围。
  Trace authorized full or partial application source, including files obtained
  one at a time through a verified file-read capability. Follow entrypoints,
  imports, configuration and path construction to a reachable goal-related flow.
---

# Source audit from available evidence

Source suggests hypotheses; a finding needs reachable input, guards, operation and
observable result. A complete repository is useful but is not a prerequisite.

## Start with the source actually available

For a local repository or extracted bundle, make a bounded inventory of languages,
manifests and entrypoints. For remotely obtained fragments, record the original
read request, source identity/path if known, local artifact and actual read ranges.
Do not invent a repository fingerprint or claim complete coverage for partial files.
A missing include or an unread range remains unknown, not absent from the application.

## Follow one evidence-supported chain

1. Find the observed route/handler and its input, session and object prerequisites.
2. Follow concrete references/imports into configuration and the relevant operation.
   Read only the next referenced file or missing range needed to resolve a question.
3. For file operations, trace configured base, path joins and the referenced data.
   Distinguish object IDs, display names and filesystem paths. Mark inferred paths
   as candidates until a read/control or source relationship verifies them.
4. Connect source, guard and sink to a reachable request and goal. Compare a direct
   check enabled by verified file reading with continuing the current business chain.
   Do not keep enumerating guessed endpoints because a comment mentions approval.
5. Validate one high-signal candidate using the existing authorized tools, a known
   control and a minimal request. Inspect returned output before updating conclusions.

Contradictory source, documents and current behavior retain separate source refs.
Do not assume partial source is deployed unchanged. A dangerous function in dead
code is not a reachable finding; absence from one fragment excludes no other file.

## Tool guidance and stopping

Use system_glob, system_read_file and system_shell for bounded local inspection;
use the existing verified file-read request for referenced remote files. Use HTTP
request/output/analysis tools with returned handles rather than replaying traffic to
read results. Search tool schemas when needed, not new clients or broad scanners.

Stop a branch when its specific path is demonstrably unreachable, its guard is
verified, the goal is verified, or a needed source/control is unavailable. The last
case is inconclusive. Revisit only for missing coverage, changed conditions or new
evidence; changing tools or growing dictionaries alone is not new information.

Report available-source identity and scope, examined paths/ranges, the source-to-
operation chain, facts versus inferred locations, control/result refs, bounded
conclusion and next uncertainty. Use solver_progress or worker_report for your role.

## 离线源码定位

获取源码后，搜索 system_source_scan 并读取 schema，对工作区源码目录运行离线扫描。通过 system_task_output 读取审计线索与 JSON 产物；再沿输入、校验、调用点和权限检查阅读源码。命中不是已证实漏洞，无命中也不是安全证明。不对整套依赖反复扫描，不把规则当成完整调用链分析器。
