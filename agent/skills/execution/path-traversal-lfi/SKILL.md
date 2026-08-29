---
name: path-traversal-lfi
description: Path traversal and LFI playbook. Use when file paths, download endpoints, filename parameters, include operations, archive extraction, or wrapper behavior may expose filesystem control. 适用于下载接口、文件名参数、路径穿越、任意文件读取。
---

# Path Traversal Lfi Skill

## Purpose

Path traversal and LFI playbook. Use when file paths, download endpoints, include operations, archive extraction, or wrapper behavior may expose filesystem control.

## When to use

Use when:
- the task mentions `web`
- the task mentions `path`
- the task mentions `traversal`
- the task mentions `lfi`
- the task mentions `download endpoint`, `filename`, `file path`, `下载接口`, `文件名`, `文件路径`, `路径穿越`, or `任意文件读取`
- the task mentions `playbook.`

## Fast flag-oriented strategy

1. Detect the smallest file-reading parameter and establish one normal-file baseline.
2. Confirm traversal with one relative probe such as `../../../../etc/passwd`; do not use an absolute-path read when the challenge forbids it.
3. If evidence identifies the application directory and a mounted secret path, calculate the relative path from the application directory to that secret. For an app reading from `/app/docs` and a secret mounted at `/run/secrets/<code>`, the bounded candidate is `../../../../run/secrets/<code>`.
4. Make one exact HTTP read of that candidate, fetch the response body, and place only the exact `flag{...}` token in `candidate_flag`.
5. Stop after the exact token is verified; report the decisive request and Evidence refs.

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
- an exact candidate Flag when the task is flag extraction
- a clear stop condition and final status

## Detailed Workflow

Read `references/detailed-workflow.md` only after the Skill is selected and the current evidence matches this vulnerability family. Read only the relevant section; keep the current atomic task, tool budget, evidence target, and stop condition unchanged.
