---
name: challenge-threat-modeling
description: >-
  Use at the Challenge controller for the first technical dispatch: build a bounded
  challenge threat model, select the smallest matching execution workflow, and
  dispatch only evidence-backed hypotheses for SRC, web, binary, exploit,
  internal-network, cloud, or AI targets.
metadata:
  version: 3
  domains: [src, web, binary, exploit, internal-network, cloud, ai]
---

# Challenge threat modeling

Keep the model small, falsifiable, and tied to the assigned challenge. Separate
the primary solving direction from the access surface: HTTP may carry a web, AI,
or cloud challenge; raw TCP may carry a binary or protocol challenge.

## Workflow

1. Read challenge metadata, current state, existing findings, and evidence only.
2. Classify the primary direction using independent signals. Treat generic words
   such as `login`, `server`, `API`, `HTTP`, and `password` as weak evidence.
3. Record the asset, entry point, trust boundary, likely impact, and one testable
   hypothesis. Use `unknown` when confidence is insufficient.
4. Choose the smallest execution Skill whose procedure matches the hypothesis.
   Include a second Skill only when the first result creates a concrete dependent
   branch.
5. Dispatch a task with one question, an evidence target, a time/tool budget,
   and an explicit stop condition.
6. Consume the execution report. Mark the hypothesis supported, rejected, or
   inconclusive; update the model only when new evidence changes it.

## Domain routing

- SRC: use `execution/src-audit-workflow` for source inventory and code evidence;
  use `execution/src-auth-business-logic` for roles, workflows, and object scope.
- Binary: use `execution/binary-reverse-triage` before any dynamic session;
  use `execution/binary-fuzz-crash` for bounded crash work;
  use `execution/binary-exploit-and-variant-analysis` only after a supported
  vulnerability hypothesis exists.
- Internal network: use `execution/internal-network-recon` before service or
  SSH work; use `execution/internal-ssh-pivot-and-post-access` only for an
  authorized, reachable session.
- AI: use `execution/ai-agent-security-testing` for a concrete model/tool trust
  boundary and `execution/ai-defense-evaluation` for repeatable scoring.
- Evidence and comparison: use `execution/competition-evidence-and-metrics`
  after useful evidence exists; it must not start new probes.

## Hypothesis record

Every candidate must contain:

- `attack_surface`: URL, port, function, file, or interaction boundary
- `vulnerability_class`: the narrowest supported class
- `priority`: critical/high/medium/low; do not mark unverified candidates critical
- `confidence`: suspected, supported, or confirmed
- `verification_status`: pending, in_progress, verified, rejected, or inconclusive
- `evidence_refs`: complete references returned by tools
- `stop_condition`: the exact condition that ends the branch

Do not dispatch a payload-only task, repeat the same arguments after a negative
result, or treat a model explanation as evidence. If a dependency is unavailable,
dispatch no substitute fiction; report the missing dependency and keep the branch
inconclusive.

## Final handoff

The Challenge Agent should dispatch concrete work and consume reports. It should
not invent flags, credentials, URLs, source locations, or exploitability claims.
Use the existing challenge report and state-update tools to preserve the finding
status and evidence references.
