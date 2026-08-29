---
name: competition-evidence-and-metrics
description: >-
  Aggregate existing AION evidence and reports into reproducible competition
  metrics for SRC, binary, internal-network, and AI workflows. Compare fixed
  baselines without starting new probes or changing target state.
---

# Competition evidence and metrics

This is a read-and-aggregate Skill. It must not create new network traffic, rerun
an exploit, or treat missing measurements as zero.

## Workflow

1. Define the denominator: challenge set, labeled vulnerabilities, audited files,
   executed cases, or completed agent tasks.
2. Read only owned reports and evidence references. Preserve run IDs, case IDs,
   artifact hashes, Skill IDs, and timestamps.
3. Normalize candidates into `candidate`, `verified`, `rejected`, and
   `inconclusive`. Deduplicate by the existing finding fingerprint where available.
4. Calculate only reconstructable metrics:
   - discovery rate = verified vulnerabilities / labeled vulnerabilities
   - false-positive rate = rejected candidates / all candidates
   - audit volume = files, functions, and LOC examined
   - high-severity time = first verified high finding time - task start time
   - cost = recorded input/output/reasoning tokens and tool time
   - human ratio = recorded human review time / total wall time
5. For binary work, include crash groups, reproducible crashes, artifact hashes,
   and exploitability status. For AI work, use the case denominators and labels
   from `ai-defense-evaluation`.
6. Compare traditional, AI+tools, and AI+Skills runs only when target set,
   time budget, case set, and baseline definition match.
7. Emit one compact JSON metrics block, a Markdown summary, and a data-quality
   section listing missing or incomparable fields.

## Tool guidance

Use `evidence_read`, `system_read_file`, and `system_shell` only for owned local
aggregation files. Do not use HTTP, network discovery, SSH, binary sessions, or
credential tools from this Skill. Finish with one `execution_report`.

## Required report

Include formulas, numerators, denominators, missing-data policy, run comparison
labels, cost units, human-time source, and evidence references. Clearly separate
measured values from explanatory conclusions.
