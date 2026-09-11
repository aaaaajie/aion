---
name: recognize-challenge-direction
description: >-
  Planning: classify a whole CTF challenge as web,
  pentest, binary, exploit, cloud, evasion, or unknown, then refine it into SRC,
  internal-network, AI, reverse, or exploitation focus from bounded metadata and,
  only when needed, one exact-target probe. Solver and execute Workers share this planning procedure.
metadata:
  version: 2
  directions: [web, pentest, binary, exploit, cloud, evasion]
  priors:
    web: 0.36
    binary: 0.18
    exploit: 0.18
    pentest: 0.14
    cloud: 0.08
    evasion: 0.06
  high_confidence: 0.80
  minimum_margin: 0.20
  probe_script: scripts/probe_target.py
---

# Challenge direction recognition

Use this Skill before the first technical plan. Return two independent values and
one optional refinement:

- `direction`: the primary solving logic: `web`, `pentest`, `binary`, `exploit`,
  `cloud`, `evasion`, or `unknown`.
- `access_surface`: how the target is reached: `http`, `https`, `raw_tcp`,
  `evm_rpc`, `artifact`, or `unknown`.
- `execution_focus`: one of `src`, `web-vuln`, `internal-network`, `ai`,
  `reverse`, `exploit`, or `unknown`. This is a routing hint, not proof.

Do not confuse transport with solving direction. HTTP can carry an AI application
or an EVM RPC endpoint. An `nc` launcher can start a blockchain instance. Port
numbers are weak evidence and never decide the direction alone.

## Challenge workflow

1. Read only the challenge metadata, current state, and this Skill first.
2. Score all six directions using independent signals. Use the competition
   percentages only as soft priors and tie breakers.
3. Select a direction only when there is one strong semantic/protocol signal or
   at least two independent medium signals, the confidence is at least `0.80`,
   and the lead over the next candidate is at least `0.20`.
4. Record the selected direction in the task reasoning and evidence. Keep it
   `unknown` when evidence does not meet the rule.
5. Set `execution_focus` only when at least one independent signal supports it:
   source code or repository evidence implies `src`; reachable internal services
   imply `internal-network`; model/tool/RAG behavior implies `ai`; an ELF or
   protocol artifact implies `reverse` or `exploit`.
6. Load exactly one matching reference: `references/web.md`,
   `references/pentest.md`, `references/binary.md`, `references/exploit.md`,
   `references/cloud.md`, or `references/evasion.md`.
7. When direction is unknown, the same Solver or execute Worker may run one bounded probe that distinguishes the leading candidates. Delegate only an independent task with an explicit task_key when useful. No stage transition requires a new Agent.
8. Refine the direction only when new evidence supports the change.

## Execution probe

A Solver or execute Worker may run the bundled script. It must read this Skill first,
write a JSON input file, and run:

```text
$AION_PYTHON $AION_SKILLS_ROOT/common/recognize-challenge-direction/scripts/probe_target.py INPUT.json OUTPUT.json
```

The Assignment is already present in the first model request. Place input and output
files inside its authorized workspace scope; successful file and Shell tools return
immutable `evidence:evidence_*` references. The input contains exactly one target. The script makes at most three requests,
uses no retries, reads at most 64 KiB per response, and has a short fixed timeout.
It may perform a homepage request, one EVM identity request, and one chain-id
request when the target is an EVM candidate, and one bounded raw-TCP banner read.
It must stop after evidence that
answers the assigned discrimination question. Return only compact JSON evidence
and the relevant Evidence references in `worker_report` (Worker) or `solver_progress` (Solver).

## Signal rules

Strong signals are explicit challenge semantics, a recognized artifact format,
or a protocol response unique to a direction. Medium signals are two related
technical terms or a service family. Generic words such as `login`, `server`,
`API`, `0x`, `nc`, `HTTP`, and `password` are weak and must not decide a result.

Use the direction references for detailed signals and first-round task planning.
