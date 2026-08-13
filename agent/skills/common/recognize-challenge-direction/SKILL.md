---
name: recognize-challenge-direction
description: Classify a CTF challenge as web, binary, AI, blockchain, or unknown from bounded metadata and, only when needed, one exact-target probe.
metadata:
  version: 1
  directions: [web, binary, ai, blockchain]
  priors:
    web: 0.67
    binary: 0.20
    ai: 0.07
    blockchain: 0.06
  high_confidence: 0.80
  minimum_margin: 0.20
  probe_script: scripts/probe_target.py
---

# Challenge direction recognition

Use this Skill before the first technical plan. Return two independent values:

- `direction`: the primary solving logic: `web`, `binary`, `ai`, `blockchain`, or
  `unknown`.
- `access_surface`: how the target is reached: `http`, `https`, `raw_tcp`,
  `evm_rpc`, `artifact`, or `unknown`.

Do not confuse transport with solving direction. HTTP can carry an AI application
or an EVM RPC endpoint. An `nc` launcher can start a blockchain instance. Port
numbers are weak evidence and never decide the direction alone.

## Challenge workflow

1. Read only the challenge metadata, current state, and this Skill first.
2. Score all four directions using independent signals. Use the competition
   percentages only as soft priors and tie breakers.
3. Select a direction only when there is one strong semantic/protocol signal or
   at least two independent medium signals, the confidence is at least `0.80`,
   and the lead over the next candidate is at least `0.20`.
4. Record the selected direction in the first analysis plan. Keep it `unknown`
   when evidence does not meet the rule.
5. Load exactly one matching reference: `references/web.md`,
   `references/binary.md`, `references/ai.md`, or `references/blockchain.md`.
6. When direction is `unknown`, create at most one bounded `recon` task with
   `hypothesis_key=challenge-direction` and `task_key=direction-probe-1`. Its
   only question must distinguish the leading candidates. Do not turn it into
   port scanning, path scanning, vulnerability testing, or flag hunting.
7. After the report, use a new cycle to update the direction only when the report
   or an observation is new evidence. Direction changes do not count as progress
   and do not reset the stagnation clock.

## Execution probe

Only an Execution Agent may run the bundled script. It must read this Skill first,
write a JSON input file, and run:

```text
$AION_PYTHON $AION_SKILLS_ROOT/common/recognize-challenge-direction/scripts/probe_target.py INPUT.json OUTPUT.json
```

The input and output files must be placed below the `evidence_root` from
`execution_get_assignment` (for example `direction-probe-input.json` and
`direction-probe-output.json`). The input contains exactly one target. The script makes at most three requests,
uses no retries, reads at most 64 KiB per response, and has a short fixed timeout.
It may perform a homepage request, one EVM identity request, and one chain-id
request when the target is an EVM candidate. It must stop after evidence that
answers the assigned discrimination question. Return only compact JSON evidence
and the output path in `execution_report`.

## Signal rules

Strong signals are explicit challenge semantics, a recognized artifact format,
or a protocol response unique to a direction. Medium signals are two related
technical terms or a service family. Generic words such as `login`, `server`,
`API`, `0x`, `nc`, `HTTP`, and `password` are weak and must not decide a result.

Use the direction references for detailed signals and first-round task planning.
