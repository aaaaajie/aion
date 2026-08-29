---
name: internal-network-recon
description: >-
  Perform bounded authorized internal-network discovery, service identification,
  and evidence collection. Confirm scope and reachability, poll owned discovery
  tasks, and select the smallest next validation branch without broad scanning.
---

# Internal network reconnaissance

Start with scope and an explicit hypothesis. Discovery results are inventory, not
proof of a vulnerability or authorization to access every host.

## Workflow

1. Record authorized CIDRs/hosts, ports, rate limits, and the question to answer.
2. Create one bounded `system_network_discovery` task and retain its task ID.
3. Poll with `system_network_output`; never replay the scan to check progress.
4. Normalize live hosts, ports, banners, protocols, confidence, and ownership.
5. Use `pentest_service_probe` only to clarify a specific service or banner.
6. Map each service to one next hypothesis: authentication, protocol behavior,
   SSH access, internal web, or binary service. Do not start all branches at once.
7. Stop when the hypothesis is answered, the target is outside scope, or the
   result cannot support a narrower validation task.

## Required evidence

Include scope, task ID, timestamps, hosts/ports examined, open-service inventory,
probe limitations, and evidence references. Distinguish `open`, `reachable`,
`authenticated`, and `vulnerable`; they are not interchangeable.

## Tool guidance

Use `system_network_discovery`, `system_network_output`, and
`pentest_service_probe`. Preserve the returned IDs and finish with exactly one
`execution_report`.
