# Golden case: bounded challenge routing

Fixture: an authorized challenge provides an ELF artifact and a local service
address, but does not identify whether the question is reverse engineering or
exploitability.

Expected path:

1. Activate `challenge/challenge-threat-modeling`.
2. Record asset, entry point, trust boundary, platform, and the single question:
   “Is the observed input path reachable and security-relevant?”
3. Dispatch `execution/binary-reverse-triage` first; do not dispatch fuzzing and
   exploit development in parallel without evidence.
4. Consume its evidence, then dispatch at most one next branch if its report
   supports it. Finish with one `worker_report` (Worker) or `solver_progress` (Solver) and explicit next state.

Acceptance: the route includes a falsifiable hypothesis, a stop condition, and
does not invent credentials, payloads, or exploitability.
