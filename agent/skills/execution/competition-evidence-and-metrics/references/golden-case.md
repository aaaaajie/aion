# Golden case: competition metric aggregation

Fixture: existing execution reports contain four candidate findings, two verified,
one rejected, one inconclusive, audit-volume counters, timestamps, token/tool
usage, and a baseline label. No target access is available to this Skill.

Expected path:

1. Activate `execution/competition-evidence-and-metrics` after locating only owned
   reports, evidence references, and run records.
2. Normalize status, severity, finding fingerprint, audit volume, elapsed time,
   cost, and human-review intervals.
3. Run `scripts/aggregate_metrics.py` and combine its JSON with reconstructable
   SRC, binary, internal-network, and AI fields.
4. Compare baseline, AI-only, and AI+Skills rows only where denominators match;
   leave unavailable values explicitly missing.
5. Finish with one `worker_report` (Worker) or `solver_progress` (Solver) containing summary/detail JSON and source
   report IDs. Do not create network traffic or rerun a validation.

Acceptance: a missing label or denominator yields `inconclusive`, not a fabricated
zero or a new attack attempt.
