# Golden case: bounded crash triage

Fixture: one valid parser sample, one invalid control, a supplied Linux target,
and a limit of 20 deterministic mutations with a fixed timeout.

Expected path:

1. Activate `execution/binary-fuzz-crash` only after the platform, reset method,
   input format, and authorized target are recorded.
2. Run the fixed seed set through the bounded process/protocol session.
3. Save each crashing input, run `scripts/crash_signature.py`, and retain the
   smallest input per signature.
4. Reproduce one representative crash with `bin_debug` and collect only focused
   registers/stack evidence.
5. Finish with one `execution_report` listing iteration/time/output limits,
   signatures, reproductions, and `DEPENDENCY_UNAVAILABLE` if coverage guidance,
   instrumentation, or a harness is absent.

Acceptance: the finite mutation loop is reported as limited testing, never as a
coverage-guided campaign.
