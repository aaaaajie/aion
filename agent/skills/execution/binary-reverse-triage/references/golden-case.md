# Golden case: Linux ELF triage

Fixture: an assigned ELF is stored in the workspace. The host may be macOS, but
the dynamic runner is available only when the artifact and execution environment
match Linux x86_64.

Expected path:

1. Activate `execution/binary-reverse-triage`.
2. Run `bin_identify`, then `bin_checksec`, `bin_strings`, `bin_symbols`, and a
   bounded `bin_disassemble` selection.
3. Map one input parser to one state-changing or output path with offsets/functions.
4. If the platform does not match, skip process/network sessions and report
   `ENTRY_UNREACHABLE` while retaining static evidence.
5. Finish with one `worker_report` (Worker) or `solver_progress` (Solver) containing artifact hash, architecture,
   protection state, path evidence, and dynamic status.

Acceptance: macOS never starts a Linux dynamic session merely because the file is
executable on the host.
