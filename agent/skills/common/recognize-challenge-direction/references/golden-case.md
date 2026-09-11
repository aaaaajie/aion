# Golden case: direction and focus routing

Fixture: challenge metadata says `binary`, supplies one ELF path, and asks for a
bounded reverse/validation pass. No network target is present.

Expected path:

1. Activate `common/recognize-challenge-direction` from the Challenge controller.
2. Return `direction=binary`, `access_surface=artifact`, and
   `execution_focus=reverse`; do not activate a web or network Skill.
3. Dispatch `execution/binary-reverse-triage` with the artifact path and one
   verification question.
4. Preserve the dispatch decision and the artifact hash as evidence, then finish
   with one `worker_report` (Worker) or `solver_progress` (Solver) containing `status=completed` or a precise
   `ENTRY_UNREACHABLE`/`INCONCLUSIVE` status.

Acceptance: direction is supported by at least two independent metadata signals,
the execution Skill is explicit, and no technical tool is called by this routing
Skill itself.
