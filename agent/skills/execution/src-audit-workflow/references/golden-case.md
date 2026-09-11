# Golden case: source-backed candidate

Fixture: a small authorized repository contains one route handler, one input
parameter, and a server-side sink. The runtime is available at a known local URL.

Expected path:

1. Activate `execution/src-audit-workflow`.
2. Run `scripts/inventory.py` with a fixed file/byte bound and retain its JSON.
3. Read only the route, guard, source, sink, and relevant dependency lines.
4. Use `system_http_request` for one control request and one one-variable
   validation request; use `system_http_analyze`/`system_http_output` as needed.
5. Report file, line, function, request, response difference, and evidence hash
   in one `worker_report` (Worker) or `solver_progress` (Solver); label the candidate `verified` or `inconclusive`.

Acceptance: a static pattern without a connected source-to-sink path is not a
finding, and the report includes the exact bounded inventory and request evidence.
