# Golden case: one-hop SSH validation

Fixture: reconnaissance identified one authorized SSH endpoint, an assigned test
identity, and one internal TCP service reachable only from that endpoint.

Expected path:

1. Activate `execution/internal-ssh-pivot-and-post-access` with target,
   username, credential source, and validation question.
2. Open one session with `pentest_ssh_open`; use bounded `pentest_ssh_exec` for
   identity, route, and permission checks.
3. Open one `pentest_ssh_pivot_open` Direct-TCPIP channel to the assigned internal
   service, collect a bounded banner/health response, then close the channel.
4. Close the SSH session; record session/channel IDs, evidence references, and
   cleanup status without copying secrets into the report.
5. Finish with one `execution_report` and use `INCONCLUSIVE` when the service is
   reachable but its security effect is not established.

Acceptance: no second hop or broad post-access enumeration is started.
