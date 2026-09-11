---
name: internal-network-recon
description: >-
  网络可达性、启动连接失败、客户端差异复验、服务识别、传输协议与应用结果分层。
  Calibrate authorized host/service reachability when clients disagree or a startup
  connection fails, then identify only evidenced services. Separate transport,
  protocol parsing and application results before drawing negative conclusions.
---

# Reachability before service discovery

Record authorized hosts/ranges, evidence for candidate services and the question to
answer. Existing reachability or service evidence may suffice; do not start a scan
when a known endpoint and a small control can resolve the uncertainty.

## Calibrate comparable conditions

A connection failure describes one attempt at a particular time, from a particular
client to a particular target. If a later HTTP request succeeds, do not preserve the
old failure as a permanent Shell network restriction. Recheck the affected client
against the same known-ready endpoint with comparable method, identity and network
conditions. HTTP success alone does not establish another port is open.

If controls still disagree, record client/proxy/encoding differences and the missing
premise; do not expand discovery to compensate for an unvalidated client. Recalibrate
only conclusions affected by readiness, client, identity or environment changes.

## Choose the smallest next operation

Use system_network_discovery only when existing evidence leaves a bounded inventory
question. Retain its task ID and read system_network_output; do not relaunch to poll.
Use pentest_service_probe to clarify a specific service. Read errors and output before
classifying hosts/ports, recording examined scope and limitations.

Distinguish open/reachable, identified protocol, authenticated and verified application
behavior. They are not interchangeable. Transport timeout, EOF or reset can coexist
with received bytes; parse errors can reflect client assumptions. Neither establishes
application filtering or rejection without a valid protocol/control.

Search existing protocol tools and retrieve their exact schemas before writing a
client. For an evidenced FastCGI service, read `references/fastcgi-validation.md`.
Do not assume a service port or server-side path from a historical example.

## Stop and report

Stop when the question is answered, scope ends, controls are unavailable, or no
narrower test is justified. After repeated no-information tests, reassess the premise;
changing clients without a distinguishing condition is not new evidence.

Report target scope, timestamp/client conditions, task/read refs, transport versus
protocol/application results, bounded conclusions and the next uncertainty. Use
solver_progress or worker_report for your role. Discovery is inventory, not proof
of a vulnerability or permission to access additional hosts.
