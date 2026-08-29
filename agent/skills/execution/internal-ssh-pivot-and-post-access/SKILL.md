---
name: internal-ssh-pivot-and-post-access
description: >-
  Validate an authorized SSH access path and one bounded internal pivot. Manage
  owned SSH sessions, commands, transfers, Direct-TCPIP channels, and limited
  post-access checks with complete cleanup and evidence tracking.
---

# Internal SSH, pivot, and post-access validation

Treat every session and channel as a scoped resource. Do not broaden the host,
credential, or port scope after access succeeds.

## Workflow

1. Confirm target, port, username, authorization, credential source, and intended
   validation question. Never place secrets in reports.
2. Open one owned session with `pentest_ssh_open` or perform a bounded SSH-only
   credential verification when explicitly assigned.
3. Use `pentest_ssh_exec` for one command at a time with output and timeout caps.
   Prefer read-only identity, route, service, and permission checks.
4. Use `pentest_ssh_transfer` only for an identified local artifact and bounded
   file size. Record direction, path, byte count, and digest.
5. Use `pentest_ssh_pivot_open` for one authorized internal host/port. Exchange
   only the bytes needed with `pentest_channel_io`, then close the channel.
6. Run `pentest_privesc_check` only when the assignment explicitly requires a
   bounded local privilege check; keep findings as candidates until verified.
7. Close every channel and session with `pentest_channel_close` and
   `pentest_ssh_close`, including error paths.

## Evidence

Report target, session ID, server fingerprint, command purpose, output reference,
channel target, transfer digest, cleanup result, and hypothesis outcome. Never
return passwords, private keys, or full sensitive files.

## Stop conditions

Stop on authentication failure, host-key or scope mismatch, unexpected route,
unbounded command requirement, channel failure, timeout, or a result that does not
answer the assigned question. Do not retry identical credentials or commands.
