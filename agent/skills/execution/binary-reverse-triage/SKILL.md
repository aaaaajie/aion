---
name: binary-reverse-triage
description: >-
  Triage and reverse-engineer an authorized Linux binary or binary protocol target
  using bounded ELF, hardening, string, symbol, disassembly, seccomp, debugger, and
  session evidence. Establish architecture and input paths before dynamic work.
---

# Binary reverse triage

Use static evidence to narrow the search before opening a live process or network
session. The target platform is Linux x86_64 unless the assignment explicitly
provides another supported environment.

## Workflow

1. Confirm the file is inside the workspace and run `bin_identify` first.
2. If the artifact is not a Linux ELF or the architecture does not match the
   available runner, do not start a dynamic session. Report `ENTRY_UNREACHABLE`
   and continue with bounded static analysis.
3. Run `bin_checksec`, `bin_strings`, and `bin_symbols`. Record protection state,
   interesting strings, imports/symbols, and available debug information.
4. Use `bin_disassemble` on a small set of relevant offsets or functions. Trace
   input parsing, validation, dangerous operations, state changes, and output.
5. Use `bin_seccomp` when a filter is supplied; use `bin_debug` only for a focused
   register, stack, or branch question.
6. For a binary protocol, identify framing and one safe request/response exchange
   before testing any hypothesis. Keep `pwn_tcp_open` and `pwn_session_io` bounded.
7. Write a candidate table linking entry point, function/offset, condition,
   impact hypothesis, evidence, and next verification step.

## Tool discipline

Use `bin_identify`, `bin_checksec`, `bin_strings`, `bin_symbols`,
`bin_disassemble`, `bin_seccomp`, and `bin_debug` for static triage. Use
`pwn_process_open` only after the Linux/architecture gate passes; use
`pwn_tcp_open` and `pwn_session_io` only for an assigned service. Close every
process or TCP session with `pwn_session_close`.

## Stop conditions

Stop dynamic work on a platform mismatch, missing executable, unbounded input
surface, repeated negative result, or unavailable dependency. Do not convert a
dangerous-looking symbol or an unexplained crash into a confirmed finding.

## Required report

Include the artifact hash, platform, protection summary, inspected functions or
offsets, input/output path, hypothesis outcome (`supported`, `rejected`, or
`inconclusive`), and complete evidence references.
