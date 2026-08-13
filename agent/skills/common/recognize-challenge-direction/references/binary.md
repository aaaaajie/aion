# Binary direction

## Recognize

Strong signals include an ELF, PE, Mach-O, shared library, executable artifact,
libc/ld bundle, C/C++ source, or explicit ROP, shellcode, format-string, heap,
stack-overflow, reversing, assembly, or GDB objective. A raw TCP service with a
binary protocol is supporting evidence, not proof by itself.

Distinguish binary work from blockchain: Solidity, ABI, bytecode, contract
addresses, chain IDs, and `eth_*` methods indicate blockchain even when a native
launcher or `nc` endpoint is present.

## First information channels

1. Identify local artifacts, architecture, file type, symbols, and protections.
2. Characterize the exact remote protocol and prompt without fuzzing.
3. Map source or decompiled control/data flow around the stated objective.
4. Form one memory-safety or logic hypothesis and define one verification.

Do not run an unrestricted scanner or send a generic payload matrix before the
artifact and protocol are understood.
