# dirsearch slim fork

Vendored from https://github.com/maurosoria/dirsearch at commit
`467f66b107f5316f6da85ceb4bcfcddbea447ae4` (v0.5.0, 2026-07-01).

This directory keeps only the algorithms AION needs for fast web path
discovery:

- wordlist and template expansion (`wordlist.py`, `wordlist_backend.py`);
- wildcard / soft-404 / redirect classification (`scanner.py`, `diff.py`);
- response match/filter helpers (`filters.py`);
- small shared structures and URL helpers (`structures.py`, `urlutils.py`).

The CLI, terminal interface, report writers, resumable session store, native
Rust backend, network requesters and global `options` state are removed.
Consumers pass explicit `ScanOptions`-style values instead of mutating global
state.

`db/templates/` and `db/categories/` contain only the data files used by the
quick / targeted / deep profiles. All files retain the upstream GPL-2.0
headers and the full license text is in `LICENSE`.
