# TscanPlus fingerprint rules

Copied from the local TscanPlus configuration
(`~/.config/TscanPlus/config/`) on 2026-08-09.

- `FingerDir.yaml` — source file (38 active-fingerprint rules).
- `FingerDir.json` — runtime conversion of the same rules; the AION runtime
  loads JSON only so no YAML dependency is required.
- `Finger.json` — passive fingerprint rules in Wappalyzer format (categories +
  custom technologies; the built-in large database lives inside the closed
  TscanPlus binary and is not extractable).

TscanPlus is a closed-source tool; these files are its user-editable rule
configuration. The active rule format is `paths` + `matchers` where a rule hits
when the response status is in `status`, any `body_contains` keyword matches,
no `body_not_contains` keyword appears, and optional `content_type` /
`header_contains` constraints are satisfied.
