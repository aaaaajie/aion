# Evasion direction

## Recognize

Strong signals include WAF/AV/EDR bypass, payload obfuscation or encoding,
shellcode evasion, or AI/LLM security objectives (prompt injection, jailbreak,
RAG poisoning, indirect injection, tool abuse). Medium signals include filtering
or sanitization wording, defense-control terminology, or an AI assistant surface.

Distinguish evasion from web: a WAF-bypass objective on an otherwise ordinary web
app is `evasion` when bypassing the defense is the goal; the same app without
that objective is `web`. AI/LLM application targets map to `evasion` even when
the surface is HTTP.

## First information channels

1. Identify the defensive control and its normalization behavior.
2. Enumerate encoding, case, comment, and protocol-level bypass dimensions.
3. For LLM targets, map input channels, retrieved context, and tool boundaries.
4. Validate one bypass or injection hypothesis with the minimal payload.

Do not rotate proxies or send large payload matrices unless the control is
already characterized.
