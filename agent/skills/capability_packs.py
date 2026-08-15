"""Six-dimensional TSecBench capability packs (single source of truth).

Each pack maps one solving direction to the Execution Skills mounted for it
and the ToolSpec names the Execution Agent should rely on.  The catalog
manifest is generated from this module so routing and the mounted skill set
can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


DIRECTIONS: tuple[str, ...] = (
    "web",
    "pentest",
    "binary",
    "exploit",
    "cloud",
    "evasion",
)

LEGACY_DIRECTION_ALIASES: dict[str, str] = {
    "web": "web",
    "binary": "binary",
    "ai": "evasion",
    "blockchain": "cloud",
}


@dataclass(frozen=True)
class CapabilityPack:
    direction: str
    skills: tuple[str, ...]
    tools: tuple[str, ...]
    keywords: tuple[str, ...]


def _pack(
    direction: str,
    skills: tuple[str, ...],
    tools: tuple[str, ...],
    keywords: tuple[str, ...],
) -> CapabilityPack:
    if len(skills) > 12:
        raise ValueError(
            f"capability pack {direction} exceeds the 12-skill listing limit"
        )
    return CapabilityPack(direction, skills, tools, keywords)


CAPABILITY_PACKS: tuple[CapabilityPack, ...] = (
    _pack(
        "web",
        (
            "sqli-sql-injection",
            "xss-cross-site-scripting",
            "csrf-cross-site-request-forgery",
            "path-traversal-lfi",
            "upload-insecure-files",
            "cmdi-command-injection",
            "deserialization-insecure",
            "api-auth-and-jwt-abuse",
            "auth-access-control",
            "source-code-audit",
            "recon-js-analysis",
            "php-file-upload-audit",
        ),
        (
            "system_http_request",
            "system_http_probe",
            "system_web_path_probe",
            "system_web_fingerprint",
            "system_http_analyze",
            "system_network_discovery",
            "pentest_dir_fuzz",
            "pentest_sqlmap",
        ),
        (
            "sql",
            "sqli",
            "xss",
            "csrf",
            "traversal",
            "lfi",
            "upload",
            "command injection",
            "ssti",
            "xxe",
            "jwt",
            "session",
            "cors",
            "smuggling",
            "deserialization",
            "login",
            "cookie",
        ),
    ),
    _pack(
        "pentest",
        (
            "api-protocol-security",
            "api-recon-and-docs",
            "graphql-and-hidden-parameters",
            "idor-broken-object-authorization",
            "oauth-oidc-misconfiguration",
            "http-host-header-attacks",
            "http-parameter-pollution",
            "web-cache-deception",
            "websocket-security",
            "performing-web-application-vulnerability-triage",
            "src-hunter",
            "401-403-bypass-techniques",
        ),
        (
            "system_network_discovery",
            "system_network_output",
            "system_http_request",
            "system_http_probe",
            "pentest_service_probe",
            "pentest_auth_brute",
            "pentest_dir_fuzz",
            "pentest_credential_lookup",
        ),
        (
            "pentest",
            "port scan",
            "nmap",
            "brute force",
            "weak password",
            "privesc",
            "privilege escalation",
            "lateral",
            "intranet",
            "graphql",
            "oauth",
            "idor",
            "host header",
            "websocket",
            "cache deception",
            "hpp",
            "403",
            "401",
        ),
    ),
    _pack(
        "binary",
        (
            "ctf-reverse",
            "ida-reverse",
            "ghidra-reverse",
            "radare2",
            "binary-diff",
            "protocol-reverse",
            "dotnet-reverse",
            "go-rust-reverse",
            "apk-reverse",
            "mobile-reverse",
            "macos-reverse",
            "reverse-flow",
        ),
        (
            "bin_identify",
            "bin_strings",
            "bin_checksec",
            "bin_symbols",
            "bin_disassemble",
            "bin_patch_elf",
            "pwn_pack",
            "pwn_rop_search",
            "pwn_libc_offsets",
            "bin_seccomp",
            "bin_debug",
        ),
        (
            "reverse",
            "binary",
            "elf",
            "pe",
            "mach-o",
            "decompile",
            "disassemble",
            "gdb",
            "radare",
            "ghidra",
            "ida",
            "strings",
            "symbol",
            "apk",
            "dex",
            "dotnet",
            "firmware",
            "bytecode",
            "obfuscated",
        ),
    ),
    _pack(
        "exploit",
        (
            "ctf-pwn",
            "stack-overflow-and-rop",
            "heap-exploitation",
            "format-string-exploitation",
            "pwn-chain",
            "kernel-exploitation",
            "browser-exploitation-v8",
            "offensive-exploit-development",
            "offensive-basic-exploitation",
            "offensive-crash-analysis",
            "symbolic-execution-tools",
            "patch-diff-exploit",
        ),
        (
            "bin_identify",
            "bin_checksec",
            "bin_symbols",
            "bin_disassemble",
            "bin_patch_elf",
            "pwn_pack",
            "pwn_rop_search",
            "pwn_libc_offsets",
            "bin_seccomp",
            "bin_debug",
        ),
        (
            "pwn",
            "exploit",
            "rop",
            "ret2libc",
            "ret2csu",
            "shellcode",
            "heap",
            "tcache",
            "fastbin",
            "uaf",
            "double free",
            "format string",
            "stack overflow",
            "buffer overflow",
            "canary",
            "nx",
            "pie",
            "kernel pwn",
            "one_gadget",
            "libc",
            "seccomp",
            "sandbox escape",
        ),
    ),
    _pack(
        "cloud",
        (
            "cloud-infra-supply-chain",
            "cloud-k8s",
            "dependency-confusion",
            "auditing-mcp-servers-for-tool-poisoning",
        ),
        (
            "system_network_discovery",
            "system_http_request",
            "system_http_probe",
            "cloud_enum",
        ),
        (
            "cloud",
            "aws",
            "gcp",
            "azure",
            "k8s",
            "kubernetes",
            "s3",
            "bucket",
            "metadata",
            "serverless",
            "docker",
            "container",
            "jenkins",
            "gitlab",
            "supply chain",
            "dependency confusion",
        ),
    ),
    _pack(
        "evasion",
        (
            "offensive-waf-bypass",
            "offensive-shellcode",
            "llm-prompt-injection",
            "detecting-indirect-prompt-injection",
            "ai-llm-agent-security",
            "continuous-llm-red-teaming-with-promptfoo",
            "testing-prompt-injection-in-rag-pipelines",
            "orchestrating-llm-attacks-with-pyrit",
        ),
        (
            "system_http_request",
            "system_http_probe",
            "evasion_payload_analyze",
        ),
        (
            "waf",
            "bypass",
            "evasion",
            "payload obfuscation",
            "encoding",
            "shellcode",
            "av",
            "edr",
            "prompt injection",
            "llm",
            "rag",
            "indirect injection",
            "jailbreak",
            "pyrit",
            "crescendo",
        ),
    ),
)

PACK_BY_DIRECTION: dict[str, CapabilityPack] = {
    pack.direction: pack for pack in CAPABILITY_PACKS
}


def normalize_direction(value: str | None) -> str:
    """Map legacy challenge metadata directions into the six-dimension space."""

    if value is None:
        return "unknown"
    key = str(value).strip().lower()
    if key in PACK_BY_DIRECTION:
        return key
    return LEGACY_DIRECTION_ALIASES.get(key, "unknown")


def pack_for_direction(direction: str) -> CapabilityPack:
    return PACK_BY_DIRECTION[normalize_direction(direction)]


def mounted_skill_ids() -> tuple[str, ...]:
    """Every execution Skill mounted by at least one capability pack."""

    seen: dict[str, None] = {}
    for pack in CAPABILITY_PACKS:
        for skill in pack.skills:
            seen.setdefault(f"execution/{skill}", None)
    seen.setdefault("common/recognize-challenge-direction", None)
    seen.setdefault("challenge/challenge-threat-modeling", None)
    return tuple(sorted(seen))


def pack_tools_for(direction: str) -> tuple[str, ...]:
    return PACK_BY_DIRECTION[normalize_direction(direction)].tools


def build_manifest() -> dict[str, Any]:
    """Deterministic catalog manifest consumed by SkillCatalog and doctor."""

    return {
        "version": 1,
        "directions": list(DIRECTIONS),
        "packs": {
            pack.direction: {
                "skills": list(pack.skills),
                "tools": list(pack.tools),
            }
            for pack in CAPABILITY_PACKS
        },
        "skills": list(mounted_skill_ids()),
    }


def write_manifest(root: Path) -> Path:
    """Write manifest.json into a skill root (used by release tooling/tests)."""

    path = root / "manifest.json"
    path.write_text(
        json.dumps(build_manifest(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return path
