"""Deterministic, metadata-first challenge domain recognition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Mapping, Sequence

from .contracts import (
    CompetitionDomainName,
    DomainSubtype,
    ScannerProfileName,
    profile_for_domain,
)

Decision = Literal["direct", "probe"]
ProbeDecision = Literal["direct", "pending", "review"]
COMPETITION_DOMAINS: tuple[CompetitionDomainName, ...] = (
    "web",
    "blockchain",
    "ai",
    "other",
)


@dataclass(frozen=True)
class _Signal:
    domain: CompetitionDomainName
    label: str
    pattern: re.Pattern[str]
    weight: float
    subtype: DomainSubtype | None = None


@dataclass(frozen=True)
class DomainAssessment:
    decision: Decision
    domain: CompetitionDomainName | None
    subdomain: DomainSubtype | None
    confidence: float
    scanner_profile: ScannerProfileName | None
    scores: dict[CompetitionDomainName, float]
    margin_ratio: float
    evidence: tuple[str, ...]
    candidate_domains: tuple[CompetitionDomainName, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "confidence": self.confidence,
            "scanner_profile": self.scanner_profile,
            "scores": dict(self.scores),
            "margin_ratio": self.margin_ratio,
            "evidence": list(self.evidence),
            "candidate_domains": list(self.candidate_domains),
        }


@dataclass(frozen=True)
class ProbeAssessment:
    decision: ProbeDecision
    domain: CompetitionDomainName | None
    subdomain: DomainSubtype | None
    confidence: float
    scanner_profile: ScannerProfileName | None
    evidence_refs: tuple[str, ...]
    results: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "confidence": self.confidence,
            "scanner_profile": self.scanner_profile,
            "evidence_refs": list(self.evidence_refs),
            "results": [dict(item) for item in self.results],
        }


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_SIGNALS: tuple[_Signal, ...] = (
    _Signal("web", "web", _rx(r"(?<![a-z0-9])web(?![a-z0-9])|网站|网页|Web题"), 2.5),
    _Signal("web", "http_url", _rx(r"https?://"), 3.2),
    _Signal("web", "web_stack", _rx(r"\b(?:html|javascript|php|django|flask|spring|tomcat|nginx|apache|graphql)\b"), 1.8),
    _Signal("web", "web_security", _rx(r"\b(?:sqli?|xss|ssrf|csrf|jwt|cookie|session)\b|注入|跨站|伪造请求|接口|路由"), 2.0),
    _Signal("web", "web_protocol", _rx(r"\b(?:http|https|request|response|api endpoint)\b|请求头|响应头"), 1.2),
    _Signal("web", "web_business_surface", _rx(r"\b(?:login|register|upload|download|crud|cms|admin panel)\b|登录|注册|上传|下载|后台"), 2.2),
    _Signal("blockchain", "blockchain", _rx(r"\b(?:blockchain|web3|ethereum|evm|defi)\b|区块链|以太坊|链上"), 2.7),
    _Signal("blockchain", "smart_contract", _rx(r"\b(?:smart contract|solidity|foundry|hardhat)\b|智能合约|合约地址"), 3.0),
    _Signal("blockchain", "contract_file", _rx(r"\.sol\b|\b(?:erc20|erc721|contract address)\b"), 2.8),
    _Signal("blockchain", "rpc_port", _rx(r":(?:8545|8546)(?:\b|/)|\bjson-rpc\b"), 2.5),
    _Signal("blockchain", "wallet", _rx(r"\b(?:wallet|transaction|nonce|gas fee)\b|钱包|交易哈希|私钥"), 1.4),
    _Signal("ai", "ai", _rx(r"(?<![a-z0-9])ai(?![a-z0-9])|人工智能"), 2.2),
    _Signal("ai", "llm", _rx(r"\b(?:llm|large language model|language model|rag|embedding)\b|大模型|语言模型|向量数据库|嵌入"), 2.8),
    _Signal("ai", "prompt", _rx(r"\b(?:prompt injection|system prompt|jailbreak|model inference)\b|提示词|提示注入|模型推理"), 3.0),
    _Signal("ai", "ml_stack", _rx(r"\b(?:machine learning|neural network|pytorch|tensorflow|transformer)\b|机器学习|神经网络"), 2.2),
    _Signal("ai", "agent", _rx(r"\b(?:ai agent|model endpoint)\b|智能体|模型接口"), 1.5),
    _Signal("ai", "model_api_path", _rx(r"/(?:v1/)?(?:chat(?:/completions)?|completions?|generate|models?|ask)(?:\b|/)"), 3.5),
    _Signal("ai", "model_request_fields", _rx(r"[\"']?(?:messages|prompt|model|temperature|max_tokens|top_p)[\"']?\s*[:=]"), 3.2),
    _Signal("ai", "model_response_fields", _rx(r"[\"']?(?:choices|assistant|usage)[\"']?\s*[:=]"), 3.2),
    _Signal("ai", "model_stream", _rx(r"\b(?:text/event-stream|server-sent events?|sse stream)\b|(?:^|\s)data:\s*\{"), 2.6),
    _Signal("other", "binary", _rx(r"\b(?:binary exploitation|elf|pe|firmware)\b|二进制"), 2.8, "binary"),
    _Signal("other", "pwn", _rx(r"\b(?:pwn|rop|buffer overflow)\b|栈溢出"), 2.8, "pwn"),
    _Signal("other", "reverse", _rx(r"\b(?:reverse(?: engineering| engineer)?|decompile|disassemble|apk)\b|逆向|反编译|反汇编"), 2.8, "reverse"),
    _Signal("other", "forensics", _rx(r"\b(?:forensics|pcap|memory dump|steganography)\b|取证|流量包|内存镜像|隐写"), 2.6, "forensics"),
    _Signal("other", "cryptography", _rx(r"\b(?:cryptography|cipher|rsa|aes)\b|密码学|密文"), 2.2, "cryptography"),
)

_FIELD_MULTIPLIERS = {
    "name": 1.35,
    "unique_code": 1.35,
    "description": 1.0,
    "hints": 1.15,
    "target_addresses": 0.9,
    "observations": 0.75,
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    return str(value)


def classify_challenge(
    challenge: Mapping[str, Any],
    *,
    hints: Sequence[str] = (),
    observations: Sequence[Mapping[str, Any] | str] = (),
    high_confidence_threshold: float = 0.75,
    minimum_raw_score: float = 3.0,
    minimum_margin_ratio: float = 0.25,
) -> DomainAssessment:
    """Classify a challenge without launching a full scanner."""

    fields = {
        "name": _text(challenge.get("name")),
        "unique_code": _text(challenge.get("unique_code")),
        "description": _text(challenge.get("description")),
        "hints": _text(hints),
        "target_addresses": _text(
            challenge.get("target_addresses") or challenge.get("container_addr")
        ),
        "observations": _text(observations),
    }
    scores: dict[CompetitionDomainName, float] = {
        domain: 0.0 for domain in COMPETITION_DOMAINS
    }
    evidence: list[str] = []
    subtype_scores: dict[DomainSubtype, float] = {
        "binary": 0.0,
        "pwn": 0.0,
        "reverse": 0.0,
        "forensics": 0.0,
        "cryptography": 0.0,
    }
    web_transport_score = 0.0
    for field_name, value in fields.items():
        if not value:
            continue
        multiplier = _FIELD_MULTIPLIERS[field_name]
        for signal in _SIGNALS:
            if signal.pattern.search(value):
                weighted = signal.weight * multiplier
                scores[signal.domain] += weighted
                if signal.subtype is not None:
                    subtype_scores[signal.subtype] += weighted
                if (
                    field_name == "target_addresses"
                    and signal.domain == "web"
                    and signal.label in {"http_url", "web_protocol"}
                ):
                    web_transport_score += weighted
                evidence.append(f"{field_name}:{signal.label}")

    # HTTP is also a transport for RPC and model APIs. Strong specialty metadata
    # should not become ambiguous merely because its endpoint uses an HTTP URL.
    if max(scores["blockchain"], scores["ai"], scores["other"]) >= 3.0:
        scores["web"] = max(0.0, scores["web"] - web_transport_score)

    ordered = sorted(scores, key=lambda domain: (-scores[domain], domain))
    top, second = ordered[0], ordered[1]
    top_score = scores[top]
    second_score = scores[second]
    total = sum(scores.values())
    confidence = top_score / total if total > 0 else 0.0
    margin_ratio = (top_score - second_score) / top_score if top_score > 0 else 0.0
    direct = (
        top_score >= minimum_raw_score
        and confidence >= high_confidence_threshold
        and margin_ratio >= minimum_margin_ratio
    )
    subdomain = None
    if direct and top == "other":
        subdomain = max(
            subtype_scores,
            key=lambda value: (subtype_scores[value], value),
        )
    return DomainAssessment(
        decision="direct" if direct else "probe",
        domain=top if direct else None,
        subdomain=subdomain,
        confidence=round(confidence, 4),
        scanner_profile=profile_for_domain(top) if direct else None,
        scores={key: round(value, 3) for key, value in scores.items()},
        margin_ratio=round(margin_ratio, 4),
        evidence=tuple(evidence[:30]),
        candidate_domains=tuple(ordered),
    )


def _structured_probe_result(value: Mapping[str, Any]) -> dict[str, Any]:
    domain = str(value.get("domain") or "").lower()
    if domain not in set(COMPETITION_DOMAINS):
        return {}
    raw_match = value.get("is_match")
    if not isinstance(raw_match, bool):
        raw_match = value.get("matches")
    confidence = value.get("confidence", 0.0)
    try:
        confidence_value = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence_value = 0.0
    return {
        "domain": domain,
        "subdomain": (
            str(value.get("subdomain")).lower()
            if str(value.get("subdomain") or "").lower()
            in {"binary", "pwn", "reverse", "forensics", "cryptography"}
            else None
        ),
        "is_match": raw_match if isinstance(raw_match, bool) else None,
        "confidence": confidence_value,
        "status": str(value.get("status") or "completed"),
        "evidence_ref": value.get("evidence_ref"),
        "signals": list(value.get("signals") or []),
    }


def assess_probe_reports(reports: Iterable[Mapping[str, Any]]) -> ProbeAssessment:
    """Combine independent one-domain reports after every active probe has stopped."""

    results = tuple(
        item
        for item in (_structured_probe_result(value) for value in reports)
        if item
    )
    active = any(item["status"] in {"pending", "queued", "starting", "running", "working"} for item in results)
    evidence_refs = tuple(
        str(item["evidence_ref"])
        for item in results
        if item.get("evidence_ref")
    )
    if active:
        return ProbeAssessment("pending", None, None, 0.0, None, evidence_refs, results)

    positives = sorted(
        (item for item in results if item["is_match"] is True),
        key=lambda item: (-item["confidence"], item["domain"]),
    )
    if positives:
        best = positives[0]
        runner_up = positives[1]["confidence"] if len(positives) > 1 else 0.0
        if best["confidence"] >= 0.7 and best["confidence"] - runner_up >= 0.15:
            domain = best["domain"]
            return ProbeAssessment(
                "direct",
                domain,
                best.get("subdomain") if domain == "other" else None,
                round(best["confidence"], 4),
                profile_for_domain(domain),
                evidence_refs,
                results,
            )
    return ProbeAssessment("review", None, None, 0.0, None, evidence_refs, results)
