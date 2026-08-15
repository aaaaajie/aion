"""Web technology fingerprint engine (TscanPlus + Yakit + EHole rule sets).

The passive engine implements the Wappalyzer-style matching used by
TscanPlus ``Finger.json`` (header regex with ``\\;version:\\1`` capture, HTML
regex, ``headerstr``/``titlestr`` substrings) and the Yakit keyword/favicon
rules. EHole keyword/regular rules require every condition and favicon rules
accept any listed hash. The active engine evaluates TscanPlus ``FingerDir`` path+matcher rules.
MurmurHash3 x86_32 is implemented in pure Python to keep the runtime
dependency-free.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .models import HttpAuth
from third_party.dirsearch.urlutils import (
    append_query_string,
    ensure_trailing_path_slash,
    safequote,
)


ROOT = Path(__file__).resolve().parents[2]
TSCAN_DATA = ROOT / "third_party" / "tscan"
YAKIT_DATA = ROOT / "third_party" / "yakit"
EHOLE_DATA = ROOT / "third_party" / "ehole"

_VERSION_SUFFIX_RE = re.compile(r"version:\\(\d+)")
_GENERIC_FINGERPRINT_TERMS = frozenset(
    {"login", "password", "username", "redirect", "admin", "submit", "logout"}
)
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_FAVICON_LINK_RE = re.compile(
    rb"""<link\b[^>]*\brel=["']?(?:shortcut\s+)?icon["']?[^>]*>""",
    re.IGNORECASE,
)
_HREF_RE = re.compile(rb"""\bhref=["']([^"']+)["']""", re.IGNORECASE)
BODY_CAP = 512 * 1024


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returns an unsigned 32-bit integer."""

    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    nblocks = length // 4
    for index in range(nblocks):
        k1 = int.from_bytes(data[index * 4 : index * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def mmh3_hash(data: bytes) -> int:
    value = murmur3_32(data)
    return value - 0x100000000 if value >= 0x80000000 else value


def favicon_hash(content: bytes) -> int:
    """Shodan/Yakit-compatible favicon hash."""

    return mmh3_hash(base64.b64encode(content))


def extract_title(body: bytes) -> str | None:
    match = _TITLE_RE.search(body or b"")
    if not match:
        return None
    text = match.group(1).decode("utf-8", errors="replace").strip()
    normalized = re.sub(r"\s+", " ", text)
    return normalized[:1024] or None


def extract_favicon_href(body: bytes) -> str | None:
    for link in _FAVICON_LINK_RE.findall(body or b""):
        match = _HREF_RE.search(link)
        if match:
            return match.group(1).decode("utf-8", errors="replace").strip()
    return None


def decode_body(body: bytes, content_type: str) -> str:
    if not body or _is_binary(body, content_type):
        return ""
    charset = _charset(content_type)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _is_binary(data: bytes, content_type: str) -> bool:
    lowered = (content_type or "").lower()
    if any(
        marker in lowered
        for marker in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "html")
    ):
        return False
    return b"\x00" in data


def _charset(content_type: str) -> str:
    match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type or "", re.IGNORECASE)
    return match.group(1) if match else "utf-8"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_cookies(
    session_cookies: list[dict[str, Any]], explicit: dict[str, str]
) -> httpx.Cookies:
    from http.cookiejar import Cookie

    jar = httpx.Cookies()
    for cookie in session_cookies:
        if str(cookie.get("name") or "") in explicit:
            continue
        domain = str(cookie.get("domain") or "")
        jar.jar.set_cookie(
            Cookie(
                version=int(cookie.get("version") or 0),
                name=str(cookie["name"]),
                value=str(cookie.get("value") or ""),
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=bool(domain),
                domain_initial_dot=domain.startswith("."),
                path=str(cookie.get("path") or "/"),
                path_specified=True,
                secure=bool(cookie.get("secure", False)),
                expires=(
                    int(cookie["expires"]) if cookie.get("expires") is not None else None
                ),
                discard=bool(cookie.get("discard", False)),
                comment=None,
                comment_url=None,
                rest=dict(cookie.get("rest") or {}),
                rfc2109=False,
            )
        )
    for name, value in explicit.items():
        jar.set(name, value)
    return jar


@dataclass(frozen=True)
class PassiveProbe:
    url: str
    status: int | None
    headers: dict[str, str]
    body_text: str
    title: str | None = None
    favicon_bytes: bytes | None = None


@dataclass(frozen=True)
class ActiveProbe:
    url: str
    path: str
    status: int
    headers: dict[str, str]
    body_text: str
    content_type: str


@dataclass
class FingerprintMatch:
    rule_id: str
    rule_sources: list[str]
    name: str
    category: str | None
    version: str | None
    source: str
    matched_path: str | None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence_score: int = 0
    confidence_level: str = "low"
    confidence_reasons: list[str] = field(default_factory=list)

    def as_record(self, **extra: Any) -> dict[str, Any]:
        return {
            "type": "fingerprint",
            "rule_id": self.rule_id,
            "rule_sources": self.rule_sources,
            "source": self.source,
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "matched_path": self.matched_path,
            "evidence": self.evidence,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "confidence_reasons": self.confidence_reasons,
            **extra,
        }

    def score(self) -> "FingerprintMatch":
        fields = {
            str(item.get("field") or "") for item in self.evidence if item.get("field")
        }
        body_evidence = [item for item in self.evidence if item.get("field") == "body"]
        reasons: list[str] = []
        if "favicon_hash" in fields:
            score = 100
            reasons.append("favicon_hash")
        elif self.source == "active":
            score = 80
            reasons.append("active_path_match")
        elif "title" in fields:
            score = 70
            reasons.append("title_signature")
        elif "header" in fields:
            score = 60
            reasons.append("header_signature")
        elif len(body_evidence) >= 2 or any(
            item.get("match_type") == "regex" for item in body_evidence
        ):
            score = 50
            reasons.append("multi_condition_body")
        else:
            score = 20
            reasons.append("single_keyword")
        additional_sources = max(0, len(set(self.rule_sources)) - 1)
        additional_fields = max(0, len(fields) - 1)
        if additional_sources:
            score += additional_sources * 20
            reasons.append("multiple_rule_sources")
        if additional_fields:
            score += additional_fields * 15
            reasons.append("multiple_response_fields")
        patterns = {
            str(item.get("pattern") or "").strip().casefold().strip("/ ")
            for item in self.evidence
            if isinstance(item.get("pattern"), str)
        }
        generic_only = bool(patterns) and patterns.issubset(_GENERIC_FINGERPRINT_TERMS)
        if generic_only and additional_sources == 0 and additional_fields == 0:
            score = min(score, 20)
            reasons.append("generic_term_capped")
        self.confidence_score = min(100, score)
        self.confidence_level = (
            "high" if self.confidence_score >= 80 else "medium" if self.confidence_score >= 50 else "low"
        )
        self.confidence_reasons = reasons
        return self


@lru_cache(maxsize=1)
def load_tscan_passive() -> dict[str, Any]:
    path = TSCAN_DATA / "Finger.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_yakit_rules() -> list[dict[str, Any]]:
    path = YAKIT_DATA / "fingerprint.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_active_rules() -> dict[str, dict[str, Any]]:
    path = TSCAN_DATA / "FingerDir.json"
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class EHoleRule:
    rule_id: str
    name: str
    method: str
    location: str
    patterns: tuple[str, ...]
    regexes: tuple[re.Pattern[str], ...] = ()


@lru_cache(maxsize=1)
def load_ehole_rules() -> tuple[tuple[EHoleRule, ...], dict[str, int]]:
    payload = json.loads((EHOLE_DATA / "finger.json").read_text(encoding="utf-8"))
    rules: list[EHoleRule] = []
    diagnostics = {"loaded": 0, "skipped": 0, "invalid_regex": 0}
    for raw in payload.get("fingerprint") or []:
        method = str(raw.get("method") or "keyword").lower()
        location = str(raw.get("location") or "body").lower()
        name = str(raw.get("cms") or "").strip()
        patterns = tuple(str(item) for item in (raw.get("keyword") or []) if str(item))
        if not name or not patterns or method not in {"keyword", "regular", "faviconhash"}:
            diagnostics["skipped"] += 1
            continue
        regexes: list[re.Pattern[str]] = []
        if method == "regular":
            invalid = False
            for pattern in patterns:
                try:
                    regexes.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    diagnostics["invalid_regex"] += 1
                    invalid = True
                    break
            if invalid:
                diagnostics["skipped"] += 1
                continue
        canonical = json.dumps(
            {
                "cms": name,
                "method": method,
                "location": location,
                "keyword": patterns,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        rules.append(
            EHoleRule(
                rule_id=f"ehole-{hashlib.sha256(canonical.encode()).hexdigest()[:20]}",
                name=name,
                method=method,
                location=location,
                patterns=patterns,
                regexes=tuple(regexes),
            )
        )
        diagnostics["loaded"] += 1
    return tuple(rules), diagnostics


def _source_rule_id(source: str, value: Any) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{source.lower()}-{hashlib.sha256(canonical.encode()).hexdigest()[:20]}"


def _result_rule_id(name: str, source: str, matched_path: str | None) -> str:
    canonical = "|".join((" ".join(name.casefold().split()), source, matched_path or ""))
    return f"fingerprint-{hashlib.sha256(canonical.encode()).hexdigest()[:20]}"


def _header_items(headers: dict[str, str]) -> dict[str, str]:
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _split_version_pattern(pattern: str) -> tuple[str, int | None]:
    if "\\;" in pattern:
        regex, _, version_part = pattern.partition("\\;")
        match = _VERSION_SUFFIX_RE.search(version_part)
        return regex, int(match.group(1)) if match else None
    return pattern, None


class FingerprintEngine:
    """Passive technology matching over one homepage response."""

    def __init__(self) -> None:
        self._tscan = load_tscan_passive()
        self._yakit = load_yakit_rules()
        self._ehole, self.rule_diagnostics = load_ehole_rules()
        self._categories = {
            str(key): str(value.get("name") or "")
            for key, value in (self._tscan.get("categories") or {}).items()
        }

    def match(self, probe: PassiveProbe) -> list[FingerprintMatch]:
        raw_matches: list[FingerprintMatch] = []
        for name, tech in (self._tscan.get("technologies") or {}).items():
            match = self._match_wappalyzer(name, tech, probe)
            if match is not None:
                raw_matches.append(match)
        for rule in self._yakit:
            match = self._match_yakit(rule, probe)
            if match is not None:
                raw_matches.append(match)
        for rule in self._ehole:
            match = self._match_ehole(rule, probe)
            if match is not None:
                raw_matches.append(match)
        matches: dict[tuple[str, str, str], FingerprintMatch] = {}
        for match in raw_matches:
            key = (
                " ".join(match.name.casefold().split()),
                match.source,
                match.matched_path or "",
            )
            existing = matches.get(key)
            if existing is None:
                match.rule_id = _result_rule_id(match.name, match.source, match.matched_path)
                matches[key] = match
                continue
            existing.evidence.extend(match.evidence)
            existing.rule_sources = sorted(
                set(existing.rule_sources).union(match.rule_sources)
            )
            if existing.version is None:
                existing.version = match.version
            if existing.category is None:
                existing.category = match.category
        return [match.score() for match in matches.values()]

    def _match_wappalyzer(
        self,
        name: str,
        tech: dict[str, Any],
        probe: PassiveProbe,
    ) -> FingerprintMatch | None:
        evidence: list[dict[str, Any]] = []
        version: str | None = None
        lowered = _header_items(probe.headers)
        for header_name, raw_pattern in (tech.get("headers") or {}).items():
            value = lowered.get(str(header_name).lower())
            if value is None:
                continue
            if not raw_pattern:
                evidence.append(
                    {"field": "header", "pattern": str(header_name), "value": value}
                )
                continue
            regex, version_group = _split_version_pattern(str(raw_pattern))
            try:
                matched = re.search(regex, value)
            except re.error:
                continue
            if matched is None:
                continue
            if version is None and version_group is not None:
                try:
                    version = matched.group(version_group)
                except (IndexError, AttributeError):
                    pass
            evidence.append(
                {
                    "field": "header",
                    "pattern": str(raw_pattern),
                    "value": matched.group(0),
                }
            )
        for pattern in tech.get("html") or []:
            try:
                matched = re.search(str(pattern), probe.body_text)
            except re.error:
                continue
            if matched is not None:
                evidence.append(
                    {
                        "field": "body",
                        "pattern": str(pattern),
                        "value": matched.group(0),
                        "match_type": "regex",
                    }
                )
        for value in tech.get("headerstr") or []:
            needle = str(value).lower()
            if any(needle in str(v).lower() for v in probe.headers.values()):
                evidence.append({"field": "header", "pattern": str(value), "value": value})
        for value in tech.get("titlestr") or []:
            needle = str(value).lower()
            if probe.title and needle in probe.title.lower():
                evidence.append(
                    {"field": "title", "pattern": str(value), "value": probe.title}
                )
        if not evidence:
            return None
        return FingerprintMatch(
            rule_id=_source_rule_id("tscanplus", {"name": name, "rule": tech}),
            rule_sources=["TscanPlus"],
            name=str(name),
            category=self._categories.get(str(tech.get("cats") or "")),
            version=version,
            source="passive",
            matched_path=None,
            evidence=evidence,
        )

    def _match_yakit(
        self,
        rule: dict[str, Any],
        probe: PassiveProbe,
    ) -> FingerprintMatch | None:
        method = str(rule.get("method") or "keyword")
        location = str(rule.get("location") or "body")
        keywords = [str(item) for item in (rule.get("keyword") or [])]
        name = str(rule.get("cms") or "unknown")
        evidence: list[dict[str, Any]] = []
        if method == "faviconhash":
            if probe.favicon_bytes is None:
                return None
            current = favicon_hash(probe.favicon_bytes)
            for keyword in keywords:
                if current == _parse_int(keyword):
                    evidence.append(
                        {
                            "field": "favicon_hash",
                            "pattern": keyword,
                            "value": str(current),
                        }
                    )
        elif location == "header":
            lowered_values = [str(value).lower() for value in probe.headers.values()]
            for keyword in keywords:
                needle = keyword.lower()
                if any(needle in value for value in lowered_values):
                    evidence.append(
                        {"field": "header", "pattern": keyword, "value": keyword}
                    )
        else:
            for keyword in keywords:
                if keyword.lower() in probe.body_text.lower():
                    evidence.append(
                        {"field": "body", "pattern": keyword, "value": keyword}
                    )
        if not evidence:
            return None
        return FingerprintMatch(
            rule_id=_source_rule_id("yakit", rule),
            rule_sources=["Yakit"],
            name=name,
            category=None,
            version=None,
            source="passive",
            matched_path=None,
            evidence=evidence,
        )

    def _match_ehole(
        self,
        rule: EHoleRule,
        probe: PassiveProbe,
    ) -> FingerprintMatch | None:
        if rule.location == "header":
            target = "\n".join(
                f"{name}: {value}" for name, value in probe.headers.items()
            )
        elif rule.location == "title":
            target = probe.title or ""
        else:
            target = probe.body_text
        evidence: list[dict[str, Any]] = []
        if rule.method == "faviconhash":
            if probe.favicon_bytes is None:
                return None
            current = favicon_hash(probe.favicon_bytes)
            candidates = {_parse_int(value) for value in rule.patterns}
            if current not in candidates:
                return None
            evidence.append(
                {
                    "field": "favicon_hash",
                    "pattern": list(rule.patterns),
                    "value": str(current),
                    "rule_id": rule.rule_id,
                }
            )
        elif rule.method == "regular":
            found = [regex.search(target) for regex in rule.regexes]
            if not found or any(match is None for match in found):
                return None
            evidence.extend(
                {
                    "field": rule.location,
                    "pattern": pattern,
                    "value": match.group(0),
                    "rule_id": rule.rule_id,
                    "match_type": "regex",
                }
                for pattern, match in zip(rule.patterns, found)
                if match is not None
            )
        else:
            lowered = target.casefold()
            if not all(pattern.casefold() in lowered for pattern in rule.patterns):
                return None
            evidence.extend(
                {
                    "field": rule.location,
                    "pattern": pattern,
                    "value": pattern,
                    "rule_id": rule.rule_id,
                }
                for pattern in rule.patterns
            )
        return FingerprintMatch(
            rule_id=rule.rule_id,
            rule_sources=["EHole"],
            name=rule.name,
            category=None,
            version=None,
            source="passive",
            matched_path=None,
            evidence=evidence,
        )


class ActiveFingerprintEngine:
    """TscanPlus FingerDir path+matcher rule evaluation."""

    def __init__(self) -> None:
        self._rules = load_active_rules()

    @property
    def rules(self) -> dict[str, dict[str, Any]]:
        return self._rules

    def all_paths(self) -> list[str]:
        seen: set[str] = set()
        paths: list[str] = []
        for rule in self._rules.values():
            for path in rule.get("paths") or []:
                if path not in seen:
                    seen.add(path)
                    paths.append(str(path))
        return paths

    def matching_rules_for(
        self, path: str, probe: ActiveProbe
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        for name, rule in self._rules.items():
            if path not in (rule.get("paths") or []):
                continue
            matchers = rule.get("matchers") or {}
            if not self._matches(path, probe, matchers):
                continue
            matches.append(
                FingerprintMatch(
                    rule_id=_result_rule_id(name, "active", path),
                    rule_sources=["TscanPlus"],
                    name=name,
                    category=None,
                    version=None,
                    source="active",
                    matched_path=path,
                    evidence=self._evidence(path, probe, matchers),
                ).score()
            )
        return matches

    @staticmethod
    def _matches(
        path: str, probe: ActiveProbe, matchers: dict[str, Any]
    ) -> bool:
        statuses = [int(value) for value in (matchers.get("status") or [])]
        if statuses and probe.status not in statuses:
            return False
        body_contains = [str(value) for value in (matchers.get("body_contains") or [])]
        if body_contains and not any(
            keyword.lower() in probe.body_text.lower() for keyword in body_contains
        ):
            return False
        body_not_contains = [
            str(value) for value in (matchers.get("body_not_contains") or [])
        ]
        if any(keyword.lower() in probe.body_text.lower() for keyword in body_not_contains):
            return False
        content_types = [
            str(value) for value in (matchers.get("content_type") or [])
        ]
        if content_types and not any(
            keyword.lower() in probe.content_type.lower() for keyword in content_types
        ):
            return False
        header_contains = [
            str(value) for value in (matchers.get("header_contains") or [])
        ]
        if header_contains:
            header_text = "\n".join(
                f"{name}: {value}" for name, value in probe.headers.items()
            ).lower()
            if not any(keyword.lower() in header_text for keyword in header_contains):
                return False
        return True

    @staticmethod
    def _evidence(
        path: str, probe: ActiveProbe, matchers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = [{"field": "status", "pattern": None, "value": probe.status}]
        for keyword in matchers.get("body_contains") or []:
            evidence.append({"field": "body", "pattern": str(keyword), "value": str(keyword)})
        return evidence


def _parse_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class FingerprintOptions:
    url: str
    passive: bool = True
    active: bool = True
    include_favicon: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth: HttpAuth | None = None
    session_id: str | None = None
    follow_redirects: bool = False
    verify_tls: bool = False
    timeout_seconds: float = 10.0
    concurrency: int = 8
    request_intent: str = "technology_fingerprint"
    parent_request_id: str | None = None
    request_group_id: str | None = None
    minimum_confidence: str = "medium"

    def to_plan(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "passive": self.passive,
            "active": self.active,
            "include_favicon": self.include_favicon,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "auth": self.auth.model_dump(mode="json") if self.auth is not None else None,
            "session_id": self.session_id,
            "follow_redirects": self.follow_redirects,
            "verify_tls": self.verify_tls,
            "timeout_seconds": self.timeout_seconds,
            "concurrency": self.concurrency,
            "request_intent": self.request_intent,
            "parent_request_id": self.parent_request_id,
            "request_group_id": self.request_group_id,
            "minimum_confidence": self.minimum_confidence,
        }

    @classmethod
    def from_plan(cls, data: dict[str, Any]) -> "FingerprintOptions":
        auth = data.get("auth")
        return cls(
            url=str(data["url"]),
            passive=bool(data.get("passive", True)),
            active=bool(data.get("active", True)),
            include_favicon=bool(data.get("include_favicon", True)),
            headers=dict(data.get("headers") or {}),
            cookies=dict(data.get("cookies") or {}),
            auth=HttpAuth.model_validate(auth) if auth is not None else None,
            session_id=data.get("session_id"),
            follow_redirects=bool(data.get("follow_redirects", False)),
            verify_tls=bool(data.get("verify_tls", False)),
            timeout_seconds=float(data.get("timeout_seconds") or 10.0),
            concurrency=int(data.get("concurrency") or 8),
            request_intent=str(data.get("request_intent") or "technology_fingerprint"),
            parent_request_id=data.get("parent_request_id"),
            request_group_id=data.get("request_group_id"),
            minimum_confidence=str(data.get("minimum_confidence") or "medium"),
        )


@dataclass
class FingerprintScanResult:
    passive_requests: int = 0
    passive_matched: int = 0
    active_requests: int = 0
    active_matched: int = 0
    errors: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    rule_diagnostics: dict[str, int] = field(default_factory=dict)
    suppressed_match_count: int = 0
    stopped: bool = False
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int = 0


@dataclass
class _FingerprintResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


class FingerprintScanner:
    """Run passive and active fingerprint probes with one shared client."""

    def __init__(
        self,
        options: FingerprintOptions,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.options = options
        self.transport = transport
        self._passive = FingerprintEngine()
        self._active = ActiveFingerprintEngine()

    async def scan(
        self,
        *,
        session_cookies: list[dict[str, Any]],
        on_match,
        stop_requested=None,
        resource_guard=None,
    ) -> FingerprintScanResult:
        clock_started = time.perf_counter()
        started_at = _now()
        cookies = _build_cookies(session_cookies, self.options.cookies)
        client = httpx.AsyncClient(
            verify=self.options.verify_tls,
            follow_redirects=self.options.follow_redirects,
            timeout=httpx.Timeout(self.options.timeout_seconds),
            transport=self.transport,
            trust_env=True,
        )
        try:
            result = await self._scan(
                client, cookies, on_match, stop_requested, resource_guard
            )
        finally:
            await client.aclose()
        result.started_at = started_at
        result.finished_at = _now()
        result.duration_ms = int((time.perf_counter() - clock_started) * 1000)
        return result

    async def _scan(
        self,
        client: httpx.AsyncClient,
        cookies: httpx.Cookies,
        on_match,
        stop_requested,
        resource_guard,
    ) -> FingerprintScanResult:
        result = FingerprintScanResult(
            rule_diagnostics=dict(self._passive.rule_diagnostics)
        )
        is_stopped = stop_requested or (lambda: False)
        if self.options.passive:
            await self._passive_scan(
                client, cookies, on_match, result, resource_guard, is_stopped
            )
        if self.options.active and not is_stopped():
            await self._active_scan(
                client, cookies, on_match, result, is_stopped, resource_guard
            )
        result.stopped = bool(is_stopped())
        return result

    async def _passive_scan(
        self,
        client: httpx.AsyncClient,
        cookies: httpx.Cookies,
        on_match,
        result: FingerprintScanResult,
        resource_guard,
        is_stopped,
    ) -> None:
        if resource_guard is not None:
            await resource_guard()
        if is_stopped():
            result.stopped = True
            return
        root = await self._get_url(client, self._join_url(""), cookies, result)
        if root is None:
            return
        favicon_bytes: bytes | None = None
        if self.options.include_favicon:
            if resource_guard is not None:
                await resource_guard()
            if is_stopped():
                result.stopped = True
                return
            href = extract_favicon_href(root.body)
            favicon_url = (
                urljoin(str(root.url), href)
                if href
                else urljoin(str(root.url), "/favicon.ico")
            )
            favicon = await self._get_url(client, favicon_url, cookies, result)
            if favicon is not None:
                favicon_bytes = favicon.body
        content_type = root.headers.get("content-type", "")
        probe = PassiveProbe(
            url=str(root.url),
            status=root.status,
            headers=dict(root.headers),
            body_text=decode_body(root.body, content_type),
            title=extract_title(root.body),
            favicon_bytes=favicon_bytes,
        )
        for match in self._passive.match(probe):
            if _CONFIDENCE_RANK[match.confidence_level] < _CONFIDENCE_RANK[
                self.options.minimum_confidence
            ]:
                result.suppressed_match_count += 1
                continue
            result.passive_matched += 1
            if match.category:
                result.by_category[match.category] = (
                    result.by_category.get(match.category, 0) + 1
                )
            await on_match(match)

    async def _active_scan(
        self,
        client: httpx.AsyncClient,
        cookies: httpx.Cookies,
        on_match,
        result: FingerprintScanResult,
        is_stopped,
        resource_guard,
    ) -> None:
        paths = self._active.all_paths()
        semaphore = asyncio.Semaphore(self.options.concurrency)

        async def one(path: str) -> None:
            if is_stopped():
                return
            async with semaphore:
                if resource_guard is not None:
                    await resource_guard()
                if is_stopped():
                    return
                response = await self._get_url(
                    client, self._join_url(path), cookies, result
                )
                if response is None:
                    return
                probe = ActiveProbe(
                    url=str(response.url),
                    path=path,
                    status=response.status,
                    headers=dict(response.headers),
                    body_text=decode_body(
                        response.body, response.headers.get("content-type", "")
                    ),
                    content_type=response.headers.get("content-type", ""),
                )
                for match in self._active.matching_rules_for(path, probe):
                    if _CONFIDENCE_RANK[match.confidence_level] < _CONFIDENCE_RANK[
                        self.options.minimum_confidence
                    ]:
                        result.suppressed_match_count += 1
                        continue
                    result.active_matched += 1
                    await on_match(match)

        await asyncio.gather(*(one(path) for path in paths))

    async def _get_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        cookies: httpx.Cookies,
        result: FingerprintScanResult,
    ) -> _FingerprintResponse | None:
        headers = dict(self.options.headers)
        lowered = {name.lower() for name in headers}
        if "cache-control" not in lowered:
            headers["Cache-Control"] = "no-cache"
        if "pragma" not in lowered:
            headers["Pragma"] = "no-cache"
        if "user-agent" not in lowered:
            headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
            )
        auth: httpx.Auth | tuple[str, str] | None = None
        if self.options.auth is not None:
            if self.options.auth.type == "basic":
                auth = (
                    self.options.auth.username or "",
                    self.options.auth.password or "",
                )
            else:
                headers["Authorization"] = f"Bearer {self.options.auth.token}"
        try:
            async with client.stream(
                "GET",
                url,
                headers=headers,
                cookies=cookies,
                auth=auth,
            ) as response:
                status = response.status_code
                final_url = str(response.url)
                response_headers = dict(response.headers)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= BODY_CAP:
                        break
        except httpx.TimeoutException as exc:
            result.errors["timeout"] = result.errors.get("timeout", 0) + 1
            return None
        except httpx.HTTPError as exc:
            result.errors["http_error"] = result.errors.get("http_error", 0) + 1
            return None
        except OSError as exc:
            result.errors["protocol_error"] = result.errors.get("protocol_error", 0) + 1
            return None
        return _FingerprintResponse(
            url=final_url,
            status=status,
            headers=response_headers,
            body=bytes(body),
        )

    def _join_url(self, path: str) -> str:
        parsed = urlsplit(ensure_trailing_path_slash(self.options.url))
        base = urlunsplit(parsed._replace(query="", fragment=""))
        return append_query_string(
            urljoin(base, safequote(path.lstrip("/"))),
            parsed.query,
        )
