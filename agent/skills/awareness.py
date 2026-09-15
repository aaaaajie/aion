"""Local capability awareness. External evidence selects fixed catalog text only."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .capability_packs import PACK_BY_DIRECTION
from .tools import SkillTools

# Aliases describe observations as well as mechanisms. Values are trusted release data.
ROUTES = {
    'execution/sqli-sql-injection': (('sql injection', 'database error', 'sql syntax error', 'quoted string not properly terminated', 'you have an error in your sql syntax', 'sqlite error', 'mysql error', 'postgresql error', 'parameter differential', 'parameter difference', 'input differential', 'input difference', 'SQL注入', 'SQL 注入', '数据库报错', '输入差异', '参数差异'), ('pentest_sqlmap', 'system_http_replay', 'system_http_compare')),
    'common/web-ctf-flow': (('login', 'cookie', 'redirect', 'authentication', 'internal server error', '5xx', '登录', '认证', '重定向', '会话', '页面报错'), ('system_http_compare', 'system_http_replay', 'system_browser_open')),
    'execution/src-auth-business-logic': (('authorization', 'idor', 'business logic', '越权', '业务逻辑', '身份接口'), ('system_http_request', 'system_http_compare')),
    'execution/src-audit-workflow': (('source code', '源码', '代码审计'), ('system_source_scan', 'system_grep', 'system_read_file')),
    'execution/api-protocol-security': (('fastcgi', 'protocol', '协议'), ('system_fastcgi_request', 'system_http_request')),
    'execution/offensive-ssrf': (('ssrf', 'server-side request', '服务端请求', '内网地址'), ('system_http_request', 'system_http_compare')),
    'execution/xss-cross-site-scripting': (('xss', 'cross-site scripting', '脚本注入'), ('system_browser_open', 'system_browser_action')),
    'execution/path-traversal-lfi': (('path traversal', 'directory traversal', 'directory climbing', 'backtracking', 'lfi', 'local file inclusion', 'arbitrary file read', 'file inclusion', 'path normalization', 'path canonicalization', 'filename parameter', 'download parameter controls file path', 'preview reads file', 'absolute path accepted', 'filter strips ../', '路径穿越', '目录穿越', '本地文件包含', '任意文件读取', '文件包含', '文件名参数', '下载参数控制文件路径', '预览读取报错', '绝对路径被接受', '过滤 ../', '路径规范化', '路径拼接'), ('system_http_request', 'system_http_compare')),
    'execution/cmdi-command-injection': (('command injection', '命令注入'), ('system_http_request', 'system_source_scan')),
    'execution/deserialization-insecure': (('deserialization', 'unserialize', 'pickle', '反序列化'), ('system_source_scan', 'system_http_request')),
    'execution/api-auth-and-jwt-abuse': (('jwt', 'json web token'), ('pentest_jwt', 'system_http_request')),
    'common/vulnerability-knowledge-base': (('poc', 'cve', '漏洞编号', '漏洞库'), ('system_poc_search', 'system_poc_inspect', 'system_poc_run', 'system_poc_output')),
    'common/cyberchef-recipes': (('base64', 'hex', 'xor', 'aes', '解密', '编解码'), ('system_cyberchef',)),
    'common/ctf-flag-locator': (
        (
            'target-side file read', 'file-read capability', 'file read', 'command execution', 'remote code execution',
            'rce', 'database read', 'admin session', 'administrator session', 'ssrf',
            '文件读取', '命令执行', '远程代码执行', '数据库读取', '管理员会话', '服务端请求',
        ),
        ('system_read_file', 'system_shell', 'system_http_request', 'evidence_read'),
    ),
}
# Delayed rendering is a workflow reference, not a fabricated standalone Skill.
ROUTES['common/web-ctf-flow'] = (ROUTES['common/web-ctf-flow'][0] + ('ssti', 'delayed rendering', '延迟渲染', '模板渲染'), ROUTES['common/web-ctf-flow'][1])
SKIP_TOOLS = {'tool_search', 'tool_result_read', 'skill_search', 'skill_invoke', 'skill_resource_read'}
MAX_SIGNAL_CHARS = 24_000
INVALID_EVIDENCE_STAGES = frozenset(
    {"parse", "schema", "semantic", "permission", "conflict"}
)
TERMINAL_FAILURES = frozenset(
    {
        "failed", "timeout", "stopped", "interrupted", "cancelled", "queued",
        "running", "waiting", "analyzing", "pending", "partial", "empty", "not_started",
    }
)
EVIDENCE_HINTS = {
    "error_response": ("5xx",),
    "state_change": ("redirect", "cookie"),
    "login_surface": ("login",),
    "input_difference": ("input difference",),
    "response_difference": ("response difference",),
    "database_signal": ("database error",),
    "capability_change": ("file read",),
}
INPUT_DIFFERENTIAL_TOOLS = frozenset(
    {"system_http_request", "system_http_replay", "system_http_probe"}
)
HTTP_EVIDENCE_TOOLS = frozenset(
    {
        "system_http_request",
        "system_http_replay",
        "system_http_probe",
        "system_http_compare",
        "system_http_response",
        "system_web_path_probe",
    }
)
LOGIN_EVIDENCE_TOOLS = frozenset(
    {"system_http_request", "system_http_probe", "system_http_replay"}
)
MAX_TARGET_WINDOWS = 8
LOGIN_PATH_SEGMENTS = frozenset({"login", "signin", "sign-in"})
LOGIN_IDENTITY_KEYS = frozenset({"user", "username", "email", "login", "identity"})
LOGIN_SECRET_KEYS = frozenset({"password", "passwd", "pass", "token", "otp", "code"})
RESPONSE_FIELDS = frozenset(
    {
        "status_code", "initial_status_code", "status", "execution_status",
        "resource_status", "analysis_status", "location", "redirect_chain",
        "set-cookie", "headers", "content", "body", "output", "results",
        "responses", "summary", "observation", "error", "auth_state",
        "authentication_status", "authenticated", "session_state",
        "protected_control", "identity", "principal",
    }
)
STATE_FIELDS = frozenset(
    {
        "location", "redirect_chain", "set-cookie", "cookie", "cookies",
        "auth_state", "authentication_status", "authenticated", "session_state",
        "protected_control", "identity", "principal",
    }
)


def contains(text: str, alias: str) -> bool:
    pattern = re.escape(alias.casefold())
    if alias.isascii():
        pattern = r'(?<![a-z0-9_])' + pattern + r'(?![a-z0-9_])'
    return re.search(pattern, text.casefold()) is not None


def signal_text(value):
    """Read evidence values, not schema keys, tool names or hidden reasoning."""
    excluded = {'reasoning_content', 'reasoning', 'thinking', 'instructions',
                'schema', 'parameters', 'tools', 'tool_name', 'resources',
                'resource_manifest', 'description', 'active_skills'}
    parts = []
    remaining = MAX_SIGNAL_CHARS

    def visit(item, depth=0):
        nonlocal remaining
        if remaining <= 0 or depth > 12:
            return
        if isinstance(item, str):
            text = item[:remaining]
            parts.append(text)
            remaining -= len(text)
        elif isinstance(item, dict):
            for key, child in item.items():
                if str(key).casefold() in excluded:
                    continue
                if str(key).casefold() == 'set-cookie' and child:
                    visit('cookie')
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
    visit(value)
    return '\n'.join(parts)


class CapabilityAwareness:
    def __init__(self, context, registry):
        self.context, self.registry = context, registry
        ids = {f'execution/{name}' for name in PACK_BY_DIRECTION['web'].skills} | set(ROUTES)
        self.skills = {s.skill_id: s for s in context.catalog.available(context.role) if s.skill_id in ids}
        self.seen: set[str] = set()
        self.current: list[dict[str, Any]] = []
        self._observation_signatures: list[str] = []
        self._input_signatures: list[str] = []
        self._evidence_classes: set[str] = set()
        self._last_observation_classes: set[str] = set()
        self._last_observation_refs: list[str] = []
        self._last_target_key: str | None = None
        self._target_windows: list[dict[str, Any]] = []
        self._decision_acknowledged = False

    @classmethod
    def from_registry(cls, registry):
        if not registry.has_tool('skill_search') or not registry.has_tool('skill_invoke'):
            return None
        provider = next((p for p in registry.providers if isinstance(p, SkillTools)), None)
        return cls(provider.context, registry) if provider else None

    def tools(self, skill_id):
        return [name for name in ROUTES.get(skill_id, ((), ()))[1] if self.registry.has_tool(name)]

    def active(self):
        return {s['skill_id'] for s in self.context.active_skills}

    def restore(self, payload):
        self.seen = set(payload.get('seen', []))
        self.current = [c for c in payload.get('candidates', []) if c['skill_id'] in self.skills][:3]
        self._observation_signatures = list(payload.get('observation_signatures', []))[-8:]
        self._input_signatures = list(payload.get('input_signatures', []))[-8:]
        self._evidence_classes = set(payload.get('evidence_classes', []))
        self._last_observation_refs = []
        self._last_target_key = None
        self._target_windows = [
            item for item in payload.get('target_windows', [])
            if isinstance(item, dict) and isinstance(item.get('target'), str)
        ][-MAX_TARGET_WINDOWS:]
        self._decision_acknowledged = bool(payload.get('decision_acknowledged', False))

    def state(self):
        return {
            'seen': sorted(self.seen),
            'candidates': self.current,
            'observation_signatures': self._observation_signatures,
            'input_signatures': self._input_signatures,
            'evidence_classes': sorted(self._evidence_classes),
            'target_windows': self._target_windows,
            'decision_acknowledged': self._decision_acknowledged,
        }

    def reset_for_strategy(self) -> None:
        """Drop stale candidates and evidence when a new strategy revision starts."""
        self.current = []
        self._observation_signatures = []
        self._input_signatures = []
        self._evidence_classes = set()
        self._last_observation_classes = set()
        self._last_observation_refs = []
        self._last_target_key = None
        self._target_windows = []
        self._decision_acknowledged = False

    def acknowledge_decision(self) -> None:
        """Record that the Solver handled the current soft checkpoint."""
        self._decision_acknowledged = True

    def evidence_refs_for_target(self, target: str) -> list[str]:
        """Return only persisted Evidence references for one target window."""
        window = next(
            (item for item in self._target_windows if item.get("target") == target),
            None,
        )
        return [
            ref for ref in (window or {}).get("evidence_refs", [])
            if isinstance(ref, str) and ref.strip()
        ][-4:]

    @staticmethod
    def _valid_observation(value: Any) -> bool:
        """Accept only complete tool observations as capability evidence."""
        if not isinstance(value, dict) or value.get("ok") is not True:
            return False
        data = value.get("data", value)
        if not isinstance(data, dict):
            return False
        error = value.get("error") or data.get("error")
        if isinstance(error, dict) and error.get("stage") in INVALID_EVIDENCE_STAGES:
            return False
        if isinstance(error, str) and any(
            marker in error.casefold() for marker in ("timeout", "timed out", "truncated", "unread", "incomplete")
        ):
            return False
        warnings = value.get("warnings")
        if isinstance(warnings, list) and any(
            isinstance(item, dict)
            and str(item.get("code") or "").casefold()
            in {"evidence_persist_failed", "output_unavailable", "result_unread"}
            for item in warnings
        ):
            return False
        if data.get("result_ref") and not any(
            key in data
            for key in ("content", "body", "output", "results", "responses", "summary", "observation")
        ):
            return False
        if CapabilityAwareness._contains_incomplete_marker(data):
            return False
        status = str(data.get("status") or data.get("execution_status") or "").casefold()
        return status not in TERMINAL_FAILURES

    @staticmethod
    def _contains_incomplete_marker(value: Any) -> bool:
        if isinstance(value, dict):
            error_text = str(value.get("error") or "").casefold()
            if any(marker in error_text for marker in ("timeout", "timed out", "truncated", "unread", "incomplete")):
                return True
            if any(bool(value.get(key)) for key in ("outcome_unknown", "timed_out", "truncated", "output_incomplete")):
                return True
            if any(value.get(key) is False for key in ("complete", "body_complete", "output_available")):
                return True
            for key in ("status", "execution_status", "outcome", "result_state"):
                if str(value.get(key) or "").casefold() in TERMINAL_FAILURES:
                    return True
            return any(CapabilityAwareness._contains_incomplete_marker(item) for item in value.values())
        if isinstance(value, list):
            return any(CapabilityAwareness._contains_incomplete_marker(item) for item in value)
        return False

    @staticmethod
    def _classify_evidence(text: str) -> set[str]:
        lowered = text.casefold()
        classes: set[str] = set()
        if (
            re.search(r"\b[45]\d{2}\b", lowered)
            or "5xx" in lowered
            or "internal server error" in lowered
            or "页面报错" in lowered
        ):
            classes.add("error_response")
        if (
            "cookie" in lowered
            or "redirect" in lowered
            or "location" in lowered
            or re.search(r"\b302\b", lowered)
            or "认证" in lowered
            or "登录" in lowered
        ):
            classes.add("state_change")
        if (
            "differential" in lowered
            or "input difference" in lowered
            or "parameter difference" in lowered
            or "对照" in lowered
            or "差异" in lowered
        ):
            classes.add("input_difference")
        if (
            "database error" in lowered
            or "sql syntax error" in lowered
            or "quoted string not properly terminated" in lowered
            or "you have an error in your sql syntax" in lowered
            or "sqlite error" in lowered
            or "mysql error" in lowered
            or "postgresql error" in lowered
            or "数据库报错" in lowered
            or "数据库读取" in lowered
        ):
            classes.add("database_signal")
        if (
            "file read" in lowered
            or "command execution" in lowered
            or "admin session" in lowered
            or "文件读取" in lowered
            or "命令执行" in lowered
            or "管理员会话" in lowered
        ):
            classes.add("capability_change")
        return classes

    @property
    def decision_due(self) -> bool:
        """Whether the Agent should make an explicit Skill decision."""
        return bool(
            any(
                candidate["skill_id"] not in self.active()
                and self._candidate_ready(candidate["skill_id"])
                for candidate in self.current
            )
            and not self._decision_acknowledged
        )

    def _candidate_ready(self, skill_id: str) -> bool:
        if not self._target_windows:
            return False
        if skill_id == "execution/sqli-sql-injection":
            return any(
                bool(window.get("input_changed"))
                and (
                    "error_response" in window.get("classes", [])
                    or "database_signal" in window.get("classes", [])
                    or "response_difference" in window.get("classes", [])
                )
                for window in self._target_windows
            )
        if skill_id == "common/web-ctf-flow":
            if any("login_surface" in window.get("classes", []) for window in self._target_windows):
                return True
            observations = sum(int(window.get("count", 0)) for window in self._target_windows)
            classes = {item for window in self._target_windows for item in window.get("classes", [])}
            return observations >= 2 and "state_change" in classes
        return len(self._observation_signatures) >= 2 and len(self._evidence_classes) >= 2

    def _candidate_basis(self, skill_id: str) -> list[str]:
        classes = {item for window in self._target_windows for item in window.get("classes", [])}
        if skill_id == "execution/sqli-sql-injection":
            return sorted(classes & {"input_difference", "response_difference", "error_response", "database_signal"})
        if skill_id == "common/web-ctf-flow":
            return sorted(classes & {"error_response", "state_change", "login_surface"})
        return sorted(classes)

    @classmethod
    def _is_login_surface(cls, name: str, arguments: Any) -> bool:
        """Recognize structured login targets without inspecting shell text or values."""
        if name not in LOGIN_EVIDENCE_TOOLS:
            return False
        value = cls._argument_value(arguments)

        def field_keys(item: Any) -> set[str]:
            if not isinstance(item, dict):
                return set()
            keys: set[str] = set()
            for candidate in (
                item.get("query"), item.get("json"), item.get("form"),
                item.get("params"), item.get("data"),
            ):
                if isinstance(candidate, dict):
                    keys.update(str(key).casefold() for key in candidate)
            body = item.get("body")
            if isinstance(body, dict) and isinstance(body.get("value"), dict):
                keys.update(str(key).casefold() for key in body["value"])
            return keys

        def request_matches(item: Any) -> bool:
            if not isinstance(item, dict):
                return False
            url = str(item.get("url", ""))
            path = urlsplit(url).path.casefold().rstrip("/")
            if path and path.split("/")[-1] in LOGIN_PATH_SEGMENTS:
                return True
            if "/auth/login" in path:
                return True
            keys = field_keys(item)
            return bool(keys & LOGIN_IDENTITY_KEYS) and bool(keys & LOGIN_SECRET_KEYS)

        if name == "system_http_probe" and isinstance(value, dict):
            cases = value.get("cases")
            return isinstance(cases, list) and any(request_matches(case) for case in cases)
        if name == "system_http_replay" and isinstance(value, dict):
            return request_matches(value.get("overrides", {}))
        return request_matches(value)

    @staticmethod
    def _response_signal(result: Any, tool_name: str | None = None) -> str:
        """Extract response evidence without command arguments or tool names."""
        data = result.get("data", result) if isinstance(result, dict) else result
        if not isinstance(data, dict):
            return ""
        selected: dict[str, Any] = {}
        for key, value in data.items():
            if str(key).casefold() in RESPONSE_FIELDS:
                if tool_name in {"system_shell", "system_task_output"} and str(key).casefold() == "output":
                    # Shell output is unstructured and often contains local
                    # paths or command text. Only retain a response block
                    # when it carries an explicit HTTP status line.
                    if not isinstance(value, str):
                        continue
                    match = re.search(r"(?im)^HTTP/\d(?:\.\d)?\s+\d{3}\b", value)
                    if match is None:
                        continue
                    value = value[match.start():]
                selected[key] = value
        return signal_text(selected)

    @staticmethod
    def _has_structured_state_change(data: Any, tool_name: str | None = None) -> bool:
        """Require a response field, rather than body prose, for state evidence."""
        if tool_name in {"system_shell", "system_task_output"}:
            output = data.get("output") if isinstance(data, dict) else None
            if isinstance(output, str) and re.search(r"(?im)^HTTP/\d(?:\.\d)?\s+3\d{2}\b", output):
                return True

        def visit(value: Any) -> bool:
            if isinstance(value, dict):
                for key, child in value.items():
                    lowered = str(key).casefold()
                    if lowered in STATE_FIELDS and child not in (None, "", [], {}, False):
                        return True
                    if lowered in {"status_code", "initial_status_code"}:
                        try:
                            if 300 <= int(child) < 400:
                                return True
                        except (TypeError, ValueError):
                            pass
                    if lowered in {"status", "execution_status"} and re.search(r"\b3\d{2}\b", str(child)):
                        return True
                    if visit(child):
                        return True
            elif isinstance(value, list):
                return any(visit(item) for item in value)
            return False

        return visit(data)

    @staticmethod
    def _argument_value(arguments: Any) -> Any:
        if hasattr(arguments, "model_dump"):
            return arguments.model_dump(mode="json")
        return arguments if isinstance(arguments, (dict, list, str, int, float, bool)) or arguments is None else str(arguments)

    @classmethod
    def _target_fingerprint(cls, name: str, arguments: Any) -> str | None:
        if name not in INPUT_DIFFERENTIAL_TOOLS and name != "system_web_path_probe":
            return None
        value = cls._argument_value(arguments)
        if not isinstance(value, dict):
            return None

        def request_shape(item: Any) -> dict[str, Any]:
            if not isinstance(item, dict):
                return {"value_type": type(item).__name__}
            url = str(item.get("url", ""))
            parsed = urlsplit(url)
            query_names = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
            body = item.get("body")
            body_shape: Any = None
            if isinstance(body, dict):
                body_shape = {"type": body.get("type"), "keys": sorted((body.get("value") or {}).keys()) if isinstance(body.get("value"), dict) else None}
            return {
                "method": str(item.get("method", "GET")).upper(),
                "scheme": parsed.scheme.casefold(),
                "host": parsed.netloc.casefold(),
                "path": parsed.path or "/",
                "query_names": query_names,
                "query_keys": sorted((item.get("query") or {}).keys()) if isinstance(item.get("query"), dict) else [],
                "body": body_shape,
            }

        if name == "system_http_replay":
            # A replay references an owned request rather than repeating its
            # URL in the call. The owned interaction/request pair is the
            # stable target; override values contribute only their shape.
            shape = {
                "interaction_id": value.get("interaction_id"),
                "request_id": value.get("request_id"),
                "override": request_shape(value.get("overrides", {})),
            }
        elif name == "system_http_probe":
            cases = value.get("cases")
            shape = [request_shape(case) for case in cases] if isinstance(cases, list) else request_shape(value)
        elif name == "system_web_path_probe":
            parsed = urlsplit(str(value.get("url", "")))
            shape = {
                "method": str(value.get("method", "GET")).upper(),
                "scheme": parsed.scheme.casefold(),
                "host": parsed.netloc.casefold(),
                "path": parsed.path or "/",
                "profile": value.get("profile"),
            }
        else:
            shape = request_shape(value)
        encoded = json.dumps({"tool": name, "shape": shape}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode()).hexdigest()

    @classmethod
    def _input_fingerprint(cls, name: str, arguments: Any) -> str:
        value = cls._argument_value(arguments)
        if name in INPUT_DIFFERENTIAL_TOOLS and isinstance(value, dict):
            def input_shape(item: Any) -> Any:
                if not isinstance(item, dict):
                    return item
                # Cookies, auth handles and transport metadata describe the
                # session. They must not masquerade as a changed injection
                # parameter; query/body values remain part of the experiment.
                return {
                    "method": item.get("method", "GET"),
                    "url": item.get("url", ""),
                    "query": item.get("query", {}),
                    "body": item.get("body"),
                    "input": item.get("input"),
                }

            if name == "system_http_replay":
                value = {
                    "interaction_id": value.get("interaction_id"),
                    "request_id": value.get("request_id"),
                    "overrides": input_shape(value.get("overrides", {})),
                }
            elif name == "system_http_probe" and isinstance(value.get("cases"), list):
                value = {
                    "cases": [input_shape(case) for case in value["cases"]],
                }
            else:
                value = input_shape(value)
        encoded = json.dumps(
            {"tool": name, "arguments": value},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(encoded.encode()).hexdigest()

    def _record_observation(self, name: str, result: Any, arguments: Any) -> bool:
        self._last_observation_classes = set()
        self._last_observation_refs = []
        self._last_target_key = None
        if not self._valid_observation(result):
            return False
        text = self._response_signal(result, name)
        # ``signal_text`` intentionally ignores scalar metadata. Include only
        # response-state fields needed for generic evidence classification; do
        # not copy arbitrary headers, cookies or secrets into awareness state.
        data = result.get("data", result) if isinstance(result, dict) else {}
        if isinstance(data, dict):
            for key in ("status_code", "initial_status_code", "status", "execution_status", "location", "redirect_chain"):
                if key in data:
                    text += f"\n{key}:{data[key]}"
        target_key = self._target_fingerprint(name, arguments) or f"tool:{name}"
        self._last_target_key = target_key
        input_key = self._input_fingerprint(name, arguments)
        response_key = hashlib.sha256(text.encode()).hexdigest()
        signature = hashlib.sha256(
            json.dumps(
                {"target": target_key, "input": input_key, "response": response_key},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if signature in self._observation_signatures:
            return False
        window = next((item for item in self._target_windows if item.get("target") == target_key), None)
        if window is None:
            window = {
                "target": target_key,
                "count": 0,
                "inputs": [],
                "responses": [],
                "classes": [],
                "input_changed": False,
                "evidence_refs": [],
            }
            self._target_windows.append(window)
            self._target_windows = self._target_windows[-MAX_TARGET_WINDOWS:]
        input_changed = name in INPUT_DIFFERENTIAL_TOOLS and bool(window["inputs"]) and input_key not in window["inputs"]
        response_changed = bool(window["responses"]) and response_key not in window["responses"]
        if name == "system_http_probe":
            probe_args = self._argument_value(arguments)
            cases = probe_args.get("cases") if isinstance(probe_args, dict) else None
            if isinstance(cases, list) and len(cases) > 1:
                case_inputs = {
                    json.dumps(case, ensure_ascii=False, sort_keys=True, default=str)
                    for case in cases
                }
                input_changed = input_changed or len(case_inputs) > 1
                probe_data = data if isinstance(data, dict) else {}
                responses = probe_data.get("responses") or probe_data.get("results")
                if isinstance(responses, list) and len(responses) > 1:
                    response_changed = response_changed or len({
                        hashlib.sha256(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
                        for item in responses
                    }) > 1
        window["count"] = int(window.get("count", 0)) + 1
        if name in INPUT_DIFFERENTIAL_TOOLS and input_key not in window["inputs"]:
            window["inputs"] = [*window["inputs"], input_key][-8:]
            self._input_signatures.append(f"{target_key}:{input_key}")
            self._input_signatures = self._input_signatures[-8:]
        if response_key not in window["responses"]:
            window["responses"] = [*window["responses"], response_key][-8:]
        self._observation_signatures.append(signature)
        self._observation_signatures = self._observation_signatures[-8:]
        classes = self._classify_evidence(text)
        if self._is_login_surface(name, arguments):
            classes.add("login_surface")
        if "state_change" in classes and not self._has_structured_state_change(data, name):
            classes.discard("state_change")
        if input_changed:
            classes.add("input_difference")
            window["input_changed"] = True
        if response_changed:
            classes.add("response_difference")
        window["classes"] = sorted(set(window.get("classes", [])) | classes)
        raw_refs = data.get("evidence_refs", []) if isinstance(data, dict) else []
        refs = [ref for ref in raw_refs if isinstance(ref, str) and ref.strip()][:4]
        if refs:
            window["evidence_refs"] = list(dict.fromkeys([
                *window.get("evidence_refs", []), *refs
            ]))[-4:]
            self._last_observation_refs = refs
        self._evidence_classes.update(classes)
        self._last_observation_classes = classes
        self._decision_acknowledged = False
        return True

    def ingest(self, value, *, source, round_number, require_gate: bool = False):
        text = signal_text(value)
        # Never use injected directory/Skill blocks as observations.
        text = re.sub(r'<(active_skills|capability_directory|capability_hints|capability_decision)>.*?</\1>', '', text, flags=re.S)
        text = re.sub(r'(?:execution|common|challenge)/[a-z0-9-]+', '', text)
        active = self.active()
        ranked = {s['skill_id']: i for i, s in enumerate(self.context.catalog.search(self.context.role, ' '.join(text.split())[:500], limit=5))} if text.strip() else {}
        additions = []
        for sid, (aliases, _) in ROUTES.items():
            if sid not in self.skills or sid in active:
                continue
            matches = sorted({a for a in aliases if contains(text, a)})
            fresh = [a for a in matches if f'{sid}:{a}' not in self.seen]
            if fresh and (not require_gate or self._candidate_ready(sid)):
                target_window = next(
                    (window for window in self._target_windows
                     if window.get('target') == self._last_target_key),
                    None,
                )
                target_refs = [
                    ref for ref in (target_window or {}).get('evidence_refs', [])
                    if isinstance(ref, str) and ref.strip()
                ][-4:]
                additions.append({
                    'skill_id': sid,
                    'matches': fresh,
                    'source': source,
                    'signal_sha256': hashlib.sha256(text.encode()).hexdigest(),
                    'detected_round': round_number,
                    'evidence_basis': self._candidate_basis(sid),
                    'evidence_refs': target_refs,
                })
        additions.sort(key=lambda c: (-len(c['matches']), ranked.get(c['skill_id'], 100), c['skill_id']))
        additions = additions[:3]
        for c in additions:
            self.seen.update(f"{c['skill_id']}:{a}" for a in c['matches'])
        replaced = {c['skill_id'] for c in additions}
        self.current = (additions + [c for c in self.current if c['skill_id'] not in active | replaced])[:3]
        return additions

    def ingest_tool(self, name, result, arguments, *, source, round_number):
        if name == "solver_review":
            # The Solver explicitly chose to defer Skill loading and recorded
            # why; new evidence will reopen the checkpoint.
            if self._valid_observation(result):
                self._decision_acknowledged = True
            return []
        if name in SKIP_TOOLS:
            return []
        # Local file reads are state inspection, not target observations. Keep
        # them out of the evidence stream without inspecting their paths or
        # arguments (which may contain arbitrary text).
        if name == 'system_read_file':
            return []
        if name not in HTTP_EVIDENCE_TOOLS:
            return []
        if not self._record_observation(name, result, arguments):
            return []
        # Input conditions are part of an auditable observation: include their
        # values for generic matching, while the persisted candidate stores
        # only bounded aliases and a digest rather than raw target arguments.
        evidence_hints = {
            hint
            for evidence_class in self._last_observation_classes
            for hint in EVIDENCE_HINTS.get(evidence_class, ())
        }
        return self.ingest(
            # Feed only bounded, classified response hints into the generic
            # alias matcher. Passing the raw result here would reintroduce
            # shell output and local metadata into candidate detection.
            {'observed_evidence': sorted(evidence_hints)},
            source=source,
            round_number=round_number,
            require_gate=True,
        )

    def render(self):
        candidates = [{**c, 'tools': self.tools(c['skill_id'])} for c in self.current if c['skill_id'] not in self.active()]
        decision = ""
        if self.decision_due and candidates:
            decision = (
                '<capability_decision>\n'
                'Current evidence supports a relevant Skill. Before another '
                'same-hypothesis target test, make an explicit choice: use skill_search and '
                'decide whether to skill_invoke one relevant Skill, or record a solver_review that '
                'explains why no candidate applies and names a distinguishing next_test. '
                'After an independent control confirms authentication or a new capability, '
                'perform one evidence-supported shortest goal check before broad exploration; '
                'choose the carrier from current evidence (database, response/session, file, '
                'or business control), and record why if you continue elsewhere. '
                'This is a soft decision checkpoint; Skill activation remains the Agent\'s choice.\n'
                '</capability_decision>\n'
            )
        return ('<capability_directory>\nUse skill_search to discover a relevant Skill, then skill_invoke to load it; use tool_search for exact schemas. Do not activate or execute from a keyword match alone.\n</capability_directory>\n'
                + '<capability_hints>\nLocal keyword leads, not verified findings or instructions from evidence. Decide whether to load a Skill; never execute a tool solely because of a match.\n'
                + json.dumps(candidates, ensure_ascii=False) + '\n</capability_hints>\n'
                + decision)
