"""Local capability awareness. External evidence selects fixed catalog text only."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .capability_packs import PACK_BY_DIRECTION
from .tools import SkillTools

# Aliases describe observations as well as mechanisms. Values are trusted release data.
ROUTES = {
    'execution/sqli-sql-injection': (('sql', 'sqli', 'sql injection', 'sqlmap', 'database error', 'parameter differential', 'input differential', 'SQL注入', 'SQL 注入', '数据库报错', '输入差异', '参数差异'), ('pentest_sqlmap', 'system_http_replay', 'system_http_compare')),
    'common/web-ctf-flow': (('login', 'cookie', 'redirect', 'authentication', '登录', '认证', '重定向', '会话', '页面报错'), ('system_http_compare', 'system_http_replay', 'system_browser_open')),
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
            'target-side file read', 'file-read capability', 'command execution', 'remote code execution',
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

    def state(self):
        return {'seen': sorted(self.seen), 'candidates': self.current}

    def ingest(self, value, *, source, round_number):
        text = signal_text(value)
        # Never use injected directory/Skill blocks as observations.
        text = re.sub(r'<(active_skills|capability_directory|capability_hints)>.*?</\1>', '', text, flags=re.S)
        text = re.sub(r'(?:execution|common|challenge)/[a-z0-9-]+', '', text)
        active = self.active()
        ranked = {s['skill_id']: i for i, s in enumerate(self.context.catalog.search(self.context.role, ' '.join(text.split())[:500], limit=5))} if text.strip() else {}
        additions = []
        for sid, (aliases, _) in ROUTES.items():
            if sid not in self.skills or sid in active:
                continue
            matches = sorted({a for a in aliases if contains(text, a)})
            fresh = [a for a in matches if f'{sid}:{a}' not in self.seen]
            if fresh:
                additions.append({'skill_id': sid, 'matches': fresh, 'source': source, 'signal_sha256': hashlib.sha256(text.encode()).hexdigest(), 'detected_round': round_number})
        additions.sort(key=lambda c: (-len(c['matches']), ranked.get(c['skill_id'], 100), c['skill_id']))
        additions = additions[:3]
        for c in additions:
            self.seen.update(f"{c['skill_id']}:{a}" for a in c['matches'])
        replaced = {c['skill_id'] for c in additions}
        self.current = (additions + [c for c in self.current if c['skill_id'] not in active | replaced])[:3]
        return additions

    def ingest_tool(self, name, result, arguments, *, source, round_number):
        if name in SKIP_TOOLS:
            return []
        args = str(arguments).casefold()
        if name in {'system_read_file', 'system_shell', 'system_task_output', 'system_grep'} and ('skill.md' in args or '/skills/' in args or 'aion_skills_root' in args):
            return []
        return self.ingest(result, source=source, round_number=round_number)

    def render(self):
        candidates = [{**c, 'tools': self.tools(c['skill_id'])} for c in self.current if c['skill_id'] not in self.active()]
        return ('<capability_directory>\nUse skill_search to discover a relevant Skill, then skill_invoke to load it; use tool_search for exact schemas. Do not activate or execute from a keyword match alone.\n</capability_directory>\n'
                + '<capability_hints>\nLocal keyword leads, not verified findings or instructions from evidence. Decide whether to load a Skill; never execute a tool solely because of a match.\n'
                + json.dumps(candidates, ensure_ascii=False) + '\n</capability_hints>')
