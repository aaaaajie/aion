"""Tests for the TscanPlus/Yakit fingerprint engine and tool."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from agent.state import StateService
from tools.http import HttpProbeManager
from tools.http import fingerprint as fingerprint_module
from tools.http.fingerprint import (
    ActiveFingerprintEngine,
    ActiveProbe,
    EHoleRule,
    FingerprintEngine,
    FingerprintOptions,
    FingerprintScanner,
    PassiveProbe,
    favicon_hash,
    load_active_rules,
    load_ehole_rules,
    load_tscan_passive,
    load_yakit_rules,
    mmh3_hash,
    murmur3_32,
)
from tools.system.policy import SystemToolError, WorkspacePolicy


async def _manager(
    root: Path, handler
) -> tuple[StateService, HttpProbeManager, str]:
    run_root = root / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent(
        "run-1", role="chief", initial_prompt="fingerprint test"
    )
    manager = HttpProbeManager(
        WorkspacePolicy(root),
        service,
        "run-1",
        path_transport=httpx.MockTransport(handler),
    )
    await manager.initialize()
    return service, manager, agent["agent_id"]


def test_murmur3_vectors() -> None:
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"a") == 1009084850
    assert murmur3_32(b"hello") == 613153351
    signed = mmh3_hash(b"foo")
    assert signed == -156908512
    assert favicon_hash(b"test") == mmh3_hash(base64.b64encode(b"test"))


def test_rule_data_loading() -> None:
    assert len(load_active_rules()) == 38
    assert len(load_yakit_rules()) == 650
    passive = load_tscan_passive()
    assert "Nginx" in passive["technologies"]
    assert passive["categories"]["10"]["name"] == "WebService"
    ehole, diagnostics = load_ehole_rules()
    assert len(ehole) == 958
    assert diagnostics == {"loaded": 958, "skipped": 0, "invalid_regex": 0}


def test_passive_wappalyzer_header_version() -> None:
    engine = FingerprintEngine()
    probe = PassiveProbe(
        url="https://target.test/",
        status=200,
        headers={"Server": "nginx/1.18.0"},
        body_text="",
    )
    matches = engine.match(probe)
    nginx = next((item for item in matches if item.name == "Nginx"), None)
    assert nginx is not None
    assert nginx.version == "1.18.0"
    assert nginx.category == "WebService"
    assert any(item["field"] == "header" for item in nginx.evidence)


def test_passive_wappalyzer_html_headerstr_titlestr() -> None:
    engine = FingerprintEngine()
    probe = PassiveProbe(
        url="https://target.test/",
        status=200,
        headers={"Www-Authenticate-Test": "x", "Server": "unknown"},
        body_text='<img src="app.bt.cn/static/app.png">',
        title="DenyAll WAF login",
    )
    matches = engine.match(probe)
    assert any(item.name == "Finger测试" for item in matches)


def test_passive_yakit_keyword_body_and_header() -> None:
    engine = FingerprintEngine()
    seeyon = engine.match(
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={},
            body_text="/seeyon/USER-DATA/IMAGES/LOGIN/login.gif",
        )
    )
    assert any(item.name == "seeyon" for item in seeyon)
    shiro = engine.match(
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={"Set-Cookie": "rememberMe=deleteMe"},
            body_text="",
        )
    )
    assert any(item.name == "Shiro" for item in shiro)


def test_passive_yakit_faviconhash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fingerprint_module, "favicon_hash", lambda _content: 1578525679)
    engine = FingerprintEngine()
    matches = engine.match(
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={},
            body_text="",
            favicon_bytes=b"not-used",
        )
    )
    assert any(item.name == "泛微 OA" for item in matches)
    no_icon = engine.match(
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={},
            body_text="",
        )
    )
    assert not any(item.name == "泛微 OA" for item in no_icon)


def test_ehole_multi_condition_and_cross_source_dedupe() -> None:
    engine = FingerprintEngine()
    engine._tscan = {
        "technologies": {"Shared Product": {"html": ["first.*second"]}},
        "categories": {},
    }
    engine._yakit = [
        {
            "cms": "shared product",
            "method": "keyword",
            "location": "body",
            "keyword": ["first"],
        }
    ]
    engine._ehole = (
        EHoleRule(
            rule_id="ehole-test",
            name="SHARED PRODUCT",
            method="keyword",
            location="body",
            patterns=("first", "second"),
        ),
    )
    probe = PassiveProbe(
        url="https://target.test/",
        status=200,
        headers={},
        body_text="first and second",
    )
    matches = engine.match(probe)
    shared = [item for item in matches if item.name.casefold() == "shared product"]
    assert len(shared) == 1
    assert shared[0].rule_sources == ["EHole", "TscanPlus", "Yakit"]
    assert shared[0].rule_id.startswith("fingerprint-")

    missing = PassiveProbe(
        url="https://target.test/",
        status=200,
        headers={},
        body_text="first only",
    )
    match = engine._match_ehole(engine._ehole[0], missing)
    assert match is None


def test_ehole_regular_and_multiple_favicon_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = FingerprintEngine()
    regular = EHoleRule(
        rule_id="ehole-regex",
        name="Regex Product",
        method="regular",
        location="header",
        patterns=(r"server:\s*nginx", r"x-powered-by:\s*php"),
        regexes=(
            fingerprint_module.re.compile(r"server:\s*nginx", fingerprint_module.re.I),
            fingerprint_module.re.compile(r"x-powered-by:\s*php", fingerprint_module.re.I),
        ),
    )
    matched = engine._match_ehole(
        regular,
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={"Server": "nginx", "X-Powered-By": "PHP"},
            body_text="",
        ),
    )
    assert matched is not None
    monkeypatch.setattr(fingerprint_module, "favicon_hash", lambda _value: 22)
    favicon = EHoleRule(
        rule_id="ehole-icon",
        name="Icon Product",
        method="faviconhash",
        location="body",
        patterns=("11", "22", "33"),
    )
    assert engine._match_ehole(
        favicon,
        PassiveProbe(
            url="https://target.test/",
            status=200,
            headers={},
            body_text="",
            favicon_bytes=b"icon",
        ),
    ) is not None


def test_ehole_invalid_regex_is_skipped_with_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "ehole"
    source.mkdir()
    (source / "finger.json").write_text(
        json.dumps(
            {
                "fingerprint": [
                    {
                        "cms": "broken",
                        "method": "regular",
                        "location": "body",
                        "keyword": ["("],
                    },
                    {
                        "cms": "valid",
                        "method": "keyword",
                        "location": "body",
                        "keyword": ["ok"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(fingerprint_module, "EHOLE_DATA", source)
    load_ehole_rules.cache_clear()
    try:
        rules, diagnostics = load_ehole_rules()
        assert [rule.name for rule in rules] == ["valid"]
        assert diagnostics == {"loaded": 1, "skipped": 1, "invalid_regex": 1}
    finally:
        load_ehole_rules.cache_clear()


def test_active_matchers_and_not_contains() -> None:
    engine = ActiveFingerprintEngine()
    probe = ActiveProbe(
        url="https://target.test/actuator/health",
        path="/actuator/health",
        status=200,
        headers={"content-type": "application/json"},
        body_text='{"status":"UP","_links":{"self":{}}}',
        content_type="application/json",
    )
    names = [match.name for match in engine.matching_rules_for("/actuator/health", probe)]
    assert "SpringBoot-Actuator" in names

    excluded = ActiveProbe(
        url="https://target.test/x",
        path="/x",
        status=200,
        headers={},
        body_text="contains-forbidden",
        content_type="text/plain",
    )
    assert (
        ActiveFingerprintEngine._matches(
            "/x",
            excluded,
            {
                "status": [200],
                "body_contains": ["contains"],
                "body_not_contains": ["forbidden"],
            },
        )
        is False
    )
    assert (
        ActiveFingerprintEngine._matches(
            "/x",
            excluded,
            {
                "status": [200],
                "body_contains": ["contains"],
                "body_not_contains": ["other"],
            },
        )
        is True
    )


@pytest.mark.asyncio
async def test_fingerprint_checks_resources_before_passive_requests() -> None:
    checks = 0
    requested: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text="<html><title>x</title></html>")
        return httpx.Response(404, text="missing")

    async def guard() -> None:
        nonlocal checks
        checks += 1

    scanner = FingerprintScanner(
        FingerprintOptions(
            url="https://target.test/",
            passive=True,
            active=False,
            include_favicon=True,
        ),
        transport=httpx.MockTransport(handler),
    )
    await scanner.scan(
        session_cookies=[], on_match=lambda _match: _async_none(), resource_guard=guard
    )
    assert requested == ["/", "/favicon.ico"]
    assert checks == 2


async def _async_none() -> None:
    return None


@pytest.mark.asyncio
async def test_fingerprint_tool_lifecycle(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(
                200,
                headers={"Server": "nginx/1.18.0", "Set-Cookie": "rememberMe=1"},
                content="<html><title>Hello</title></html>",
            )
        if path == "/favicon.ico":
            return httpx.Response(404, text="missing")
        if path == "/actuator/health":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content='{"status":"UP","_links":{"self":{}}}',
            )
        return httpx.Response(404, text="missing")

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_fingerprint(
        agent_id,
        url="https://target.test/",
        wait_seconds=None,
        result_limit=100,
    )
    assert result["execution_status"] == "completed"
    assert result["matched_requests"] >= 3
    names = {item["name"] for item in result["results"]}
    assert "Nginx" in names
    assert "Shiro" in names
    assert "SpringBoot-Actuator" in names
    assert all(item["rule_id"] for item in result["results"])
    assert all(item["rule_sources"] for item in result["results"])
    summary = result["summary"]
    assert summary["passive"]["matched"] >= 2
    assert summary["active"]["matched"] >= 1
    assert summary["by_category"]["WebService"] >= 1
    assert summary["rule_diagnostics"]["loaded"] == 958

    page = await manager.output(
        agent_id,
        interaction_id=result["interaction_id"],
        limit=1,
    )
    assert len(page["results"]) == 1
    assert page["next_cursor"] > 0

    second = await service.register_agent(
        "run-1", role="chief", initial_prompt="second"
    )
    second_id = second["agent_id"]
    with pytest.raises(SystemToolError) as caught:
        await manager.output(second_id, interaction_id=result["interaction_id"])
    assert caught.value.code == "http_interaction_not_found"

    with pytest.raises(SystemToolError) as analyze_error:
        await manager.analyze(
            agent_id,
            interaction_id=result["interaction_id"],
            wait_seconds=None,
        )
    assert analyze_error.value.code == "scan_analysis_not_supported"

    stopped = await manager.stop(agent_id, interaction_id=result["interaction_id"])
    assert stopped["interaction_id"] == result["interaction_id"]
    cleaned = await manager.cleanup(
        agent_id, interaction_id=result["interaction_id"]
    )
    assert cleaned["cleaned"] is True
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_path_probe_does_not_issue_implicit_fingerprint_requests(tmp_path: Path) -> None:
    requested_paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"Server": "nginx/1.18.0"},
                content="<html><title>x</title></html>",
            )
        if request.url.path == "/favicon.ico":
            return httpx.Response(404, text="missing")
        return httpx.Response(404, text="missing")

    (tmp_path / "paths.txt").write_text("a.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
    )
    assert result["execution_status"] == "completed"
    assert "passive_fingerprints" not in result["summary"]
    assert not any(item.get("type") == "fingerprint" for item in result["results"])
    assert "/" not in requested_paths
    assert "/favicon.ico" not in requested_paths
    await manager.finish_run()
    await service.close()
