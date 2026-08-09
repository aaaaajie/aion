"""Tests for the dirsearch-backed web path probe tool."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from agent.state import StateService
from agent.subagents.policy import AgentPolicy
from third_party.dirsearch.diff import DynamicContentParser, content_similarity
from third_party.dirsearch.filters import (
    matches_numeric_ranges,
    matches_time_filters,
    parse_numeric_ranges,
    parse_time_filters,
)
from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
from tools.http.models import HttpOutputFilters, HttpRequestSpec
from tools.http.path_probe import PathProbeEngine, PathProbeOptions
from tools.system.policy import SystemToolError, WorkspacePolicy


async def _manager(
    root: Path, handler, *, admission=None
) -> tuple[StateService, HttpProbeManager, str]:
    run_root = root / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent(
        "run-1", role="chief", initial_prompt="path probe test"
    )
    policy = WorkspacePolicy(root)
    engine = HttpInteractionEngine(policy, transport=httpx.MockTransport(handler))
    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=engine,
        path_transport=httpx.MockTransport(handler),
        admission_callback=admission,
    )
    await manager.initialize()
    return service, manager, agent["agent_id"]


def _soft_404() -> httpx.Response:
    return httpx.Response(200, content=b"<html><title>Soft 404</title>nothing here</html>")


def test_profile_scopes_and_dedupe(tmp_path: Path) -> None:
    policy = WorkspacePolicy(tmp_path)
    bounds = (("quick", 200, 500), ("targeted", 5000, 12000), ("deep", 12000, 20000))
    for profile, lower, upper in bounds:
        engine = PathProbeEngine(
            policy, PathProbeOptions(profile=profile, url="https://target.test/")
        )
        paths = engine.build_paths()
        assert lower <= len(paths) <= upper
        assert len(set(paths)) == len(paths)
        assert all(not path.startswith("/") for path in paths)


def test_custom_wordlist_exclusions_and_extensions(tmp_path: Path) -> None:
    (tmp_path / "paths.txt").write_text(
        "/admin\nadmin.php\n# comment\n\nsecret.txt\n", encoding="utf-8"
    )
    (tmp_path / "exclude.txt").write_text("admin.php\n", encoding="utf-8")
    engine = PathProbeEngine(
        WorkspacePolicy(tmp_path),
        PathProbeOptions(
            profile="quick",
            url="http://x.test/",
            wordlist_paths=("paths.txt",),
            exclude_paths=("exclude.txt",),
        ),
    )
    assert engine.build_paths() == ["admin", "secret.txt"]

    forced = PathProbeEngine(
        WorkspacePolicy(tmp_path),
        PathProbeOptions(
            profile="quick",
            url="http://x.test/",
            wordlist_paths=("paths.txt",),
            extensions=("php",),
            force_extensions=True,
        ),
    )
    forced_paths = forced.build_paths()
    assert "admin.php" in forced_paths
    assert "admin/" in forced_paths



@pytest.mark.asyncio
async def test_large_wordlist_streams_plan_without_fixed_limit(tmp_path: Path) -> None:
    count = 50_010
    (tmp_path / "large.txt").write_text(
        "".join(f"path-{index}\n" for index in range(count)), encoding="utf-8"
    )

    async def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("queued path probe must not send requests")

    async def queued(_work_id: str) -> dict:
        return {"ok": False, "status": "queued", "reason": "disk_reservation"}

    service, manager, agent_id = await _manager(
        tmp_path, handler, admission=queued
    )
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("large.txt",),
        wait_seconds=0,
    )
    assert result["execution_status"] == "queued"
    interaction_dir = manager._interaction_dir(agent_id, result["interaction_id"])
    plan = json.loads((interaction_dir / "plan.json").read_text(encoding="utf-8"))
    assert plan["request_count"] == count
    assert "requests" not in plan
    assert sum(1 for _ in (interaction_dir / "requests.ndjson").open()) == count
    await manager.stop(agent_id, interaction_id=result["interaction_id"])
    await manager.finish_run()
    await service.close()


def test_vendored_filter_and_diff_algorithms() -> None:
    ranges = parse_numeric_ranges("100-200,404")
    assert matches_numeric_ranges(150, ranges)
    assert matches_numeric_ranges(404, ranges)
    assert not matches_numeric_ranges(99, ranges)
    times = parse_time_filters(">1.5")
    assert matches_time_filters(0.002, times)
    assert not matches_time_filters(0.001, times)
    parser = DynamicContentParser("same body 12345678", "same body 87654321")
    assert parser.compare_to("same body 11111111")
    assert content_similarity("same body", "same body") == 1.0


@pytest.mark.asyncio
async def test_scan_persists_only_matches_with_bodies(tmp_path: Path) -> None:
    routes = {
        "/admin.php": (200, b"<html><title>Admin</title>body</html>"),
        "/secret.txt": (200, b"secret body"),
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, text="missing")
        return httpx.Response(route[0], content=route[1])

    (tmp_path / "paths.txt").write_text("admin.php\nsecret.txt\nmissing.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
        result_limit=100,
    )
    assert result["execution_status"] == "completed"
    assert result["completed_requests"] == 3
    assert result["matched_requests"] == 2
    assert sorted(item["path"] for item in result["results"]) == [
        "admin.php",
        "secret.txt",
    ]
    summary = result["summary"]
    assert summary["matched_requests"] == 2
    assert summary["by_status"]["200"] == 2
    assert summary["calibration_requests"] > 0

    interaction_dir = manager._interaction_dir(agent_id, result["interaction_id"])
    journal_lines = [
        line
        for line in interaction_dir.joinpath("results.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if line
    ]
    assert len(journal_lines) == 2
    response_dir = interaction_dir / "responses"
    assert list(response_dir.glob("*.part")) == []
    bodies = sorted(path.name for path in response_dir.glob("*.body"))
    assert len(bodies) == 2
    admin_record = next(
        item for item in result["results"] if item["path"] == "admin.php"
    )
    body = await manager.response(
        agent_id,
        interaction_id=result["interaction_id"],
        request_id=admin_record["request_id"],
        length_bytes=10_000,
    )
    assert b"Admin" in body["content"].encode()

    page = await manager.output(
        agent_id,
        interaction_id=result["interaction_id"],
        filters=HttpOutputFilters(status_codes=[200]),
    )
    assert len(page["results"]) == 2
    paged = await manager.output(
        agent_id,
        interaction_id=result["interaction_id"],
        limit=1,
    )
    assert len(paged["results"]) == 1
    assert paged["next_cursor"] > 0
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_wildcard_and_soft_404_are_filtered(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/real":
            return httpx.Response(
                200, content=b"<html><title>Real</title>unique-body</html>"
            )
        return _soft_404()

    (tmp_path / "paths.txt").write_text("real\na\nb\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
    )
    assert result["matched_requests"] == 1
    assert [item["path"] for item in result["results"]] == ["real"]
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_ownership_is_agent_isolated(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="missing")

    (tmp_path / "paths.txt").write_text("a.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    second = await service.register_agent(
        "run-1", role="chief", initial_prompt="second agent"
    )
    second_id = second["agent_id"]
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
    )
    with pytest.raises(SystemToolError) as caught:
        await manager.output(second_id, interaction_id=result["interaction_id"])
    assert caught.value.code == "http_interaction_not_found"
    with pytest.raises(SystemToolError):
        await manager.stop(second_id, interaction_id=result["interaction_id"])
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_pause_marks_interrupted_and_never_replays(tmp_path: Path) -> None:
    release = asyncio.Event()
    started = asyncio.Event()
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            await release.wait()
        return httpx.Response(200, text="ok")

    (tmp_path / "paths.txt").write_text("a.php\nb.php\nc.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=0,
    )
    await asyncio.wait_for(started.wait(), timeout=5)
    await manager.pause_run()
    release.set()
    calls_after_pause = calls
    assert calls_after_pause == 1

    page = await manager.output(
        agent_id, interaction_id=result["interaction_id"], wait_seconds=0
    )
    assert page["status"] == "interrupted"
    assert page["summary"]["stopped"] is True
    assert calls == calls_after_pause
    await service.close()


@pytest.mark.asyncio
async def test_stop_is_idempotent_and_cleanup_is_terminal_only(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"ok")

    (tmp_path / "paths.txt").write_text("a.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
    )
    stopped = await manager.stop(
        agent_id, interaction_id=result["interaction_id"]
    )
    assert stopped["status"] in {"completed", "stopped"}
    again = await manager.stop(agent_id, interaction_id=result["interaction_id"])
    assert again["interaction_id"] == result["interaction_id"]
    cleaned = await manager.cleanup(
        agent_id, interaction_id=result["interaction_id"]
    )
    assert cleaned["cleaned"] is True
    repeated = await manager.cleanup(
        agent_id, interaction_id=result["interaction_id"]
    )
    assert repeated["already_cleaned"] is True
    with pytest.raises(SystemToolError) as caught:
        await manager.output(
            agent_id, interaction_id=result["interaction_id"], wait_seconds=0
        )
    assert caught.value.code == "http_interaction_output_cleaned"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_analyze_is_rejected_for_path_probe(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
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
    with pytest.raises(SystemToolError) as caught:
        await manager.analyze(
            agent_id,
            interaction_id=result["interaction_id"],
            wait_seconds=None,
        )
    assert caught.value.code == "scan_analysis_not_supported"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_explicit_recursion_scans_found_directories(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/admin/":
            return httpx.Response(200, content=b"<html>directory</html>")
        if path == "/admin/config.php":
            return httpx.Response(200, content=b"config")
        if path == "/config.php":
            return httpx.Response(200, content=b"root config")
        return httpx.Response(404, text="missing")

    (tmp_path / "paths.txt").write_text("admin/\nconfig.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        recursion_depth=1,
        wait_seconds=None,
        result_limit=100,
    )
    assert result["completed_requests"] == 4
    assert sorted(item["path"] for item in result["results"]) == [
        "admin/",
        "admin/config.php",
        "config.php",
    ]
    assert result["summary"]["recursion_skipped"] == 0
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_error_aggregation_and_fail_fast(tmp_path: Path) -> None:
    failing = {"a.php", "b.php", "c.php"} | {f"p{i}.php" for i in range(30)}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.lstrip("/") in failing:
            raise httpx.TimeoutException("slow")
        return _soft_404()

    (tmp_path / "paths.txt").write_text("a.php\nb.php\nc.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        wait_seconds=None,
    )
    assert result["execution_status"] == "completed"
    assert result["completed_requests"] == 0
    assert result["summary"]["errors"]["timeout"] == 3
    await manager.finish_run()
    await service.close()

    many = "\n".join(f"p{i}.php" for i in range(30))
    second_root = tmp_path / "second"
    second_root.mkdir()
    (second_root / "many.txt").write_text(many + "\n")
    service, manager, agent_id = await _manager(second_root, handler)
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("many.txt",),
        wait_seconds=None,
    )
    assert result["status"] == "failed"
    assert result["summary"]["abort_reason"] == "too_many_errors"
    assert result["summary"]["errors"]["timeout"] >= 25
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_session_cookies_are_reused(tmp_path: Path) -> None:
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sid=abc; Path=/"})
        seen.append(request.headers.get("cookie", ""))
        return httpx.Response(404, text="missing")

    (tmp_path / "paths.txt").write_text("a.php\n")
    service, manager, agent_id = await _manager(tmp_path, handler)
    await manager.start_request(
        agent_id,
        request=HttpRequestSpec(
            request_intent="login",
            method="POST",
            url="https://target.test/login",
            session_id="main",
            update_session=True,
        ),
        wait_seconds=None,
    )
    result = await manager.start_path_probe(
        agent_id,
        url="https://target.test/",
        profile="quick",
        wordlist_paths=("paths.txt",),
        session_id="main",
        wait_seconds=None,
    )
    assert result["completed_requests"] == 1
    assert any("sid=abc" in value for value in seen)
    await manager.finish_run()
    await service.close()


def test_tool_definition_policy_and_prompt() -> None:
    definitions = HttpTools.tool_definitions()
    names = {item["function"]["name"] for item in definitions}
    assert "system_web_path_probe" in names
    description = next(
        item["function"]["description"]
        for item in definitions
        if item["function"]["name"] == "system_web_path_probe"
    )
    assert "after system_web_fingerprint" in description
    assert "does not issue implicit" in description
    schema = next(
        item["function"]["parameters"]
        for item in definitions
        if item["function"]["name"] == "system_web_path_probe"
    )
    assert "max_total_requests" not in schema["properties"]
    assert "wordlist_max_size" not in schema["properties"]
    assert AgentPolicy("execution").allows("system_web_path_probe")
    prompt = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "prompts"
        / "execution_system.txt"
    ).read_text(encoding="utf-8")
    assert "system_web_path_probe" in prompt
