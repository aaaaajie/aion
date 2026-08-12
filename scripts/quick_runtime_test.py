"""Run one controlled, env-backed AION Runtime smoke test.

Run from the project root with::

    ./.venv/bin/python scripts/quick_runtime_test.py

Edit ``CHALLENGES`` below to describe local CTF challenge slots. Each slot uses
``name``, ``description``, ``address`` and ``mission``; no platform
``unique_code`` or manual container start is required. Add more dictionaries
to that list when testing multiple challenges. The default mode uses the
configured LLM and exercises the complete Chief -> Challenge -> Execution
path. The test runner removes state-changing benchmark tools. Execution Agents
keep their complete system-tool surface, including ``system_shell``; the
prompt supplies the configured CTF addresses and assigned mission.

This script never connects to a competition platform, starts a target, requests
platform hints, or submits flags. Closing the logical local challenge slot is
opt-in with ``--close-on-exit``. The test stays alive until every configured
challenge has had its child reports consumed by the Challenge Agent, an
explicit ``--wait-seconds`` deadline is reached, or Ctrl-C is pressed. A local
read-only monitor starts by default; use ``--no-monitor`` for unattended
execution or ``--monitor-exit-on-complete`` for CI.

Pass ``--vpn`` to start and own the single OpenVPN profile under
``config/vpn`` before the Runtime accesses its local Benchmark adapter. Run
``sudo -v`` first; use ``--vpn-config PATH`` when more than one profile exists.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import AgentSettings
from agent.runtime import AgentRuntime
from agent.runner import AgentRunner, ToolRegistry
from scripts.network_manager import VPNManager, discover_vpn_config
from scripts.runtime_web import RuntimeMonitor


# Local-only challenge slots. The name becomes the internal SQLite challenge
# key and the address is passed to Challenge/Execution Agents as target
# context. Add more dictionaries to test multiple challenge branches.
CHALLENGES: list[dict[str, Any]] = [
    {
        "name": "test",
        "description": "ctf-test",
        "address": "http://www.dlhayashi.com/",
        "mission": (
            "Test the configured CTF address with the available tools. Do not "
            "request hints, submit flags, or close the challenge."
        ),
    },
]


class PassiveRunner:
    """Keep an Agent alive without making an LLM request when requested.

    Runtime and Supervisor still persist registration, running state, and
    heartbeat information. This makes the default test deterministic while
    the local challenge catalog remains fully offline.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self._stopped = False

    async def run(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise
        return {"status": "stopped"}

    async def close(self) -> None:
        self._stopped = True


class GuardedAgentRunner(AgentRunner):
    """Use the configured model with test-only local-effect instructions."""

    async def run_session(self, prompt: str | None = None, **kwargs: Any) -> Any:
        store = kwargs.get("store")
        run_id = getattr(store, "run_id", "run")
        role = self.role or "agent"
        if role == "chief":
            guard = (
                "TEST HARNESS RULES: This is a controlled CTF capability test. "
                "Refresh the configured local catalog, create only the Challenge "
                "Agents named in the user prompt, and read their reports. The "
                "catalog adapter is local-only: do not connect to any competition "
                "platform or request platform operations."
            )
        elif role == "challenge":
            guard = (
                "TEST HARNESS RULES: This is an authorized assessment of the "
                "configured CTF target. Do not connect to a competition platform, "
                "start or stop a target, request a platform Hint, submit a Flag, or "
                "close the challenge. Begin a cycle, decompose the mission into "
                "useful non-duplicated Execution tasks, and create as many short-lived "
                "Execution Agents as the evidence warrants. After creating them, "
                "wait for and consume every execution report, including failures. "
                "Record blockers and decide on non-duplicating follow-up work before "
                "ending the cycle. Use only the configured target addresses; do not "
                "invent additional targets."
            )
        else:
            guard = (
                "TEST HARNESS RULES: This is an authorized CTF capability test. "
                "Perform real observation and verification against the configured "
                "addresses in <target_addresses> using the available network and "
                "system tools. You may use ordinary HTTP/TCP discovery and local "
                "analysis required by the assigned mission, but stay within those "
                "addresses and do not invent targets. Do not connect to a competition "
                "platform, start or stop a target, request a platform Hint, submit a "
                "Flag, or close a challenge. Record concrete evidence and finally "
                "call execution_report with a concise, honest summary; never include "
                "a candidate Flag in the report."
            )
        guarded_prompt = f"{prompt or ''}\n\n{guard}"
        if store is not None and hasattr(store, "append_event"):
            await store.append_event(
                "test_effective_prompt",
                {"prompt": guarded_prompt},
            )
        return await super().run_session(guarded_prompt, **kwargs)


ROLE_DISABLED_TOOLS: dict[str, frozenset[str]] = {
    "chief": frozenset({"chief_request_hint"}),
    "challenge": frozenset({"challenge_submit_flag", "challenge_close_challenge"}),
}

TERMINAL_AGENT_STATUSES = frozenset(
    {"completed", "failed", "stopped", "cancelled", "interrupted"}
)
DEFAULT_WAIT_SECONDS = 0.0


class LocalChallengeBenchmark:
    """Offline Benchmark-shaped adapter backed by the configured CTF slots."""

    def __init__(self, challenges: list[dict[str, Any]]) -> None:
        self._challenges = {
            item["unique_code"]: dict(item) for item in challenges
        }
        self._started: set[str] = set()

    async def dispatch(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        arguments = arguments or {}
        if name == "benchmark_list_challenges":
            return {
                "ok": True,
                "data": [self._state(item) for item in self._challenges.values()],
            }

        unique_code = str(arguments.get("unique_code") or "")
        challenge = self._challenges.get(unique_code)
        if challenge is None:
            return {
                "ok": False,
                "error": {
                    "type": "local_catalog",
                    "code": "task_not_found",
                    "message": "The local challenge name is not configured",
                    "status_code": 404,
                    "detail": {},
                },
            }
        if name == "benchmark_start_challenge":
            self._started.add(unique_code)
            return {
                "ok": True,
                "data": {
                    "unique_code": unique_code,
                    "container_addr": challenge["container_addr"],
                },
            }
        if name == "benchmark_close_challenge":
            self._started.discard(unique_code)
            return {
                "ok": True,
                "data": {
                    "unique_code": unique_code,
                    "container_addr": challenge["container_addr"],
                },
            }
        if name in {"benchmark_get_hint", "benchmark_submit_flag"}:
            return {
                "ok": False,
                "error": {
                    "type": "test_guard",
                    "code": "local_operation_disabled",
                    "message": "Hint and Flag operations are disabled in the local smoke test",
                    "status_code": None,
                    "detail": {},
                },
            }
        return {
            "ok": False,
            "error": {
                "type": "local_catalog",
                "code": "unsupported_operation",
                "message": "The local challenge adapter does not support this operation",
                "status_code": None,
                "detail": {},
            },
        }

    def _state(self, challenge: dict[str, Any]) -> dict[str, Any]:
        unique_code = challenge["unique_code"]
        return {
            "unique_code": unique_code,
            "description": challenge["description"],
            "difficulty": "local",
            "level": 0,
            "total_score": 0,
            "flag_count": 0,
            "correct_flag_count": 0,
            "is_completed": False,
            "container_status": "running" if unique_code in self._started else "stopped",
            "container_addr": challenge["container_addr"],
        }

    async def close(self) -> None:
        return None


def guarded_runner_factory(
    settings: AgentSettings,
    registry: ToolRegistry,
    **kwargs: Any,
) -> GuardedAgentRunner:
    """Build a real model Runner with the test-only tool allow-list."""

    role = str(kwargs.get("role") or "")
    disabled = ROLE_DISABLED_TOOLS.get(role, frozenset())
    if disabled:
        allowed = (registry.allowed_tools or set()) - set(disabled)
        registry = ToolRegistry(registry.wrappers, allowed_tools=allowed)
    return GuardedAgentRunner(settings, registry, **kwargs)


def _selected_challenges(override: str | None) -> list[dict[str, Any]]:
    values = [dict(item) for item in CHALLENGES]
    if override:
        if not values:
            raise ValueError("CHALLENGES must contain at least one local slot")
        values = [{**values[0], "name": override}]
    if not values:
        raise ValueError("CHALLENGES must contain at least one local slot")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(values, start=1):
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError(
                f"fill CHALLENGES[{index - 1}]['name'] before running"
            )
        description = str(item.get("description", "")).strip()
        if not description:
            raise ValueError(
                f"fill CHALLENGES[{index - 1}]['description'] before running"
            )
        raw_address = item.get("address", item.get("addresses", []))
        if isinstance(raw_address, str):
            addresses = [raw_address.strip()] if raw_address.strip() else []
        elif isinstance(raw_address, list):
            addresses = [str(value).strip() for value in raw_address if str(value).strip()]
        else:
            addresses = []
        if not addresses:
            raise ValueError(
                f"fill CHALLENGES[{index - 1}]['address'] before running"
            )
        item["name"] = name
        item["unique_code"] = name
        item["description"] = description
        item["mission"] = str(item.get("mission", "")).strip()
        item["address"] = addresses[0] if len(addresses) == 1 else addresses
        item["container_addr"] = addresses
        normalized.append(item)
    names = [item["unique_code"] for item in normalized]
    if len(set(names)) != len(names):
        raise ValueError("local challenge names must be unique")
    return normalized


def _prompt(challenges: list[dict[str, Any]]) -> str:
    selected = "\n".join(
        f"- {item['name']} @ {item['address']}: {item['mission'] or 'No extra mission supplied.'}"
        for item in challenges
    )
    return (
        "This is a controlled AION Runtime smoke test using a local CTF catalog. The harness has selected "
        f"these challenge slots:\n{selected}\n"
        "First refresh the local challenge catalog, then create exactly these Challenge "
        "Agents. The catalog is a local test adapter and must not be contacted as a "
        "real competition platform. Do not start targets, request platform hints, "
        "submit flags, or close challenges. Let each Challenge Agent plan and "
        "delegate real work against its configured CTF addresses, then summarize the "
        "persisted lifecycle."
    )


def _print_overview(overview: dict[str, Any], state_path: Path) -> None:
    run = overview["run"]
    print(f"[quick-test] run_id: {run['run_id']}")
    print(f"[quick-test] state: {state_path}")
    print(f"[quick-test] run_status: {run['status']}")
    print(f"[quick-test] agents: {len(overview['agents'])}")
    report_count = 0
    execution_count = 0
    for agent in overview["agents"]:
        if agent["role"] == "execution":
            execution_count += 1
            if agent["last_report_sequence"]:
                report_count += 1
        print(
            "[quick-test] agent: "
            f"{agent['role']} "
            f"status={agent['status']} "
            f"reports={agent['last_report_sequence']}"
        )
    for challenge in overview["challenges"]:
        print(
            "[quick-test] challenge: "
            f"{challenge['unique_code']} "
            f"container={challenge['container_status']} "
            f"work={challenge['work_status']}"
        )
    print(f"[quick-test] execution_agents: {execution_count}")
    print(f"[quick-test] execution_reports: {report_count}")


def _execution_phase_complete(
    overview: dict[str, Any], expected_codes: set[str]
) -> bool:
    """Return true only after child reports reached their Challenge parent."""

    execution_agents = [
        item
        for item in overview["agents"]
        if item["role"] == "execution" and item["unique_code"] in expected_codes
    ]
    if not execution_agents:
        return False
    if {item["unique_code"] for item in execution_agents} != expected_codes:
        return False
    if not all(
        item["status"] in TERMINAL_AGENT_STATUSES
        and bool(item["last_report_sequence"])
        for item in execution_agents
    ):
        return False

    challenge_agents = {
        item["agent_id"]: item
        for item in overview["agents"]
        if item["role"] == "challenge" and item["unique_code"] in expected_codes
    }
    if {item["unique_code"] for item in challenge_agents.values()} != expected_codes:
        return False
    # Consuming the current batch is not the end of a Challenge Agent's
    # lifecycle.  It may still be deciding whether to create follow-up
    # Execution Agents, update the cycle, or continue observing the target.
    # Only let the harness close the Runtime after the parent has explicitly
    # reached a terminal state as well.
    if not all(
        item["status"] in TERMINAL_AGENT_STATUSES
        for item in challenge_agents.values()
    ):
        return False
    for code in expected_codes:
        children = [
            item
            for item in execution_agents
            if item["unique_code"] == code
        ]
        parent_ids = {item.get("parent_id") for item in children}
        if None in parent_ids or len(parent_ids) != 1:
            return False
        parent = challenge_agents.get(next(iter(parent_ids)))
        if parent is None:
            return False
        latest_report = max(
            int(item.get("last_report_sequence") or 0) for item in children
        )
        cursors = parent.get("report_cursors") or {}
        consumed_through = int(
            cursors.get("execution", parent.get("report_cursor", 0)) or 0
        )
        if consumed_through < latest_report:
            return False
    return True


def _unconsumed_report_count(
    overview: dict[str, Any], expected_codes: set[str]
) -> int:
    """Count persisted child reports not yet consumed by their parent."""

    agents = overview["agents"]
    parents = {item["agent_id"]: item for item in agents}
    count = 0
    for item in agents:
        if (
            item["role"] != "execution"
            or item["unique_code"] not in expected_codes
            or not item.get("last_report_sequence")
        ):
            continue
        parent = parents.get(item.get("parent_id"), {})
        cursor = int(
            (parent.get("report_cursors") or {}).get(
                "execution", parent.get("report_cursor", 0)
            )
            or 0
        )
        if cursor < int(item["last_report_sequence"]):
            count += 1
    return count


async def _wait_for_monitor_exit() -> None:
    """Hold the frozen page until the user sends Ctrl-C."""

    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    installed = False
    try:
        try:
            loop.add_signal_handler(signal.SIGINT, stopped.set)
            installed = True
        except (NotImplementedError, RuntimeError):
            installed = False
        if installed:
            await stopped.wait()
        else:
            try:
                await asyncio.Event().wait()
            except KeyboardInterrupt:
                pass
    finally:
        if installed:
            try:
                loop.remove_signal_handler(signal.SIGINT)
            except (NotImplementedError, RuntimeError):
                pass


def _create_network_manager(
    vpn_enabled: bool,
    vpn_config: Path | None,
) -> VPNManager | None:
    if not vpn_enabled:
        return None
    return VPNManager(discover_vpn_config(PROJECT_ROOT, vpn_config))


async def run_test(
    *,
    challenges: list[dict[str, Any]],
    run_id: str,
    passive: bool,
    wait_seconds: float,
    close_on_exit: bool,
    monitor_enabled: bool = True,
    monitor_port: int = 0,
    monitor_exit_on_complete: bool = False,
    vpn_enabled: bool = False,
    vpn_config: Path | None = None,
) -> int:
    settings = AgentSettings()  # Loads .env and process environment.
    print(
        "[quick-test] admission thresholds: "
        f"cpu<{settings.cpu_limit_percent:g}% "
        f"memory<{settings.memory_limit_percent:g}%"
    )
    benchmark = LocalChallengeBenchmark(challenges)
    network_manager = _create_network_manager(vpn_enabled, vpn_config)
    if network_manager is not None:
        print(f"[quick-test] vpn: starting with {network_manager.config_path}")
    runtime_kwargs: dict[str, Any] = {
        "settings": settings,
        "benchmark": benchmark,
        "project_root": PROJECT_ROOT,
        "run_root": settings.run_root,
        "catalog_reconcile_interval_seconds": 0,
    }
    if network_manager is not None:
        runtime_kwargs["network_manager"] = network_manager
    if passive:
        runtime_kwargs["runner_factory"] = PassiveRunner
    else:
        runtime_kwargs["runner_factory"] = guarded_runner_factory

    runtime = AgentRuntime(**runtime_kwargs)
    started_agents: list[tuple[str, str]] = []
    monitor: RuntimeMonitor | None = None
    monitor_started = False
    result_code = 1
    result_message = "test did not complete"
    interrupted = False
    try:
        chief_id = await runtime.start(_prompt(challenges), run_id=run_id)
        await runtime.ensure_healthy()
        if network_manager is not None:
            vpn_status = network_manager.status
            print(
                "[quick-test] vpn: connected "
                f"pid={vpn_status.pid} config={vpn_status.config_path}"
            )
        assert runtime.supervisor is not None
        print(f"[quick-test] chief_agent_id: {chief_id}")
        if monitor_enabled:
            state_path = settings.run_root / run_id / "state.sqlite3"
            monitor = RuntimeMonitor(state_path, run_id, port=monitor_port)
            print(f"[quick-test] monitor: {monitor.start()}")
            print("[quick-test] monitor is local-only; open the URL above in a browser")
            monitor_started = True

        if passive:
            for item in challenges:
                await runtime.ensure_healthy()
                unique_code = item["unique_code"]
                result = await runtime.supervisor.create_challenge_agent(
                    chief_id, unique_code
                )
                if not result.get("ok"):
                    print(
                        f"[quick-test] challenge failed: {unique_code}: "
                        f"{result.get('error', {}).get('code', 'unknown')}"
                    )
                    result_message = f"challenge agent failed: {unique_code}"
                    break
                started_agents.append((unique_code, result["data"]["agent_id"]))
                print(f"[quick-test] challenge agent started: {unique_code}")
            else:
                result_code = 0
                result_message = "passive SQLite lifecycle and local challenge startup completed"
        else:
            assert runtime.state_service is not None
            deadline = (
                asyncio.get_running_loop().time() + wait_seconds
                if wait_seconds > 0
                else None
            )
            expected_codes = {item["unique_code"] for item in challenges}
            while deadline is None or asyncio.get_running_loop().time() < deadline:
                await runtime.ensure_healthy()
                overview = await runtime.state_service.get_overview(run_id)
                actual_codes = {
                    item["unique_code"]
                    for item in overview["agents"]
                    if item["role"] == "challenge" and item["unique_code"]
                }
                if expected_codes.issubset(actual_codes):
                    for item in overview["agents"]:
                        if item["role"] == "challenge" and item["unique_code"] in expected_codes:
                            started_agents.append((item["unique_code"], item["agent_id"]))
                    break
                await asyncio.sleep(1)
            if len(started_agents) != len(expected_codes):
                print("[quick-test] Chief did not create all configured Challenge Agents")
                result_message = "Chief did not create all configured Challenge Agents"
            else:
                print("[quick-test] Chief created the configured Challenge Agents")
                result_message = "waiting for configured Challenge Agents to report"

        if not passive and len(started_agents) == len(challenges):
            assert runtime.state_service is not None
            expected_codes = {item["unique_code"] for item in challenges}
            deadline = (
                asyncio.get_running_loop().time() + wait_seconds
                if wait_seconds > 0
                else None
            )
            while deadline is None or asyncio.get_running_loop().time() < deadline:
                await runtime.ensure_healthy()
                overview = await runtime.state_service.get_overview(run_id)
                if _execution_phase_complete(overview, expected_codes):
                    result_code = 0
                    result_message = (
                        "configured target assessment completed; SQLite reports persisted; "
                        "no platform or Flag operation was performed"
                    )
                    break
                await asyncio.sleep(2)

        await runtime.ensure_healthy()
        assert runtime.state_service is not None
        overview = await runtime.state_service.get_overview(run_id)
        _print_overview(overview, settings.run_root / run_id / "state.sqlite3")
        if not passive:
            expected_codes = {item["unique_code"] for item in challenges}
            execution_agents = [
                item
                for item in overview["agents"]
                if item["role"] == "execution"
                and item["unique_code"] in expected_codes
            ]
            if not execution_agents:
                result_code = 1
                result_message = "no Execution Agent was created for the configured targets"
            elif not _execution_phase_complete(overview, expected_codes):
                result_code = 1
                pending = sum(
                    item["status"] not in TERMINAL_AGENT_STATUSES
                    or not item["last_report_sequence"]
                    for item in execution_agents
                )
                pending_consumption = _unconsumed_report_count(
                    overview, expected_codes
                )
                result_message = (
                    f"{pending} Execution Agent(s) are still queued, running, or missing a report; "
                    f"{pending_consumption} report(s) are waiting for Challenge consumption"
                )
        print(f"[quick-test] result: {result_message}")
    except KeyboardInterrupt:
        interrupted = True
        raise
    finally:
        try:
            if (
                close_on_exit
                and runtime.supervisor is not None
                and runtime.state_service is not None
            ):
                for unique_code, challenge_agent_id in started_agents:
                    challenge = next(
                        (
                            item
                            for item in await runtime.state_service.list_challenges(run_id)
                            if item["unique_code"] == unique_code
                        ),
                        None,
                    )
                    if challenge and challenge["container_status"] in {"starting", "running"}:
                        close_result = await runtime.supervisor.close_challenge(challenge_agent_id)
                        if close_result.get("ok"):
                            print(f"[quick-test] local challenge slot closed: {unique_code}")
                        else:
                            print(f"[quick-test] local challenge slot close failed: {unique_code}")
        finally:
            await runtime.close()
            if network_manager is not None:
                print("[quick-test] vpn: stopped")
            if monitor_started and monitor is not None:
                try:
                    monitor.freeze(result_code, message=result_message)
                    print(f"[quick-test] monitor frozen: {monitor.url}")
                    if not monitor_exit_on_complete and not interrupted:
                        print("[quick-test] press Ctrl-C to close the frozen monitor")
                        await _wait_for_monitor_exit()
                except Exception as exc:
                    print(f"[quick-test] monitor unavailable: {type(exc).__name__}: {exc}")
                finally:
                    monitor.close()


async def async_main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--challenge",
        help="override the first challenge slot without editing the script",
    )
    parser.add_argument(
        "--run-id",
        default=f"quick-real-{uuid4().hex[:12]}",
        help="SQLite run id; defaults to a unique quick-test id",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="skip model calls and only verify the real Benchmark + SQLite lifecycle",
    )
    parser.add_argument(
        "--wait-seconds",
        type=float,
        default=DEFAULT_WAIT_SECONDS,
        help=(
            "maximum assessment time in seconds; 0 waits for all configured "
            "Execution reports or Ctrl-C (default: 0)"
        ),
    )
    parser.add_argument(
        "--close-on-exit",
        action="store_true",
        help="close started local challenge slots before exiting",
    )
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="disable the local test-only Flight Recorder",
    )
    parser.add_argument(
        "--monitor-port",
        type=int,
        default=0,
        help="local monitor port; 0 selects a free port (default: 0)",
    )
    parser.add_argument(
        "--monitor-exit-on-complete",
        action="store_true",
        help="exit when the test completes instead of holding the frozen monitor",
    )
    parser.add_argument(
        "--vpn",
        action="store_true",
        help="start and own a local OpenVPN connection for this test",
    )
    parser.add_argument(
        "--vpn-config",
        type=Path,
        help=(
            "OpenVPN profile; --vpn auto-discovers the only config/vpn/*.ovpn "
            "file when omitted"
        ),
    )
    args = parser.parse_args()
    if args.wait_seconds < 0:
        parser.error("--wait-seconds must not be negative")
    if not 0 <= args.monitor_port <= 65535:
        parser.error("--monitor-port must be between 0 and 65535")
    if args.vpn_config is not None and not args.vpn:
        parser.error("--vpn-config requires --vpn")

    try:
        challenges = _selected_challenges(args.challenge)
        return await run_test(
            challenges=challenges,
            run_id=args.run_id,
            passive=args.passive,
            wait_seconds=args.wait_seconds,
            close_on_exit=args.close_on_exit,
            monitor_enabled=not args.no_monitor,
            monitor_port=args.monitor_port,
            monitor_exit_on_complete=args.monitor_exit_on_complete,
            vpn_enabled=args.vpn,
            vpn_config=args.vpn_config,
        )
    except KeyboardInterrupt:
        print("[quick-test] interrupted")
        return 130
    except Exception as exc:
        print(f"[quick-test] failed: {type(exc).__name__}: {exc}")
        return 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
