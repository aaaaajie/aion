"""Run the production AION Runtime against the online Benchmark."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import sys
from typing import Awaitable, TypeVar
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import AgentSettings
from agent.prompts import load_prompt
from agent.runtime import AgentRuntime, RuntimePausedError
from challenges_sdk import ChallengesClient, ChallengesSettings
from scripts.network_manager import VPNManager, discover_vpn_config
from scripts.runtime_web import RuntimeMonitor
from tools.benchmark import BenchmarkTools


DEFAULT_WAIT_SECONDS = 0.0
DEFAULT_MONITOR_PORT = 8765
_T = TypeVar("_T")
PAUSE_SIGNAL = getattr(signal, "SIGUSR1", None)


def _read_benchmark_token(path: Path) -> str:
    """Read one non-empty token without falling back to process configuration."""

    try:
        value = path.expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Benchmark token file could not be read: {path}") from exc
    if value.endswith("\n"):
        value = value[:-1]
        if value.endswith("\r"):
            value = value[:-1]
    if not value or "\n" in value or "\r" in value:
        raise ValueError("Benchmark token file must contain exactly one non-empty line")
    return value


def _benchmark_from_token(token: str) -> BenchmarkTools:
    settings = ChallengesSettings(benchmark_token=token)
    return BenchmarkTools(ChallengesClient.from_settings(settings))


def _openvpn_requires_sudo() -> bool:
    return os.geteuid() != 0


def _install_signal_handlers(
    stop_event: asyncio.Event,
) -> tuple[dict[str, int | None], list[signal.Signals]]:
    loop = asyncio.get_running_loop()
    state: dict[str, int | None] = {"signal": None}
    installed: list[signal.Signals] = []

    def request_stop(received: signal.Signals) -> None:
        if state["signal"] is None:
            state["signal"] = int(received)
        stop_event.set()

    received_signals = [signal.SIGINT, signal.SIGTERM]
    if PAUSE_SIGNAL is not None:
        received_signals.append(PAUSE_SIGNAL)
    for received in received_signals:
        try:
            loop.add_signal_handler(received, request_stop, received)
        except (NotImplementedError, RuntimeError):
            continue
        installed.append(received)
    return state, installed


def _remove_signal_handlers(installed: list[signal.Signals]) -> None:
    loop = asyncio.get_running_loop()
    for received in installed:
        try:
            loop.remove_signal_handler(received)
        except (NotImplementedError, RuntimeError):
            pass


async def _wait_for_operation(
    operation: Awaitable[_T],
    stop_event: asyncio.Event,
    *,
    timeout: float | None = None,
) -> tuple[str, _T | None]:
    operation_task = asyncio.create_task(operation)
    stop_task = asyncio.create_task(stop_event.wait())
    try:
        done, _ = await asyncio.wait(
            {operation_task, stop_task},
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if operation_task in done:
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
            return "completed", await operation_task
        operation_task.cancel()
        await asyncio.gather(operation_task, return_exceptions=True)
        return ("stopped" if stop_task in done else "timeout"), None
    finally:
        if not stop_task.done():
            stop_task.cancel()
        if not operation_task.done():
            operation_task.cancel()
        await asyncio.gather(operation_task, stop_task, return_exceptions=True)


def _signal_result(received: int | None) -> tuple[int, str]:
    if PAUSE_SIGNAL is not None and received == int(PAUSE_SIGNAL):
        return 0, "online Runtime paused for deployment"
    if received == int(signal.SIGTERM):
        return 143, "online Runtime terminated"
    return 130, "online Runtime interrupted"


def _write_current_run(path: Path, run_id: str) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(f"{run_id}\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _read_launch_config(path: Path) -> tuple[str, bool]:
    try:
        raw = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Runtime launch config could not be read: {path}") from exc
    if not isinstance(raw, dict) or set(raw) != {"mode", "run_id"}:
        raise ValueError("Runtime launch config must contain only mode and run_id")
    mode = raw.get("mode")
    run_id = raw.get("run_id")
    if mode not in {"fresh", "resume"}:
        raise ValueError("Runtime launch mode must be fresh or resume")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValueError("Runtime launch run_id is invalid")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in run_id):
        raise ValueError("Runtime launch run_id contains unsupported characters")
    return run_id, mode == "resume"


async def run_online(
    *,
    run_id: str,
    resume: bool,
    benchmark_token_file: Path,
    vpn_config: Path | None,
    workspace_root: Path,
    run_root: Path | None,
    wait_seconds: float,
    monitor_enabled: bool,
    monitor_port: int,
    monitor_exit_on_complete: bool,
    current_run_file: Path | None,
) -> int:
    token = _read_benchmark_token(benchmark_token_file)
    settings = AgentSettings()
    workspace = workspace_root.expanduser().resolve()
    state_root = (run_root or settings.run_root).expanduser().resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = discover_vpn_config(PROJECT_ROOT, vpn_config)
    vpn = VPNManager(config_path, use_sudo=_openvpn_requires_sudo())
    benchmark = _benchmark_from_token(token)
    del token
    runtime = AgentRuntime(
        settings,
        benchmark=benchmark,
        network_manager=vpn,
        project_root=workspace,
        run_root=state_root,
    )
    monitor: RuntimeMonitor | None = None
    monitor_started = False
    result_code = 1
    result_message = "online Runtime did not complete"
    interrupted = False
    stop_event = asyncio.Event()
    signal_state, installed_signals = _install_signal_handlers(stop_event)
    try:
        print(f"[online] vpn: starting with {config_path}", flush=True)
        phase, chief_id = await _wait_for_operation(
            runtime.start(
                load_prompt("chief_agent.txt"), run_id=run_id, resume=resume
            ),
            stop_event,
        )
        if phase == "stopped":
            interrupted = True
            result_code, result_message = _signal_result(signal_state["signal"])
            print(f"[online] result: {result_message}", flush=True)
            return result_code
        assert chief_id is not None
        await runtime.ensure_healthy()
        if current_run_file is not None:
            _write_current_run(current_run_file, run_id)
        print(f"[online] vpn: connected pid={vpn.status.pid}", flush=True)
        print(f"[online] run_id: {run_id}", flush=True)
        print(f"[online] chief_agent_id: {chief_id}", flush=True)

        if monitor_enabled:
            state_path = state_root / run_id / "state.sqlite3"
            monitor = RuntimeMonitor(state_path, run_id, port=monitor_port)
            print(f"[online] web monitor: {monitor.start()}", flush=True)
            monitor_started = True

        phase, _ = await _wait_for_operation(
            runtime.wait(chief_id),
            stop_event,
            timeout=wait_seconds if wait_seconds > 0 else None,
        )
        if phase == "completed":
            result_code = 0
            result_message = "online Runtime completed"
        elif phase == "timeout":
            result_code = 124
            result_message = f"online Runtime reached the {wait_seconds:g}s deadline"
        else:
            interrupted = True
            result_code, result_message = _signal_result(signal_state["signal"])
        print(f"[online] result: {result_message}", flush=True)
    except RuntimePausedError as exc:
        result_code = 0
        result_message = f"online Runtime paused: {exc.reason}"
        print(f"[online] paused: {exc.reason}", flush=True)
    except Exception as exc:
        result_message = f"online Runtime failed: {type(exc).__name__}: {exc}"
        try:
            if runtime.state_service is not None and runtime.run_id is not None:
                await runtime.state_service.append_run_event(
                    runtime.run_id,
                    "runtime_fatal_error",
                    {
                        "code": "runtime_fatal",
                        "error_type": type(exc).__name__,
                    },
                )
                await runtime.state_service.finish_run(
                    runtime.run_id,
                    "failed",
                    report={
                        "type": "runtime_fatal_error",
                        "summary": "The online Runtime encountered an unrecoverable failure",
                    },
                )
        except Exception:
            pass
        print(f"[online] failed: {type(exc).__name__}: {exc}", flush=True)
    finally:
        pause_requested = (
            PAUSE_SIGNAL is not None
            and signal_state["signal"] == int(PAUSE_SIGNAL)
        )
        if pause_requested:
            await runtime.pause()
        else:
            await runtime.close()
        print("[online] vpn: stopped", flush=True)
        if monitor_started and monitor is not None:
            try:
                monitor.freeze(result_code, message=result_message)
                print(f"[online] web monitor frozen: {monitor.url}", flush=True)
                if not monitor_exit_on_complete and not interrupted:
                    print("[online] waiting for SIGINT or SIGTERM", flush=True)
                    await stop_event.wait()
            finally:
                monitor.close()
        _remove_signal_handlers(installed_signals)
    return result_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the production AION Runtime against the online Benchmark"
    )
    parser.add_argument(
        "--benchmark-token-file",
        type=Path,
        required=True,
        help="file containing exactly one BENCHMARK_TOKEN value",
    )
    parser.add_argument(
        "--run-id",
        help="SQLite run id; fresh runs default to a unique online run id",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume the existing --run-id instead of creating a new run",
    )
    parser.add_argument(
        "--launch-config-file",
        type=Path,
        help="internal JSON file containing mode and run_id",
    )
    parser.add_argument(
        "--vpn-config",
        type=Path,
        help="OpenVPN profile; defaults to the only config/vpn/*.ovpn file",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=PROJECT_ROOT,
        help="writable Agent workspace; defaults to the project root",
    )
    parser.add_argument(
        "--run-root",
        type=Path,
        help="persistent Runtime state root; defaults to AgentSettings.run_root",
    )
    parser.add_argument(
        "--current-run-file",
        type=Path,
        help="write the successfully started run id to this file",
    )
    parser.add_argument(
        "--wait-seconds",
        type=float,
        default=DEFAULT_WAIT_SECONDS,
        help="maximum online Runtime time; 0 waits until completion (default: 0)",
    )
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="disable the local read-only web monitor",
    )
    parser.add_argument(
        "--monitor-port",
        type=int,
        default=DEFAULT_MONITOR_PORT,
        help=f"localhost monitor port (default: {DEFAULT_MONITOR_PORT})",
    )
    parser.add_argument(
        "--monitor-exit-on-complete",
        action="store_true",
        help="exit instead of holding the frozen monitor after completion",
    )
    return parser


async def async_main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.wait_seconds < 0:
        parser.error("--wait-seconds must not be negative")
    if not 0 <= args.monitor_port <= 65535:
        parser.error("--monitor-port must be between 0 and 65535")
    if args.launch_config_file is not None and (args.resume or args.run_id):
        parser.error("--launch-config-file cannot be combined with --resume or --run-id")
    if args.resume and not args.run_id:
        parser.error("--resume requires --run-id")
    try:
        if args.launch_config_file is not None:
            run_id, resume = _read_launch_config(args.launch_config_file)
        else:
            run_id = args.run_id or f"online-{uuid4().hex[:12]}"
            resume = args.resume
        return await run_online(
            run_id=run_id,
            resume=resume,
            benchmark_token_file=args.benchmark_token_file,
            vpn_config=args.vpn_config,
            workspace_root=args.workspace_root,
            run_root=args.run_root,
            wait_seconds=args.wait_seconds,
            monitor_enabled=not args.no_monitor,
            monitor_port=args.monitor_port,
            monitor_exit_on_complete=args.monitor_exit_on_complete,
            current_run_file=args.current_run_file,
        )
    except ValueError as exc:
        parser.error(str(exc))


def main() -> None:
    try:
        raise SystemExit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
