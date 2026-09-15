"""Run the production AION Runtime against the online Benchmark."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import sys
from typing import Any, Awaitable, TypeVar
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import AgentSettings, normalize_selected_challenge_codes
from agent.prompts import load_prompt
from agent.runtime import AgentRuntime, RuntimePausedError
from challenges_sdk import ChallengesClient, ChallengesSettings
from tools.benchmark import BenchmarkTools


DEFAULT_WAIT_SECONDS = 0.0
RUNTIME_SHUTDOWN_TIMEOUT_SECONDS = 30.0
VPN_SHUTDOWN_TIMEOUT_SECONDS = 8.0
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


def _read_benchmark_token_from_environment() -> str:
    """Read the platform-injected benchmark token without logging or fallback."""

    value = os.environ.get("BENCHMARK_TOKEN")
    if not value or "\n" in value or "\r" in value:
        raise ValueError(
            "BENCHMARK_TOKEN must contain exactly one non-empty environment value"
        )
    return value


def _benchmark_from_token(
    token: str, agent_settings: AgentSettings | None = None
) -> BenchmarkTools:
    settings = ChallengesSettings(benchmark_token=token)
    if agent_settings is None:
        return BenchmarkTools(ChallengesClient.from_settings(settings))
    from tools.benchmark.recovery import BenchmarkLLMRecovery

    recoverer = BenchmarkLLMRecovery(agent_settings)
    return BenchmarkTools(
        ChallengesClient.from_settings(
            settings,
            response_recoverer=recoverer,
            contract_recoverer=recoverer,
        ),
        response_recoverer=recoverer,
    )


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


async def _bounded_shutdown(operation: Awaitable[Any], label: str, timeout: float) -> None:
    """Keep systemd shutdown below its stop window while preserving best effort cleanup."""

    try:
        from agent.deadline import before
        await before(operation, asyncio.get_running_loop().time() + timeout)
    except asyncio.TimeoutError:
        print(f"[online] shutdown: {label} exceeded {timeout:g}s", flush=True)
    except Exception as exc:
        print(f"[online] shutdown: {label} failed: {type(exc).__name__}", flush=True)


async def _mark_runtime_interrupted(runtime: AgentRuntime, reason: str) -> None:
    """Persist a terminal stop state before resource cleanup can detach the service."""

    service = runtime.state_service
    if service is None or runtime.run_id is None:
        return
    try:
        await service.finish_run(
            runtime.run_id,
            "interrupted",
            report={"type": "runtime_interrupted", "summary": reason[:500]},
        )
    except Exception as exc:
        print(f"[online] state: interrupt mark failed: {type(exc).__name__}", flush=True)


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


def _read_launch_config(path: Path) -> tuple[str, bool, list[str] | None]:
    try:
        raw = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Runtime launch config could not be read: {path}") from exc
    if not isinstance(raw, dict) or not {"mode", "run_id"} <= set(raw) or set(raw) - {"mode", "run_id", "selected_challenge_codes"}:
        raise ValueError("Runtime launch config requires mode and run_id, with optional selected_challenge_codes")
    mode = raw.get("mode")
    run_id = raw.get("run_id")
    if mode not in {"fresh", "resume"}:
        raise ValueError("Runtime launch mode must be fresh or resume")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValueError("Runtime launch run_id is invalid")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in run_id):
        raise ValueError("Runtime launch run_id contains unsupported characters")
    selected = normalize_selected_challenge_codes(raw.get("selected_challenge_codes"))
    if mode == "resume" and selected is not None:
        raise ValueError("Resume cannot replace selected_challenge_codes")
    return run_id, mode == "resume", selected


async def run_online(
    *,
    run_id: str,
    resume: bool,
    benchmark_token_file: Path | None,
    hosted: bool,
    vpn_config: Path | None,
    workspace_root: Path,
    run_root: Path | None,
    wait_seconds: float,
    current_run_file: Path | None,
    selected_challenge_codes: list[str] | None = None,
) -> int:
    if hosted:
        token = _read_benchmark_token_from_environment()
    else:
        if benchmark_token_file is None:
            raise ValueError("--benchmark-token-file is required outside hosted mode")
        token = _read_benchmark_token(benchmark_token_file)
    if resume and selected_challenge_codes is not None:
        raise ValueError("Resume cannot replace selected_challenge_codes")
    settings = AgentSettings(**(
        {"selected_challenge_codes": selected_challenge_codes}
        if selected_challenge_codes is not None else {}
    ))
    workspace = workspace_root.expanduser().resolve()
    state_root = (
        run_root or workspace / ".aion" / "runs"
    ).expanduser().resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    vpn: Any | None = None
    config_path: Path | None = None
    if not hosted:
        from scripts.network_manager import VPNManager, discover_vpn_config

        config_path = discover_vpn_config(PROJECT_ROOT, vpn_config)
        vpn = VPNManager(config_path, use_sudo=_openvpn_requires_sudo())
    benchmark = _benchmark_from_token(token, settings)
    del token
    runtime = AgentRuntime(
        settings,
        benchmark=benchmark,
        network_manager=vpn,
        project_root=workspace,
        run_root=state_root,
    )
    result_code = 1
    result_message = "online Runtime did not complete"
    interrupted = False
    interrupted_reason: str | None = None
    stop_event = asyncio.Event()
    signal_state, installed_signals = _install_signal_handlers(stop_event)
    try:
        if hosted:
            print("[hosted] network: using platform-provided network", flush=True)
        else:
            assert vpn is not None and config_path is not None
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
            interrupted_reason = result_message
            print(f"[online] result: {result_message}", flush=True)
            return result_code
        assert chief_id is not None
        await runtime.ensure_healthy()
        if current_run_file is not None:
            _write_current_run(current_run_file, run_id)
        if vpn is not None:
            print(f"[online] vpn: connected pid={vpn.status.pid}", flush=True)
        print(f"[online] run_id: {run_id}", flush=True)
        print(f"[online] chief_agent_id: {chief_id}", flush=True)

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
            interrupted_reason = result_message
        else:
            interrupted = True
            result_code, result_message = _signal_result(signal_state["signal"])
            interrupted_reason = result_message
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
        if not pause_requested and interrupted_reason is not None:
            await _mark_runtime_interrupted(runtime, interrupted_reason)
        if pause_requested:
            await _bounded_shutdown(
                runtime.pause(), "runtime pause", RUNTIME_SHUTDOWN_TIMEOUT_SECONDS
            )
        else:
            await _bounded_shutdown(
                runtime.close(), "runtime close", RUNTIME_SHUTDOWN_TIMEOUT_SECONDS
            )
        if vpn is not None:
            await _bounded_shutdown(vpn.close(), "vpn close", VPN_SHUTDOWN_TIMEOUT_SECONDS)
            print("[online] vpn: stopped", flush=True)
        _remove_signal_handlers(installed_signals)
    return result_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the production AION Runtime against the online Benchmark"
    )
    token_source = parser.add_mutually_exclusive_group(required=True)
    token_source.add_argument(
        "--benchmark-token-file",
        type=Path,
        help="file containing exactly one BENCHMARK_TOKEN value",
    )
    token_source.add_argument(
        "--hosted",
        action="store_true",
        help="use platform-injected environment variables and skip OpenVPN",
    )
    parser.add_argument(
        "--run-id",
        help="SQLite run id; fresh runs default to a unique online run id",
    )
    parser.add_argument(
        "--challenge-code", action="append", dest="selected_challenge_codes",
        help="limit a new run to this challenge; repeat for multiple challenges",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume the existing --run-id instead of creating a new run",
    )
    parser.add_argument(
        "--launch-config-file",
        type=Path,
        help="internal JSON file containing mode, run_id and optional selected_challenge_codes",
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
        help="persistent Runtime state root; defaults to <workspace-root>/.aion/runs",
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
    return parser


async def async_main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.wait_seconds < 0:
        parser.error("--wait-seconds must not be negative")
    if args.hosted and args.vpn_config is not None:
        parser.error("--vpn-config cannot be used with --hosted")
    if args.launch_config_file is not None and (args.resume or args.run_id or args.selected_challenge_codes is not None):
        parser.error("--launch-config-file cannot be combined with --resume, --run-id or --challenge-code")
    if args.resume and args.selected_challenge_codes is not None:
        parser.error("--resume cannot replace selected_challenge_codes with --challenge-code")
    if args.resume and not args.run_id:
        parser.error("--resume requires --run-id")
    try:
        if args.launch_config_file is not None:
            run_id, resume, selected = _read_launch_config(args.launch_config_file)
        else:
            run_id = args.run_id or f"online-{uuid4().hex[:12]}"
            resume = args.resume
            selected = normalize_selected_challenge_codes(args.selected_challenge_codes)
        return await run_online(
            run_id=run_id,
            resume=resume,
            benchmark_token_file=args.benchmark_token_file,
            hosted=args.hosted,
            vpn_config=args.vpn_config,
            workspace_root=args.workspace_root,
            run_root=args.run_root,
            wait_seconds=args.wait_seconds,
            current_run_file=args.current_run_file,
            selected_challenge_codes=selected,
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
