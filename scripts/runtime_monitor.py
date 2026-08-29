"""Serve the read-only Web Monitor independently from the online Runtime."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.runtime_web import RuntimeMonitor


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
DEFAULT_RUN_ROOT = Path("/var/lib/aion/runs")
DEFAULT_CURRENT_RUN_FILE = Path("/var/lib/aion/current-run-id")
DEFAULT_PORT = 8765
DEFAULT_RUNTIME_SERVICE = "aion-online.service"
SYNC_SECONDS = 0.5

LOGGER = logging.getLogger("aion.runtime_monitor")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[AION monitor-service] %(asctime)s %(levelname)s %(message)s")
    )
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


def _runtime_active(service_name: str) -> bool | None:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service_name],
            check=False,
        )
    except OSError:
        # Local development commonly runs on macOS, where systemd is absent.
        # Keep polling so a locally launched Runtime can update the dashboard.
        return None
    return result.returncode == 0


def _current_run_id(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if RUN_ID_PATTERN.fullmatch(value) is None:
        return None
    return value


def _run_database(run_root: Path, run_id: str) -> Path | None:
    """Return one safe run database below ``run_root``."""

    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        return None
    database = run_root / run_id / "state.sqlite3"
    if database.is_symlink() or not database.is_file():
        return None
    try:
        database.resolve(strict=True).relative_to(run_root)
    except (OSError, ValueError):
        return None
    return database


def _latest_run_id(run_root: Path) -> str | None:
    """Find the newest complete-looking SQLite run below ``run_root``."""

    candidates: list[tuple[str, str, int, str]] = []
    try:
        run_directories = tuple(run_root.iterdir())
    except OSError:
        return None
    for directory in run_directories:
        if not directory.is_dir() or directory.is_symlink():
            continue
        run_id = directory.name
        database = _run_database(run_root, run_id)
        if database is None:
            continue
        try:
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                record = connection.execute(
                    "SELECT started_at, updated_at FROM runs WHERE run_id = ? LIMIT 1",
                    (run_id,),
                ).fetchone()
            modified_at = database.stat().st_mtime_ns
        except (OSError, sqlite3.Error):
            continue
        if record is None or not record[0]:
            continue
        started_at = str(record[0])
        updated_at = str(record[1] or "")
        candidates.append((started_at, updated_at, modified_at, run_id))
    if not candidates:
        return None
    return max(candidates)[3]


class MonitorController:
    """Keep one read-only monitor attached to the current persistent Run."""

    def __init__(
        self,
        *,
        run_root: Path,
        current_run_file: Path,
        port: int,
        runtime_service: str = DEFAULT_RUNTIME_SERVICE,
        sync_seconds: float = SYNC_SECONDS,
        auto_latest: bool = True,
    ) -> None:
        self.run_root = run_root.expanduser().resolve()
        self.current_run_file = current_run_file.expanduser().resolve()
        self.port = port
        self.runtime_service = runtime_service
        self.sync_seconds = sync_seconds
        self.auto_latest = auto_latest
        self._monitor: RuntimeMonitor | None = None
        self._run_id: str | None = None
        self._stop = threading.Event()
        self._last_active: bool | None = None

    @property
    def monitor(self) -> RuntimeMonitor | None:
        return self._monitor

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        LOGGER.info(
            "monitor_service_started run_root=%s current_run_file=%s port=%s",
            self.run_root,
            self.current_run_file,
            self.port,
        )
        try:
            while not self._stop.wait(self.sync_seconds):
                self.sync_once()
        finally:
            if self._monitor is not None:
                self._monitor.close()
                self._monitor = None
            LOGGER.info("monitor_service_stopped")

    def sync_once(self) -> None:
        active = _runtime_active(self.runtime_service)
        run_id = _current_run_id(self.current_run_file)
        if _run_database(self.run_root, run_id or "") is None and self.auto_latest:
            latest_run_id = _latest_run_id(self.run_root)
            if latest_run_id is not None:
                run_id = latest_run_id
        if run_id is not None and run_id != self._run_id:
            self._switch_run(run_id, active)
        elif self._monitor is not None:
            if active is True and self._monitor.frozen:
                self._monitor.resume()
            elif active is False and not self._monitor.frozen:
                self._freeze(active=False)
        elif run_id is None:
            LOGGER.debug("monitor_waiting_for_run_marker path=%s", self.current_run_file)
        self._last_active = active

    def _switch_run(self, run_id: str, active: bool) -> None:
        database = _run_database(self.run_root, run_id)
        if database is None:
            LOGGER.warning("monitor_run_database_missing run_id=%s database=%s", run_id, database)
            return
        if self._monitor is not None:
            self._monitor.close()
            self._monitor = None
        monitor = RuntimeMonitor(database, run_id, port=self.port)
        monitor.start()
        self._monitor = monitor
        self._run_id = run_id
        LOGGER.info("monitor_run_selected run_id=%s active=%s", run_id, active)
        if active is False:
            self._freeze(active=False)

    def _freeze(self, *, active: bool) -> None:
        if self._monitor is None:
            return
        self._monitor.freeze(
            "stopped",
            message="AION Runtime is active" if active else "AION Runtime is stopped; read-only snapshot",
        )
        LOGGER.info("monitor_snapshot_frozen run_id=%s active=%s", self._run_id, active)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--current-run-file", type=Path, default=DEFAULT_CURRENT_RUN_FILE)
    parser.add_argument("--monitor-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--runtime-service", default=DEFAULT_RUNTIME_SERVICE)
    parser.add_argument(
        "--no-auto-latest",
        action="store_false",
        dest="auto_latest",
        help="only follow --current-run-file; do not discover the newest state.sqlite3",
    )
    parser.set_defaults(auto_latest=True)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if not 0 <= args.monitor_port <= 65535:
        raise SystemExit("--monitor-port must be between 0 and 65535")
    controller = MonitorController(
        run_root=args.run_root,
        current_run_file=args.current_run_file,
        port=args.monitor_port,
        runtime_service=args.runtime_service,
        auto_latest=args.auto_latest,
    )
    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, lambda _signum, _frame: controller.stop())
    controller.sync_once()
    controller.run_forever()


if __name__ == "__main__":
    main()
