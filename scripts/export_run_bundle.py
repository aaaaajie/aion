"""Create a credential-free diagnostic bundle for one persistent AION run."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from typing import Any


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout


def _database_metadata(database: Path, run_id: str) -> dict[str, Any]:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        row = connection.execute(
            "SELECT run_id, status, started_at, deadline_at, last_sequence "
            "FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        raise ValueError(f"Run {run_id!r} was not found in its state database")
    return {
        "run_id": row[0],
        "status": row[1],
        "started_at": row[2],
        "deadline_at": row[3],
        "last_sequence": row[4],
    }


def _backup_database(source_path: Path, destination_path: Path) -> None:
    with sqlite3.connect(
        f"file:{source_path}?mode=ro", uri=True, timeout=30
    ) as source, sqlite3.connect(destination_path) as destination:
        source.backup(destination)
        result = destination.execute("PRAGMA integrity_check").fetchone()
    if result != ("ok",):
        raise RuntimeError("SQLite backup did not pass integrity_check")
    os.chmod(destination_path, 0o600)


def _journal_since(started_at: str) -> str:
    since = started_at
    if "T" not in since:
        since = since.replace(" ", "T", 1)
    if not since.endswith(("Z", "+00:00")):
        since = f"{since}+00:00"
    return _run(
        [
            "journalctl",
            "-u",
            "aion-online.service",
            "--since",
            since,
            "--no-pager",
            "--output=short-iso-precise",
        ]
    )


def create_bundle(
    *,
    run_root: Path,
    run_id: str,
    output: Path,
    include_workspace: bool = False,
    workspace_root: Path = Path("/var/lib/aion/workspace"),
) -> Path:
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError("run_id contains unsupported characters")
    root = run_root.expanduser().resolve()
    run_directory = root / run_id
    database = run_directory / "state.sqlite3"
    if not database.is_file():
        raise FileNotFoundError(f"Run database was not found: {database}")
    metadata = _database_metadata(database, run_id)
    destination = output.expanduser().resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f"aion-{run_id}-", dir=destination.parent
    ) as temporary_name:
        temporary = Path(temporary_name)
        snapshot = temporary / "state.sqlite3"
        _backup_database(database, snapshot)

        current_release = Path("/opt/aion/current")
        release_id = None
        if current_release.is_symlink():
            release_id = Path(os.readlink(current_release)).name
        metadata.update(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "release_id": release_id,
                "host": platform.node(),
                "platform": platform.platform(),
                "workspace_included": include_workspace,
            }
        )
        (temporary / "metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (temporary / "journal.log").write_text(
            _journal_since(str(metadata["started_at"])), encoding="utf-8"
        )
        (temporary / "service-status.txt").write_text(
            _run(
                [
                    "systemctl",
                    "show",
                    "aion-online.service",
                    "--no-pager",
                    "--property=ActiveState,SubState,MainPID,ExecMainStatus,StateChangeTimestamp",
                ]
            ),
            encoding="utf-8",
        )

        temporary_archive = destination.with_name(f".{destination.name}.tmp")
        try:
            with tarfile.open(temporary_archive, "w:gz") as archive:
                for name in (
                    "state.sqlite3",
                    "metadata.json",
                    "journal.log",
                    "service-status.txt",
                ):
                    archive.add(temporary / name, arcname=name, recursive=False)
                if include_workspace:
                    workspace = workspace_root.expanduser().resolve()
                    if workspace.is_dir():
                        archive.add(workspace, arcname="workspace", recursive=True)
            os.chmod(temporary_archive, 0o600)
            os.replace(temporary_archive, destination)
        finally:
            temporary_archive.unlink(missing_ok=True)
    return destination


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-workspace", action="store_true")
    parser.add_argument(
        "--workspace-root", type=Path, default=Path("/var/lib/aion/workspace")
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    try:
        create_bundle(
            run_root=args.run_root,
            run_id=args.run_id,
            output=args.output,
            include_workspace=args.include_workspace,
            workspace_root=args.workspace_root,
        )
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"aion bundle failed: {exc}") from None


if __name__ == "__main__":
    main()
