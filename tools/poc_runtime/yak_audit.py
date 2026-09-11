"""Read-only inventory for local Yakit SQLite plugin databases."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def audit_database(path: str | Path, output: str | Path) -> dict[str, Any]:
    db = Path(path).resolve()
    destination = Path(output).resolve()
    if destination.exists() or destination.is_symlink():
        raise ValueError("output directory must be new")
    destination.mkdir(parents=True, mode=0o700)
    tables: list[dict[str, Any]] = []
    script_inventory: dict[str, Any] = {"available": False, "reason": "yak_scripts table not present"}
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for name in names:
            escaped = '"' + name.replace('"', '""') + '"'
            columns = [dict(row) for row in connection.execute(f"PRAGMA table_info({escaped})")]
            count = int(connection.execute(f"SELECT COUNT(*) FROM {escaped}").fetchone()[0])
            tables.append({"name": name, "columns": columns, "row_count": count})
            if name == "yak_scripts":
                column_names = {str(item["name"]) for item in columns}
                script_inventory = {
                    "available": True,
                    "row_count": count,
                    "script_content_column_present": "content" in column_names,
                    "distinct_types": [],
                    "flags": {},
                }
                if "type" in column_names:
                    script_inventory["distinct_types"] = [row[0] for row in connection.execute(f"SELECT type, COUNT(*) FROM {escaped} GROUP BY type ORDER BY type")]
                for flag in ("from_local", "from_store", "is_external", "is_core_plugin", "enable_plugin_selector", "is_batch_script"):
                    if flag in column_names:
                        flag_sql = f"SELECT COALESCE(CAST({flag} AS TEXT), 'NULL'), COUNT(*) FROM {escaped} GROUP BY {flag} ORDER BY 1"
                        script_inventory["flags"][flag] = [{"value": row[0], "count": row[1]} for row in connection.execute(flag_sql)]
    result = {
        "database": str(db),
        "read_only": True,
        "tables": tables,
        "script_inventory": script_inventory,
        "capability_inventory": {
            "http_api": "not inferred from schema-only inspection",
            "external_resources": "not read",
            "lifecycle_dependencies": "not inferred from schema-only inspection",
        },
        "limitations": ["does not execute Yak scripts", "does not read external plugin resources", "database records do not prove script semantics"],
    }
    (destination / "yak-audit.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "report.md").write_text("# Yakit plugin database inventory\n\nThis is a read-only schema and row-count inventory. No Yak script or external resource was executed.\n\n" + "\n".join(f"- `{item['name']}`: {item['row_count']} rows" for item in tables) + "\n\nScript inventory: " + json.dumps(script_inventory, ensure_ascii=False) + "\n", encoding="utf-8")
    return result
