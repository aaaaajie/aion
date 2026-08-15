"""Per-run async SQLite database management."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path

from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .models import Base, SchemaMetaRecord

SCHEMA_VERSION = 15


class StateDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._initialized = False
        self._initialize_lock = asyncio.Lock()
        self.engine: AsyncEngine = create_async_engine(
            f"sqlite+aiosqlite:///{self.path}",
            connect_args={"timeout": 30},
        )
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)
        self._configure_sqlite()

    def _configure_sqlite(self) -> None:
        @event.listens_for(self.engine.sync_engine, "connect")
        def set_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=FULL")
            cursor.close()

    async def initialize(self) -> None:
        async with self._initialize_lock:
            if self._initialized:
                return
            await asyncio.to_thread(self._prepare_path)
            await asyncio.to_thread(self._validate_existing_schema)
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            await asyncio.to_thread(os.chmod, self.path, 0o600)
            async with self.sessions.begin() as session:
                current = await session.scalar(
                    select(SchemaMetaRecord).where(SchemaMetaRecord.key == "schema_version")
                )
                if current is None:
                    session.add(
                        SchemaMetaRecord(
                            key="schema_version", value=str(SCHEMA_VERSION)
                        )
                    )
                elif current.value != str(SCHEMA_VERSION):
                    raise RuntimeError("unsupported state database schema version")
            self._initialized = True

    def _prepare_path(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)

    def _validate_existing_schema(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        with sqlite3.connect(f"file:{self.path}?mode=ro", uri=True) as connection:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'"
            ).fetchone()
            if table is None:
                raise RuntimeError("unsupported state database schema version")
            current = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        if current is None or current[0] != str(SCHEMA_VERSION):
            raise RuntimeError("unsupported state database schema version")

    async def close(self) -> None:
        await self.engine.dispose()

    async def pragma(self, name: str) -> str | int:
        if name not in {"journal_mode", "foreign_keys", "busy_timeout", "synchronous"}:
            raise ValueError("unsupported pragma")
        async with self.engine.connect() as connection:
            result = await connection.exec_driver_sql(f"PRAGMA {name}")
            return result.scalar_one()
