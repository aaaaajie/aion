"""Workspace-scoped filesystem operations for system tools."""

from __future__ import annotations

import asyncio
import errno
import glob as glob_module
import hashlib
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import SystemToolError, WorkspacePolicy

MAX_READ_BYTES = 10 * 1024 * 1024
MAX_SEARCH_FILE_BYTES = 10 * 1024 * 1024
MAX_GREP_MATCH_TEXT = 4_000


@dataclass(frozen=True)
class FileSnapshot:
    mtime_ns: int
    size: int
    digest: str | None
    full_read: bool


class FileSystemService:
    """Perform filesystem operations while keeping a per-session read state."""

    def __init__(self, policy: WorkspacePolicy) -> None:
        self.policy = policy
        self._read_state: dict[Path, FileSnapshot] = {}

    async def read_file(
        self,
        file_path: str,
        offset: int | None = None,
        limit_chars: int | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._read_file, file_path, offset, limit_chars
        )

    async def write_file(self, file_path: str, content: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._write_file, file_path, content)

    async def edit_file(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._edit_file,
            file_path,
            old_string,
            new_string,
            replace_all,
        )

    async def evidence_snapshot(self, file_path: str) -> str:
        """Read the exact final UTF-8 file while the caller still owns its lock."""

        return await asyncio.to_thread(
            self.policy.resolve(file_path).read_text, encoding="utf-8"
        )

    async def create_directory(self, path: str, parents: bool = True) -> dict[str, Any]:
        return await asyncio.to_thread(self._create_directory, path, parents)

    async def delete_path(self, path: str, recursive: bool = False) -> dict[str, Any]:
        return await asyncio.to_thread(self._delete_path, path, recursive)

    async def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        max_entries: int = 1000,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._list_directory,
            path,
            recursive,
            max_entries,
        )

    async def glob(
        self,
        pattern: str,
        path: str = ".",
        max_results: int = 100,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self._glob, pattern, path, max_results)

    async def grep(
        self,
        pattern: str,
        path: str = ".",
        glob: str | None = None,
        ignore_case: bool = False,
        max_results: int = 100,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._grep,
            pattern,
            path,
            glob,
            ignore_case,
            max_results,
        )

    def _read_file(
        self,
        file_path: str,
        offset: int | None,
        limit_chars: int | None,
    ) -> dict[str, Any]:
        path = self.policy.resolve(file_path, must_exist=True)
        if not path.is_file():
            raise self._error("validation", "not_a_file", "Path is not a regular file")

        try:
            size = path.stat().st_size
            full_read = offset is None and limit_chars is None
            if full_read and size > MAX_READ_BYTES:
                raise self._error(
                    "validation",
                    "file_too_large",
                    "File is too large for a full read; provide offset and limit_chars",
                    {"size_bytes": size, "max_bytes": MAX_READ_BYTES},
                )
            if size > MAX_READ_BYTES and limit_chars is None:
                raise self._error(
                    "validation",
                    "file_too_large",
                    "Large files require limit_chars for safe reading",
                    {"size_bytes": size, "max_bytes": MAX_READ_BYTES},
                )

            start = offset or 0
            if size <= MAX_READ_BYTES:
                data = path.read_bytes()
                text = self._decode_text(data)
                end = len(text) if limit_chars is None else start + limit_chars
                content = text[start:end]
                truncated = end < len(text)
                snapshot = self._snapshot(path, data, full_read)
            else:
                remaining_skip = start
                remaining_take = int(limit_chars or 0)
                chunks: list[str] = []
                has_more = False
                with path.open("r", encoding="utf-8", newline="") as stream:
                    while remaining_take > 0:
                        read_chars = min(
                            64 * 1024,
                            remaining_skip + remaining_take + 1,
                        )
                        chunk = stream.read(read_chars)
                        if not chunk:
                            break
                        if remaining_skip:
                            skipped = min(remaining_skip, len(chunk))
                            remaining_skip -= skipped
                            chunk = chunk[skipped:]
                            if not chunk:
                                continue
                        take = min(remaining_take, len(chunk))
                        chunks.append(chunk[:take])
                        remaining_take -= take
                        if take < len(chunk):
                            has_more = True
                            break
                    if not has_more and remaining_take == 0:
                        has_more = bool(stream.read(1))
                content = "".join(chunks)
                if len(content.encode("utf-8")) > MAX_READ_BYTES:
                    raise self._error(
                        "validation",
                        "read_limit_exceeded",
                        "The selected text exceeds the safe read limit",
                        {"max_bytes": MAX_READ_BYTES},
                    )
                truncated = has_more
                snapshot = self._snapshot(path, None, False)

            previous = self._read_state.get(path)
            if not (
                previous is not None
                and previous.full_read
                and previous.mtime_ns == snapshot.mtime_ns
                and previous.size == snapshot.size
                and (
                    snapshot.digest is None
                    or previous.digest == snapshot.digest
                )
            ):
                self._read_state[path] = snapshot
            next_offset = start + len(content)
            return {
                "file_path": self.policy.relative(path),
                "content": content,
                "offset": start,
                "next_offset": next_offset if truncated else None,
                "num_chars": len(content),
                "num_lines": len(content.splitlines()),
                "truncated": truncated,
                "size_bytes": size,
            }
        except SystemToolError:
            raise
        except UnicodeDecodeError as exc:
            raise self._error(
                "validation",
                "binary_file",
                "Binary files cannot be read as UTF-8 text",
            ) from exc
        except OSError as exc:
            raise self._filesystem_error(exc) from exc

    def _write_file(self, file_path: str, content: str) -> dict[str, Any]:
        path = self.policy.resolve(file_path)
        existed = path.exists()
        previous_content: str | None = None

        if existed:
            if not path.is_file():
                raise self._error("validation", "not_a_file", "Path is not a regular file")
            previous_content, current_snapshot = self._read_current_text(path)
            self._require_fresh_full_read(path, current_snapshot)

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write(path, content, self._mode_for(path))
            self._read_state[path] = self._snapshot(path, content.encode("utf-8"), True)
            return {
                "type": "update" if existed else "create",
                "file_path": self.policy.relative(path),
                "bytes_written": len(content.encode("utf-8")),
                "lines_written": len(content.splitlines()),
                "replaced_existing": existed,
                "original_bytes": len(previous_content.encode("utf-8")) if previous_content is not None else None,
            }
        except SystemToolError:
            raise
        except OSError as exc:
            raise self._filesystem_error(exc) from exc

    def _edit_file(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        replace_all: bool,
    ) -> dict[str, Any]:
        if old_string == new_string:
            raise self._error("validation", "no_changes", "old_string and new_string are identical")

        path = self.policy.resolve(file_path)
        existed = path.exists()
        if not existed:
            if old_string != "":
                raise self._error("not_found", "path_not_found", "File does not exist")
            content = new_string
            path.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write(path, content, 0o644)
            self._read_state[path] = self._snapshot(path, content.encode("utf-8"), True)
            return {
                "type": "create",
                "file_path": self.policy.relative(path),
                "replaced_count": 0,
                "bytes_written": len(content.encode("utf-8")),
            }

        if not path.is_file():
            raise self._error("validation", "not_a_file", "Path is not a regular file")
        content, current_snapshot = self._read_current_text(path)
        self._require_fresh_full_read(path, current_snapshot)

        if old_string == "":
            if content != "":
                raise self._error(
                    "conflict",
                    "file_not_empty",
                    "An empty old_string can only replace an empty file",
                )
            replacement_count = 0
            updated_content = new_string
        else:
            replacement_count = content.count(old_string)
            if replacement_count == 0:
                raise self._error(
                    "not_found",
                    "old_string_not_found",
                    "The requested text was not found in the file",
                )
            if replacement_count > 1 and not replace_all:
                raise self._error(
                    "conflict",
                    "multiple_matches",
                    "The requested text occurs multiple times; set replace_all to true",
                    {"matches": replacement_count},
                )
            updated_content = content.replace(
                old_string,
                new_string,
                -1 if replace_all else 1,
            )

        try:
            self._atomic_write(path, updated_content, self._mode_for(path))
            self._read_state[path] = self._snapshot(
                path,
                updated_content.encode("utf-8"),
                True,
            )
            return {
                "type": "update",
                "file_path": self.policy.relative(path),
                "replaced_count": replacement_count if replace_all else min(replacement_count, 1),
                "bytes_written": len(updated_content.encode("utf-8")),
            }
        except OSError as exc:
            raise self._filesystem_error(exc) from exc

    def _create_directory(self, path_value: str, parents: bool) -> dict[str, Any]:
        path = self.policy.resolve(path_value)
        if path.exists():
            if path.is_dir():
                return {"path": self.policy.relative(path), "created": False}
            raise self._error("validation", "path_exists_as_file", "Path is not a directory")
        if not parents and not path.parent.exists():
            raise self._error(
                "not_found",
                "parent_directory_not_found",
                "Parent directory does not exist",
            )
        try:
            path.mkdir(parents=parents, exist_ok=False)
            return {"path": self.policy.relative(path), "created": True}
        except OSError as exc:
            raise self._filesystem_error(exc) from exc

    def _delete_path(self, path_value: str, recursive: bool) -> dict[str, Any]:
        lexical = self._lexical_path(path_value)
        is_symlink = lexical.is_symlink()
        path = self.policy.resolve(
            path_value,
            must_exist=not is_symlink,
            allow_root=False,
        )
        try:
            if is_symlink:
                lexical.unlink()
            elif path.is_dir():
                if recursive:
                    shutil.rmtree(path)
                else:
                    path.rmdir()
            else:
                path.unlink()
            self._read_state.pop(path, None)
            relative = self.policy.relative_lexical(lexical) if is_symlink else self.policy.relative(path)
            return {"path": relative, "deleted": True}
        except OSError as exc:
            if isinstance(exc, OSError) and getattr(exc, "errno", None) in {
                errno.ENOTEMPTY,
                errno.EEXIST,
            }:
                raise self._error(
                    "conflict",
                    "directory_not_empty",
                    "Directory is not empty; set recursive to true",
                ) from exc
            raise self._filesystem_error(exc) from exc

    def _list_directory(
        self,
        path_value: str,
        recursive: bool,
        max_entries: int,
    ) -> dict[str, Any]:
        path = self.policy.resolve(path_value, must_exist=True)
        try:
            exists = path.exists()
            is_directory = path.is_dir() if exists else False
        except OSError as exc:
            raise self._filesystem_error(exc) from exc
        if not exists:
            raise self._error("semantic", "path_not_found", "Directory disappeared while it was being listed")
        if not is_directory:
            raise self._error("validation", "not_a_directory", "Path is not a directory")

        entries: list[dict[str, Any]] = []
        pending = [path]
        while pending and len(entries) < max_entries:
            current = pending.pop(0)
            try:
                children = sorted(current.iterdir(), key=lambda item: item.name)
            except FileNotFoundError as exc:
                if current == path:
                    raise self._error(
                        "semantic", "path_not_found", "Directory disappeared while it was being listed"
                    ) from exc
                # A recursive child may legitimately disappear between the
                # parent snapshot and the walk; continue with the remaining
                # snapshot instead of surfacing an internal error.
                continue
            except OSError as exc:
                if current == path:
                    raise self._filesystem_error(exc) from exc
                continue
            for child in children:
                if len(entries) >= max_entries:
                    break
                # Atomic writes use this private suffix while replacing a
                # file. It is never a user-visible workspace entry.
                if child.name.endswith(".system-tools.tmp"):
                    continue
                try:
                    if child.is_symlink():
                        entry_type = "symlink"
                        size = None
                        self.policy.resolve(child, must_exist=True)
                    elif child.is_dir():
                        entry_type = "directory"
                        size = None
                        if recursive:
                            pending.append(child)
                    elif child.is_file():
                        entry_type = "file"
                        size = child.stat().st_size
                    else:
                        entry_type = "other"
                        size = None
                except (SystemToolError, OSError):
                    # A child can be renamed or removed while it is being
                    # inspected. Listing is a best-effort snapshot; skip
                    # only that entry and keep the rest of the directory.
                    continue
                try:
                    relative = (
                        self.policy.relative_lexical(child)
                        if child.is_symlink()
                        else self.policy.relative(child)
                    )
                except (SystemToolError, OSError):
                    continue
                entries.append(
                    {
                        "path": relative,
                        "name": child.name,
                        "type": entry_type,
                        "size_bytes": size,
                    }
                )

        return {
            "path": self.policy.relative(path),
            "entries": entries,
            "truncated": bool(pending) or len(entries) >= max_entries,
        }

    def _glob(self, pattern: str, path_value: str, max_results: int) -> dict[str, Any]:
        self.policy.validate_pattern(pattern)
        base = self.policy.resolve(path_value, must_exist=True)
        if not base.is_dir():
            raise self._error("validation", "not_a_directory", "Search base is not a directory")

        matches: list[str] = []
        for candidate_string in glob_module.iglob(
            str(base / pattern),
            recursive=True,
            include_hidden=True,
        ):
            candidate = Path(candidate_string)
            try:
                resolved = self.policy.resolve(candidate, must_exist=True)
            except SystemToolError:
                continue
            relative = self.policy.relative_lexical(candidate)
            if relative not in matches:
                matches.append(relative)
            if len(matches) >= max_results:
                break
        matches.sort()
        return {
            "pattern": pattern,
            "path": self.policy.relative(base),
            "matches": matches,
            "truncated": len(matches) >= max_results,
        }

    def _grep(
        self,
        pattern: str,
        path_value: str,
        file_glob: str | None,
        ignore_case: bool,
        max_results: int,
    ) -> dict[str, Any]:
        try:
            regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise self._error("validation", "invalid_regex", "Invalid regular expression") from exc

        base = self.policy.resolve(path_value, must_exist=True)
        if base.is_file():
            candidates = [base]
        elif base.is_dir():
            candidates = self._search_files(base, file_glob)
        else:
            raise self._error("validation", "unsupported_search_path", "Path is not searchable")

        matches: list[dict[str, Any]] = []
        files_scanned = 0
        skipped_binary = 0
        for candidate in candidates:
            if len(matches) >= max_results:
                break
            try:
                if candidate.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                data = candidate.read_bytes()
                text = self._decode_text(data)
            except (UnicodeDecodeError, SystemToolError):
                skipped_binary += 1
                continue
            except OSError as exc:
                raise self._filesystem_error(exc) from exc

            files_scanned += 1
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = regex.search(line)
                if match is None:
                    continue
                matches.append(
                    {
                        "file_path": self.policy.relative(candidate),
                        "line_number": line_number,
                        "line": line[:MAX_GREP_MATCH_TEXT],
                        "match": match.group(0)[:MAX_GREP_MATCH_TEXT],
                    }
                )
                if len(matches) >= max_results:
                    break

        return {
            "pattern": pattern,
            "path": self.policy.relative(base),
            "matches": matches,
            "files_scanned": files_scanned,
            "skipped_binary": skipped_binary,
            "truncated": len(matches) >= max_results,
        }

    def _search_files(self, base: Path, file_glob: str | None) -> list[Path]:
        pattern = file_glob or "**/*"
        self.policy.validate_pattern(pattern)
        candidates: list[Path] = []
        for candidate_string in glob_module.iglob(
            str(base / pattern),
            recursive=True,
            include_hidden=True,
        ):
            candidate = Path(candidate_string)
            if not candidate.is_file() or candidate.is_symlink():
                continue
            try:
                self.policy.resolve(candidate, must_exist=True)
            except SystemToolError:
                continue
            candidates.append(candidate)
        return sorted(candidates)

    def _read_current_text(self, path: Path) -> tuple[str, FileSnapshot]:
        try:
            data = path.read_bytes()
            if len(data) > MAX_READ_BYTES:
                raise self._error(
                    "validation",
                    "file_too_large",
                    "File is too large to modify safely",
                )
            text = self._decode_text(data)
            return text, self._snapshot(path, data, True)
        except SystemToolError:
            raise
        except UnicodeDecodeError as exc:
            raise self._error(
                "validation",
                "binary_file",
                "Binary files cannot be modified as text",
            ) from exc
        except OSError as exc:
            raise self._filesystem_error(exc) from exc

    def _require_fresh_full_read(self, path: Path, current: FileSnapshot) -> None:
        previous = self._read_state.get(path)
        if previous is None or not previous.full_read:
            raise self._error(
                "conflict",
                "file_not_read",
                "Read the complete file before modifying it",
            )
        if previous != current:
            raise self._error(
                "conflict",
                "file_modified_since_read",
                "File changed after it was read; read it again before modifying it",
            )

    @staticmethod
    def _decode_text(data: bytes) -> str:
        if b"\x00" in data:
            raise SystemToolError(
                error_type="validation",
                code="binary_file",
                message="Binary files cannot be read as text",
            )
        return data.decode("utf-8")

    @staticmethod
    def _snapshot(path: Path, data: bytes | None, full_read: bool) -> FileSnapshot:
        metadata = path.stat()
        digest = hashlib.sha256(data).hexdigest() if data is not None else None
        return FileSnapshot(metadata.st_mtime_ns, metadata.st_size, digest, full_read)

    @staticmethod
    def _atomic_write(path: Path, content: str, mode: int) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".system-tools.tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), stat.S_IMODE(mode))
            os.replace(temporary_path, path)
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _mode_for(path: Path) -> int:
        try:
            return path.stat().st_mode
        except FileNotFoundError:
            return 0o644

    def _lexical_path(self, value: str) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.policy.root / candidate
        return Path(os.path.abspath(os.path.normpath(candidate)))

    @staticmethod
    def _error(
        error_type: str,
        code: str,
        message: str,
        detail: Any = None,
    ) -> SystemToolError:
        return SystemToolError(
            error_type=error_type,
            code=code,
            message=message,
            detail=detail,
        )

    @staticmethod
    def _filesystem_error(exc: OSError) -> SystemToolError:
        if isinstance(exc, PermissionError):
            return FileSystemService._error(
                "permission",
                "filesystem_permission_denied",
                "The filesystem denied this operation",
            )
        if isinstance(exc, FileNotFoundError):
            return FileSystemService._error(
                "not_found",
                "path_not_found",
                "Path does not exist",
            )
        return FileSystemService._error(
            "internal",
            "filesystem_error",
            "The filesystem operation could not be completed",
        )
