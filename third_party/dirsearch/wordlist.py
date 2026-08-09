# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .exceptions import WordlistLimitError
from .settings import DATA_DIR, EXTENSION_TAG, WORDLIST_CATEGORIES, WORDLIST_CATEGORY_DIR
from .structures import OrderedSet


TOKEN_RE = re.compile(r"%([A-Z0-9_:/-]+)%", re.IGNORECASE)


DEFAULT_PLACEHOLDERS: dict[str, tuple[str, ...]] = {
    "SUBJECT": (
        "user",
        "users",
        "account",
        "accounts",
        "profile",
        "article",
        "articles",
        "post",
        "posts",
        "product",
        "products",
        "order",
        "orders",
        "invoice",
        "invoices",
    ),
    "CRUD_OP": (
        "create",
        "read",
        "update",
        "delete",
        "list",
        "get",
        "add",
        "edit",
        "remove",
        "search",
    ),
    "AUTH_OP": (
        "login",
        "logout",
        "signin",
        "signout",
        "signup",
        "register",
        "reset",
        "forgot",
        "password",
        "oauth",
        "sso",
    ),
    "ADMIN_OP": (
        "admin",
        "dashboard",
        "panel",
        "manage",
        "settings",
        "users",
        "roles",
        "permissions",
    ),
    "ENV": ("dev", "development", "test", "stage", "staging", "prod", "production", "local"),
    "SEP": ("-", "_", ".", "/"),
    "DB": ("mysql", "postgres", "postgresql", "sqlite", "mariadb", "mongodb", "redis"),
    "DB_ENGINE": ("mysql", "postgres", "postgresql", "sqlite", "mariadb", "mongodb", "redis"),
    "ARCHIVE": ("zip", "tar", "tar.gz", "tgz", "gz", "7z", "rar", "bak"),
    "ARCHIVE_EXT": ("zip", "tar", "tar.gz", "tgz", "gz", "7z", "rar", "bak"),
    "API_VERSION": ("v1", "v2", "v3", "v4", "latest", "beta"),
}


def normalize_placeholders(
    placeholders: Mapping[str, Iterable[str] | str] | None,
) -> dict[str, tuple[str, ...]]:
    normalized: dict[str, tuple[str, ...]] = {}
    for key, values in (placeholders or {}).items():
        token = key.strip("%").upper()
        if isinstance(values, str):
            normalized[token] = (values,)
        else:
            normalized[token] = tuple(str(value) for value in values)
    return normalized


def expand_template_line(
    line: str,
    *,
    extensions: Iterable[str] = (),
    placeholders: Mapping[str, Iterable[str] | str] | None = None,
) -> Iterator[str]:
    values = _placeholder_values(extensions, placeholders)
    tokens: list[str] = []
    for token in TOKEN_RE.findall(line):
        normalized = token.upper()
        if normalized in tokens:
            continue
        if _resolve_token(normalized, values) is not None:
            tokens.append(normalized)
    if not tokens:
        yield line
        return
    expansions = [_resolve_token(token, values) for token in tokens]
    if any(expansion is None for expansion in expansions):
        yield line
        return
    if any(not expansion for expansion in expansions):
        return
    for combo in itertools.product(*expansions):
        rendered = line
        for token, value in zip(tokens, combo):
            rendered = re.sub(
                f"%{re.escape(token)}%",
                lambda _match, replacement=value: replacement,
                rendered,
                flags=re.IGNORECASE,
            )
        yield rendered


def _placeholder_values(
    extensions: Iterable[str],
    placeholders: Mapping[str, Iterable[str] | str] | None,
) -> dict[str, tuple[str, ...]]:
    today = date.today()
    values = dict(DEFAULT_PLACEHOLDERS)
    values.update(
        {
            EXTENSION_TAG.strip("%").upper(): tuple(extensions),
            "YYYY": (today.strftime("%Y"),),
            "YY": (today.strftime("%y"),),
            "MM": (today.strftime("%m"),),
            "DD": (today.strftime("%d"),),
            "DATE": (today.isoformat(),),
            "DATE_COMPACT": (today.strftime("%Y%m%d"),),
        }
    )
    values.update(normalize_placeholders(placeholders))
    return values


def _resolve_token(token: str, values: Mapping[str, tuple[str, ...]]) -> tuple[str, ...] | None:
    if token.startswith("CATEGORY:"):
        return _load_category(token.split(":", 1)[1].lower())
    return values.get(token)


def _load_category(name: str) -> tuple[str, ...]:
    if not re.fullmatch(r"[a-z0-9_./-]+", name):
        return ()
    filename = WORDLIST_CATEGORIES.get(name)
    if filename:
        path = WORDLIST_CATEGORY_DIR / filename
    else:
        path = WORDLIST_CATEGORY_DIR / f"{name}.txt"
    if not path.is_file():
        return ()
    return tuple(
        line.strip().lstrip("/")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


@dataclass(frozen=True)
class WordlistState:
    items: tuple[str, ...]
    index: int = 0


class Wordlist:
    items: tuple[str, ...]

    def __init__(self, items: Iterable[str], *, max_entries: int | None = None) -> None:
        object.__setattr__(
            self,
            "items",
            tuple(self._dedupe(items, max_entries=max_entries)),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Wordlist":
        return cls(_file_lines(Path(path)))

    @classmethod
    def from_template(
        cls,
        template: "WordlistTemplate",
        *,
        extensions: Iterable[str] = (),
        placeholders: Mapping[str, Iterable[str] | str] | None = None,
        max_entries: int | None = None,
    ) -> "Wordlist":
        return cls(
            template.render(extensions=extensions, placeholders=placeholders),
            max_entries=max_entries,
        )

    @staticmethod
    def _dedupe(
        items: Iterable[str],
        *,
        max_entries: int | None = None,
    ) -> Iterator[str]:
        seen = OrderedSet()
        for item in items:
            path = item.strip().lstrip("/")
            if not path or path.startswith("#") or path in seen:
                continue
            seen.add(path)
            if max_entries is not None and len(seen) > max_entries:
                raise WordlistLimitError(
                    f"Generated wordlist exceeded max_entries ({max_entries})"
                )
            yield path

    def __iter__(self) -> Iterator[str]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def state(self, index: int = 0) -> WordlistState:
        return WordlistState(items=self.items, index=index)


@dataclass(frozen=True)
class WordlistTemplate:
    lines: tuple[str, ...]
    placeholders: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __init__(
        self,
        lines: Iterable[str],
        placeholders: Mapping[str, Iterable[str] | str] | None = None,
    ) -> None:
        object.__setattr__(self, "lines", tuple(lines))
        object.__setattr__(
            self,
            "placeholders",
            normalize_placeholders(placeholders or {}),
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        placeholders: Mapping[str, Iterable[str] | str] | None = None,
    ) -> "WordlistTemplate":
        return cls(_file_lines(Path(path)), placeholders=placeholders)

    @classmethod
    def from_builtin(
        cls,
        name: str,
        placeholders: Mapping[str, Iterable[str] | str] | None = None,
    ) -> "WordlistTemplate":
        filename = name.strip()
        if not filename:
            raise ValueError("Built-in template name is required")
        if not filename.endswith(".txt"):
            filename += ".txt"
        if Path(filename).name != filename:
            raise ValueError(f"Invalid built-in template name: {name}")
        path = DATA_DIR / "db" / "templates" / filename
        if not path.is_file():
            raise ValueError(f"Unknown built-in template: {name}")
        return cls.from_file(path, placeholders=placeholders)

    def render(
        self,
        *,
        extensions: Iterable[str] = (),
        placeholders: Mapping[str, Iterable[str] | str] | None = None,
    ) -> Iterator[str]:
        values = {f"%{key}%": value for key, value in self.placeholders.items()}
        values.update(placeholders or {})
        for line in self.lines:
            yield from expand_template_line(
                line,
                extensions=extensions,
                placeholders=values,
            )


def _file_lines(path: Path) -> list[str]:
    return [
        line.rstrip("\r\n")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
