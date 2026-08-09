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

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .exceptions import WordlistLimitError
from .structures import OrderedSet
from .urlutils import clean_path, lstrip_once
from .wordlist import expand_template_line


@dataclass(frozen=True)
class WordlistConfig:
    extensions: tuple[str, ...] = ()
    force_extensions: bool = False
    exclude_extensions: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()
    max_size: int = 50_000
    lowercase: bool = False
    uppercase: bool = False
    capitalization: bool = False


def generate_wordlist(files: Iterable[Path], config: WordlistConfig) -> list[str]:
    lines: list[str] = []
    for path in files:
        source = Path(path)
        lines.extend(source.read_text(encoding="utf-8").splitlines())
    return generate_wordlist_lines(lines, config)


def generate_wordlist_lines(lines: Iterable[str], config: WordlistConfig) -> list[str]:
    wordlist = OrderedSet()
    for line in lines:
        line = lstrip_once(line.strip(), "/")
        for expanded in expand_template_line(line, extensions=config.extensions):
            if not _is_valid(expanded, config):
                continue
            _add_wordlist_entry(wordlist, expanded, config)
            if not config.force_extensions or "." in expanded or expanded.endswith("/"):
                continue
            _add_wordlist_entry(wordlist, expanded + "/", config)
            for extension in config.extensions:
                _add_wordlist_entry(wordlist, f"{expanded}.{extension}", config)
    if not config.prefixes and not config.suffixes:
        return _transform(wordlist, config)
    altered = OrderedSet()
    for path in wordlist:
        for pref in config.prefixes:
            if not path.startswith(("/", pref)):
                _add_wordlist_entry(altered, pref + path, config)
        for suff in config.suffixes:
            if not path.endswith(("/", suff)) and "?" not in path and "#" not in path:
                _add_wordlist_entry(altered, path + suff, config)
    if altered:
        wordlist = altered
    return _transform(wordlist, config)


def _is_valid(path: str, config: WordlistConfig) -> bool:
    if not path or path.startswith("#"):
        return False
    cleaned_path = clean_path(path)
    if cleaned_path.endswith(tuple(f".{extension}" for extension in config.exclude_extensions)):
        return False
    return True


def _add_wordlist_entry(wordlist: OrderedSet, path: str, config: WordlistConfig) -> None:
    wordlist.add(path)
    if config.max_size and len(wordlist) > config.max_size:
        raise WordlistLimitError(
            f"Generated wordlist exceeded max size ({config.max_size})"
        )


def _transform(wordlist: OrderedSet, config: WordlistConfig) -> list[str]:
    if config.lowercase:
        return list(map(str.lower, wordlist))
    if config.uppercase:
        return list(map(str.upper, wordlist))
    if config.capitalization:
        return list(map(str.capitalize, wordlist))
    return list(wordlist)
