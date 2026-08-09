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

import difflib
import re

from .urlutils import lstrip_once

_DYNAMIC_TOKEN_REGEXES = (
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),
    re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+-]+Z?)?\b"),
    re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"),
    re.compile(r"\b\d{6,}\b"),
)

_HTML_ATTRIBUTE_VALUE_REGEX = re.compile(
    r"""(?i)\b(?:nonce|csrf|token|request[_-]?id|trace[_-]?id|session[_-]?id)=["'][^"']+["']"""
)


def normalize_dynamic_content(content: str) -> str:
    normalized = content
    normalized = _HTML_ATTRIBUTE_VALUE_REGEX.sub("__DYNAMIC_ATTR__", normalized)
    for regex in _DYNAMIC_TOKEN_REGEXES:
        normalized = regex.sub("__DYNAMIC__", normalized)
    return " ".join(normalized.split())


def content_similarity(content1: str, content2: str) -> float:
    return difflib.SequenceMatcher(
        None,
        normalize_dynamic_content(content1),
        normalize_dynamic_content(content2),
    ).ratio()


class DynamicContentParser:
    def __init__(self, content1: str, content2: str) -> None:
        self._static_patterns: list[str] | None = None
        self._differ = difflib.Differ()
        self._contents = [content1, content2]
        self._base_content = content1
        self._is_static = False
        self._recalculate()

    @property
    def static_patterns(self) -> list[str]:
        return self._static_patterns or []

    @property
    def is_ambiguous(self) -> bool:
        if self._is_static:
            return False
        return (
            len(self.static_patterns) < 8
            or self.similarity_to(self._contents[-1]) < 0.55
        )

    def add_sample(self, content: str) -> None:
        self._contents.append(content)
        self._recalculate()

    def compare_to(self, content: str) -> bool:
        if self._is_static:
            return (
                content == self._base_content
                or normalize_dynamic_content(content) == normalize_dynamic_content(self._base_content)
            )
        i = -1
        splitted_content = normalize_dynamic_content(content).split()
        misses = 0
        for pattern in self._static_patterns:
            try:
                i = splitted_content.index(pattern, i + 1)
            except ValueError:
                if misses or len(self._static_patterns) < 20:
                    return False
                misses += 1
        if (
            len(content.split()) > len(self._base_content.split())
            and len(self._static_patterns) < 20
        ):
            return self.similarity_to(content) > 0.75
        return True

    def similarity_to(self, content: str) -> float:
        return content_similarity(self._base_content, content)

    def _recalculate(self) -> None:
        self._is_static = all(content == self._base_content for content in self._contents)
        if self._is_static:
            self._static_patterns = []
            return
        first, second = (
            normalize_dynamic_content(self._contents[0]),
            normalize_dynamic_content(self._contents[1]),
        )
        patterns = self.get_static_patterns(
            self._differ.compare(first.split(), second.split())
        )
        for content in self._contents[2:]:
            normalized_words = normalize_dynamic_content(content).split()
            patterns = [pattern for pattern in patterns if pattern in normalized_words]
        self._static_patterns = patterns

    @staticmethod
    def get_static_patterns(patterns: list[str]) -> list[str]:
        return [lstrip_once(pattern, "  ") for pattern in patterns if pattern.startswith("  ")]


def generate_matching_regex(string1: str, string2: str) -> str:
    start = "^"
    end = "$"
    for char1, char2 in zip(string1, string2):
        if char1 != char2:
            start += ".*"
            break
        start += re.escape(char1)
    if start.endswith(".*"):
        for char1, char2 in zip(string1[::-1], string2[::-1]):
            if char1 != char2:
                break
            end = re.escape(char1) + end
    return start + end
