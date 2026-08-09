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

import asyncio
import re
from collections.abc import Awaitable, Callable, Generator, Iterable
from dataclasses import dataclass
from typing import Any

from .diff import (
    DynamicContentParser,
    content_similarity,
    generate_matching_regex,
    normalize_dynamic_content,
)
from .random import rand_stealth_word
from .settings import REFLECTED_PATH_MARKER, WILDCARD_TEST_POINT_MARKER
from .urlutils import clean_path, replace_path


AUTO_CALIBRATION_EXTRA_SAMPLES = 2
AUTO_CALIBRATION_DUPLICATE_THRESHOLD = 8
AUTO_CALIBRATION_FORCED_THRESHOLD = 3
AUTO_CALIBRATION_MIN_CONTENT_LENGTH = 32
AMBIGUOUS_SIMILARITY_THRESHOLD = 0.9
AMBIGUOUS_SIMILARITY_MAX_CONTENT_LENGTH = 262144

RequestCallable = Callable[[str], Awaitable["ProbeResponse"]]


@dataclass
class ProbeResponse:
    url: str
    path: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    content: str
    redirect: str
    length: int
    type: str
    elapsed: float
    outcome: str = "response"
    error: str | None = None
    final_url: str = ""
    body_complete: bool = True
    line_count: int = 0

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ProbeResponse)
            and (self.status, self.body, self.redirect)
            == (other.status, other.body, other.redirect)
        )


class WildcardScanner:
    def __init__(
        self,
        *,
        path: str = "",
        tested: dict[str, dict[str, "WildcardScanner"]] | None = None,
        context: str = "all cases",
        auto_calibration: bool = False,
        delay: float = 0.0,
    ) -> None:
        self.path = path
        self.tested = tested
        self.context = context
        self.auto_calibration = auto_calibration
        self.delay = delay
        self.response: ProbeResponse | None = None
        self.wildcard_redirect_regex: str | None = None
        self.sample_count = 0
        self.reason = ""
        self.content_parser: DynamicContentParser | None = None

    async def setup(self, requester: RequestCallable) -> None:
        first_path = self.path.replace(WILDCARD_TEST_POINT_MARKER, rand_stealth_word())
        first_response = await requester(first_path)
        self.response = first_response
        self.sample_count = 1
        if self.delay:
            await asyncio.sleep(self.delay)
        duplicate = self.get_duplicate(first_response)
        if duplicate is not None:
            self.content_parser = duplicate.content_parser
            self.wildcard_redirect_regex = duplicate.wildcard_redirect_regex
            return
        second_path = self.path.replace(
            WILDCARD_TEST_POINT_MARKER,
            rand_stealth_word(omit=first_path),
        )
        second_response = await requester(second_path)
        self.sample_count += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if first_response.redirect and second_response.redirect:
            self.wildcard_redirect_regex = self.generate_redirect_regex(
                clean_path(first_response.redirect),
                first_path,
                clean_path(second_response.redirect),
                second_path,
            )
        self.content_parser = DynamicContentParser(
            first_response.content, second_response.content
        )
        await self.auto_calibrate((first_path, second_path), requester)

    async def auto_calibrate(self, tested_paths: tuple[str, ...], requester: RequestCallable) -> None:
        if not self.should_auto_calibrate():
            return
        omitted = set(tested_paths)
        for _ in range(AUTO_CALIBRATION_EXTRA_SAMPLES):
            sample_path = self.path.replace(
                WILDCARD_TEST_POINT_MARKER,
                rand_stealth_word(omit=omitted),
            )
            omitted.add(sample_path)
            sample_response = await requester(sample_path)
            self.add_calibration_sample(sample_response)
            if self.delay:
                await asyncio.sleep(self.delay)

    def get_duplicate(self, response: ProbeResponse) -> "WildcardScanner | None":
        for category in self.tested or {}:
            for tester in (self.tested or {}).get(category, {}).values():
                if tester is self:
                    continue
                if response == tester.response:
                    return tester
        return None

    def check(self, path: str, response: ProbeResponse) -> bool:
        return self.classify(path, response) != "wildcard"

    def classify(self, path: str, response: ProbeResponse) -> str:
        if self.response is None or self.content_parser is None:
            return "unique"
        if self.response.status != response.status:
            self.reason = "status differs from wildcard profile"
            return "unique"
        if self.wildcard_redirect_regex and response.redirect:
            redirect = replace_path(
                clean_path(response.redirect),
                clean_path(path),
                REFLECTED_PATH_MARKER,
            )
            if not re.match(self.wildcard_redirect_regex, redirect, re.IGNORECASE):
                self.reason = "redirect differs from wildcard profile"
                return "unique"
        if self.is_wildcard(response):
            self.reason = "matches wildcard profile"
            return "wildcard"
        if self.is_probable_wildcard(path, response):
            self.reason = "matches ambiguous wildcard profile"
            return "wildcard"
        self.reason = "response is unique enough"
        return "unique"

    def is_wildcard(self, response: ProbeResponse) -> bool:
        if self.response is None or self.content_parser is None:
            return False
        if not self.response.content and not response.content:
            return self.response.body == response.body
        return self.content_parser.compare_to(response.content)

    def is_probable_wildcard(self, path: str, response: ProbeResponse) -> bool:
        if self.response is None or self.content_parser is None:
            return False
        if not self.response.content or not response.content:
            return False
        if self.response.type != response.type:
            return False
        if self.response.redirect and not response.redirect:
            return False
        if self.content_parser.static_patterns and len(self.content_parser.static_patterns) >= 20:
            return False
        if (
            len(self.response.content) > AMBIGUOUS_SIMILARITY_MAX_CONTENT_LENGTH
            or len(response.content) > AMBIGUOUS_SIMILARITY_MAX_CONTENT_LENGTH
        ):
            return False
        similarity = content_similarity(self.response.content, response.content)
        if similarity < AMBIGUOUS_SIMILARITY_THRESHOLD:
            return False
        base_length = max(self.response.length, 1)
        length_delta = abs(self.response.length - response.length) / base_length
        if length_delta > 0.35:
            return False
        normalized_content = normalize_dynamic_content(response.content)
        normalized_path = clean_path(path).strip("/")
        if normalized_path and normalized_path in normalized_content:
            return True
        return self.content_parser.is_ambiguous

    def should_auto_calibrate(self) -> bool:
        return bool(self.auto_calibration) or bool(
            self.content_parser and self.content_parser.is_ambiguous
        )

    def add_calibration_sample(self, response: ProbeResponse) -> None:
        self.sample_count += 1
        if response.content and self.content_parser is not None:
            self.content_parser.add_sample(response.content)

    @staticmethod
    def generate_redirect_regex(
        first_loc: str,
        first_path: str,
        second_loc: str,
        second_path: str,
    ) -> str:
        if first_path:
            first_loc = first_loc.replace("/" + first_path, REFLECTED_PATH_MARKER)
        if second_path:
            second_loc = second_loc.replace("/" + second_path, REFLECTED_PATH_MARKER)
        return generate_matching_regex(first_loc, second_loc)


def build_scanner_map(
    base_path: str,
    *,
    extensions: Iterable[str] = (),
    prefixes: Iterable[str] = (),
    suffixes: Iterable[str] = (),
    auto_calibration: bool = False,
    delay: float = 0.0,
) -> dict[str, dict[str, WildcardScanner]]:
    scanners: dict[str, dict[str, WildcardScanner]] = {
        "default": {},
        "prefixes": {},
        "suffixes": {},
    }
    scanners["default"]["random"] = WildcardScanner(
        path=f"{base_path}{WILDCARD_TEST_POINT_MARKER}",
        tested=scanners,
        context="all cases",
        auto_calibration=auto_calibration,
        delay=delay,
    )
    for prefix in prefixes:
        scanners["prefixes"][prefix] = WildcardScanner(
            path=f"{base_path}{prefix}{WILDCARD_TEST_POINT_MARKER}",
            tested=scanners,
            context=f"/{base_path}{prefix}***",
            auto_calibration=auto_calibration,
            delay=delay,
        )
    for suffix in suffixes:
        scanners["suffixes"][suffix] = WildcardScanner(
            path=f"{base_path}{WILDCARD_TEST_POINT_MARKER}{suffix}",
            tested=scanners,
            context=f"/{base_path}***{suffix}",
            auto_calibration=auto_calibration,
            delay=delay,
        )
    for extension in extensions:
        suffix = f".{extension}"
        if suffix not in scanners["suffixes"]:
            scanners["suffixes"][suffix] = WildcardScanner(
                path=f"{base_path}{WILDCARD_TEST_POINT_MARKER}{suffix}",
                tested=scanners,
                context=f"/{base_path}***{suffix}",
                auto_calibration=auto_calibration,
                delay=delay,
            )
    return scanners


def applicable_scanners(
    scanners: dict[str, dict[str, WildcardScanner]],
    path: str,
) -> Generator[WildcardScanner, None, None]:
    cleaned = clean_path(path)
    for prefix in scanners["prefixes"]:
        if cleaned.startswith(prefix):
            yield scanners["prefixes"][prefix]
    for suffix in scanners["suffixes"]:
        if cleaned.endswith(suffix):
            yield scanners["suffixes"][suffix]
    for scanner in scanners["default"].values():
        yield scanner


def response_fingerprint(response: ProbeResponse) -> tuple:
    path = clean_path(response.path).strip("/")
    body = normalize_dynamic_content(response.content)
    redirect = clean_path(response.redirect)
    if path:
        body = body.replace(path, "__PATH__")
        redirect = redirect.replace(path, "__PATH__")
    return (
        response.status,
        response.type,
        redirect,
        len(body) // 64,
        hash(body[:4096]),
    )
