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

import string
from pathlib import Path

VERSION = "0.5.0-aion-1"

DATA_DIR = Path(__file__).resolve().parent
WORDLIST_CATEGORY_DIR = DATA_DIR / "db" / "categories"
WORDLIST_CATEGORIES = {
    "conf": "conf.txt",
    "vcs": "vcs.txt",
    "backups": "backups.txt",
    "db": "db.txt",
    "logs": "logs.txt",
    "keys": "keys.txt",
    "web": "web.txt",
    "common": "common.txt",
}

DEFAULT_ENCODING = "utf-8"

DEFAULT_TEST_PREFIXES = (".", ".ht")
DEFAULT_TEST_SUFFIXES = ("/", "~")

DEFAULT_HEADERS = {
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
    ),
    "accept": "*/*",
    "accept-encoding": "*",
    "keep-alive": "timeout=15, max=1000",
    "cache-control": "max-age=0",
}

REFLECTED_PATH_MARKER = "__REFLECTED_PATH__"
WILDCARD_TEST_POINT_MARKER = "__WILDCARD_POINT__"
EXTENSION_TAG = "%ext%"

EXTENSION_RECOGNITION_REGEX = r"\w+([.][a-zA-Z0-9]{2,5}){1,3}~?$"
UNKNOWN = "unknown"
URL_SAFE_CHARS = string.punctuation

MAX_CONSECUTIVE_REQUEST_ERRORS = 25
