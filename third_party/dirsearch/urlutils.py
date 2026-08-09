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

import re
from html import escape
from json import dumps
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .settings import URL_SAFE_CHARS


def lstrip_once(string: str, pattern: str) -> str:
    if string.startswith(pattern):
        return string[len(pattern) :]
    return string


def clean_path(path: str, keep_queries: bool = False, keep_fragment: bool = False) -> str:
    if not keep_fragment:
        path = path.split("#")[0]
    if not keep_queries:
        path = path.split("?")[0]
    return path


def safequote(string_: str) -> str:
    return quote(string_, safe=URL_SAFE_CHARS)


def replace_path(string: str, path: str, replace_with: str) -> str:
    def sub(value: str, to_replace: str, replacement: str) -> str:
        regex = re.escape(to_replace) + "(?=[^\\w]|$)"
        return re.sub(regex, replacement, value)

    path = "/" + path
    string = sub(string, quote(path), replace_with)
    string = sub(string, quote(quote(path)), replace_with)
    string = sub(string, unquote(path), replace_with)
    string = sub(string, unquote(unquote(path)), replace_with)
    string = sub(string, escape(path), replace_with)
    string = sub(string, dumps(path), replace_with)
    return sub(string, path, replace_with)


def ensure_trailing_path_slash(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path
    if not path.endswith("/"):
        path += "/"
    return urlunsplit(parsed._replace(path=path))


def append_query_string(value: str, query: str) -> str:
    if not query or "?" in value:
        return value
    path, separator, fragment = value.partition("#")
    value = f"{path}?{query}"
    if separator:
        value += f"#{fragment}"
    return value
