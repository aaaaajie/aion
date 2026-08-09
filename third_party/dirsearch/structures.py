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

from typing import Any, Iterator


class OrderedSet:
    def __init__(self, items: list[Any] | None = None) -> None:
        self._data: dict[Any, None] = dict()
        for item in items or []:
            self._data[item] = None

    def __contains__(self, item: Any) -> bool:
        return item in self._data

    def __eq__(self, other: Any) -> bool:
        return self._data.keys() == other._data.keys()

    def __iter__(self) -> Iterator[Any]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def add(self, item: Any) -> None:
        self._data[item] = None

    def clear(self) -> None:
        self._data.clear()

    def discard(self, item: Any) -> None:
        self._data.pop(item, None)

    def update(self, items: list[Any]) -> None:
        for item in items:
            self.add(item)
