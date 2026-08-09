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

"""Slim dirsearch fork used by the AION path-probe engine.

Only the wordlist/template, wildcard-calibration and response-filtering
algorithms are vendored. Network, CLI, report, session, native and view
layers are intentionally absent; AION provides those.
"""

from .exceptions import WordlistLimitError
from .wordlist import Wordlist, WordlistState, WordlistTemplate
from .wordlist_backend import WordlistConfig, generate_wordlist, generate_wordlist_lines

__all__ = [
    "Wordlist",
    "WordlistConfig",
    "WordlistLimitError",
    "WordlistState",
    "WordlistTemplate",
    "generate_wordlist",
    "generate_wordlist_lines",
]
