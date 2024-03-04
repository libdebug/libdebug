#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Gabriele Digregorio.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from time import perf_counter

from libdebug import debugger, libcontext

d = debugger("binaries/node")

r = d.start()

# Let ignore debuginfod for this test to avoid inconsistencies due to network
with libcontext.tmp(sym_lvl=4):
    # Try resolving a non-existent symbol, which will force the resolution of all symbols.
    t1_start = perf_counter()
    try:
        d.memory["provola", 2]
    except Exception:
        pass
    t1_stop = perf_counter()
    print("Elapsed time during the symbols resolution in seconds:", t1_stop - t1_start)

d.kill()
