#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini, Gabriele Digregorio.
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

from libdebug import debugger, libcontext

d = debugger("binaries/basic_test")

libcontext.terminal = ["tmux", "splitw", "-h"]
# libcontext.terminal = ["gnome-terminal", "--tab", "--"]

d.run()

bp = d.breakpoint("register_test")

d.step()
d.step()

print(hex(d.rip))

d.migrate_to_gdb()

print(hex(d.rip))

d.cont()
d.wait()

print(hex(d.rip))

d.step()

print(hex(d.rip))

d.kill()
