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

from dataclasses import dataclass


class Amd64StackUnwinding():
    """
    Class that provides stack unwinding for the x86_64 architecture.
    """

    def unwind(self, target, target_interface):
        """
        Unwind the stack of a process.
        """

        current_rbp = target.rbp
        stack_trace = [target.rip]

        while current_rbp:
            
            try:
                # Read the return address
                return_address = target_interface._peek_mem(current_rbp + 8)
                
                # Read the previous rbp and set it as the current one
                current_rbp = target_interface._peek_mem(current_rbp)
                
                stack_trace.append(return_address)
            except OSError:
                break

        return stack_trace
