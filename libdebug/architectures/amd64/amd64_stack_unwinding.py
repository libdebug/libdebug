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


class Amd64StackUnwinding():
    """
    Class that provides stack unwinding for the x86_64 architecture.
    """

    def unwind(self, target: "Debugger") -> list:
        """
        Unwind the stack of a process.

        Args:
            target (Debugger): The target Debugger.
        
        Returns:
            list: A list of return addresses.
        """

        current_rbp = target.rbp
        stack_trace = [target.rip]

        while current_rbp:
            
            try:
                # Read the return address
                return_address = int.from_bytes(target.memory[current_rbp + 8, 8], byteorder="little")
                
                # Read the previous rbp and set it as the current one
                current_rbp = int.from_bytes(target.memory[current_rbp, 8], byteorder="little")
                
                stack_trace.append(return_address)
            except OSError:
                break

        return stack_trace
