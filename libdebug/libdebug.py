#
# This file is part of libdebug Python library (https://github.com/gabriele180698/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

from libdebug.architectures.register_holder import RegisterHolder
from libdebug.data.breakpoint import Breakpoint
from libdebug.interfaces.interface_helper import debugging_interface_provider
from libdebug.utils.elf_utils import get_symbol_address
import logging
from queue import Queue
from typing import Callable, Self
from threading import Thread, Event


class Debugger:
    """The Debugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    def __init__(self, argv):
        """Do not use this constructor directly.
        Use the `debugger` function instead.
        """
        self.argv: str | list[str] = argv

        # running is True if and only if the process is currently running
        self.running = False

        # instanced is True if and only if the process has been started and has not been killed yet
        self.instanced = False

        # threading utilities
        self.polling_thread: Thread | None = None
        self.polling_thread_start_event: Event = Event()
        self.polling_thread_command_queue: Queue = Queue()

        # additional attributes
        self.registers: RegisterHolder = None
        self.breakpoints: dict[int, Breakpoint] = {}

    def __del__(self):
        self.kill()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.kill()
        return False

    def _poll_registers(self):
        """Updates the register values."""
        self.registers = self.interface.get_register_holder()
        self.registers.apply_on(self, Debugger)

    def _flush_registers(self):
        self.registers.flush(self)

    def start(self):
        """Starts the process. This method must be called before any other method, and any time the process needs to be restarted."""
        if self.instanced:
            self.kill()

        self.interface = debugging_interface_provider(self.argv)
        self._setup_polling_thread()
        self.polling_thread_start_event.set()
        self.instanced = True

    def kill(self):
        """Kills the process."""
        if self.polling_thread:
            self.polling_thread.join(timeout=5.0)
        self.interface.shutdown()
        self.polling_thread.join(timeout=5.0)
        self.instanced = False

    def _flush_and_cont_after_bp(self, breakpoint: Breakpoint):
        """Flushes the registers, resumes the execution of the process, and re-sets the breakpoint at the specified address."""
        self.registers.flush(self)
        self.interface.restore_breakpoint(breakpoint.address, breakpoint.hardware)
        # step over the breakpoint
        self.interface.step_execution()
        self.interface.wait_for_child()
        self._poll_registers()
        # re-set the breakpoint
        self.interface.set_breakpoint(breakpoint.address, breakpoint.hardware)
        # continue the execution
        self.interface.continue_execution()
        self.running = True

    def _flush_and_cont(self):
        """Flushes the registers and continues the execution of the process."""
        self.registers.flush(self)
        self.interface.continue_execution()
        self.running = True

    def _flush_and_step(self):
        """Flushes the registers and executes a single instruction before stopping again."""
        self.registers.flush(self)
        self.interface.step_execution()
        self.running = True

    def cont(self):
        """Continues the execution of the process."""
        if self.running:
            raise RuntimeError("Cannot continue while the process is running.")
        self.polling_thread_command_queue.put((self._flush_and_cont, ()))

    def block(self):
        """Stops the execution of the process."""
        pass

    def step(self):
        """Executes a single instruction before stopping again."""
        if self.running:
            raise RuntimeError(
                "Cannot step while the process is running. Block it first."
            )
        self.polling_thread_command_queue.put((self._flush_and_step, ()))

    def b(
        self,
        location: int | str,
        callback: None | Callable[[Self, Breakpoint], None] = None,
        hardware_assisted: bool = False,
    ):
        """Sets a breakpoint at the specified location. The callback will be executed when the breakpoint is hit.

        Args:
            location (int | bytes): The location of the breakpoint.
            callback (None | callable, optional): The callback to call when the breakpoint is hit. Defaults to None.
            hardware_assisted (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
        """
        if self.running:
            raise RuntimeError("Cannot set a breakpoint while the process is running.")

        if isinstance(location, str):
            address = get_symbol_address(self.argv[0], location)
            breakpoint = Breakpoint(address, location, 0, hardware_assisted, callback)
        else:
            address = location
            breakpoint = Breakpoint(location, None, 0, hardware_assisted, callback)

        self.breakpoints[address] = breakpoint

        self.polling_thread_command_queue.put(
            (self.interface.set_breakpoint, (address, hardware_assisted))
        )

    def jump(self, location: int | bytes):
        """Jumps to the specified location.

        Args:
            location (int | bytes): The location to jump to.
        """
        pass

    def maps(self):
        """Returns the memory maps of the process."""
        return self.interface.maps()

    def fds(self):
        """Returns the file descriptors of the process."""
        return self.interface.fds()

    def _polling_thread_function(self):
        """The function executed by the polling thread."""
        while True:
            if not self.polling_thread_command_queue.empty():
                command, args = self.polling_thread_command_queue.get()
                command(*args)
            elif self.polling_thread_start_event.is_set():
                self.polling_thread_start_event.clear()
                logging.debug("Starting process %s", self.argv[0])
                self.interface.run(self.argv)
                self._poll_registers()
            elif self.running:
                logging.debug("Polling process %s for state change", self.argv[0])

                if not self.interface.wait_for_child():
                    # The process has exited
                    break

                self.running = False
                self._poll_registers()

                # TODO: this -1 is dependent on the architecture's instruction size
                if (
                    self.rip not in self.breakpoints
                    and (self.rip - 1) in self.breakpoints
                ):
                    # Sometimes the process stops at the instruction after the breakpoint
                    # TODO: investigate why
                    address = self.rip - 1
                else:
                    address = self.rip

                if address in self.breakpoints:
                    breakpoint = self.breakpoints[address]
                    # Restore RIP
                    self.rip = address
                    if breakpoint._callback:
                        breakpoint._callback(self, breakpoint)
                    self._flush_and_cont_after_bp(breakpoint)
                else:
                    logging.debug(
                        "Stopped at: %x but no breakpoint set, continuing", self.rip
                    )
                    self._flush_and_cont()

    def _setup_polling_thread(self):
        """Sets up the thread that polls the process for changes."""
        self.polling_thread = Thread(target=self._polling_thread_function)
        self.polling_thread.start()


def debugger(argv: str | list[str]) -> Debugger:
    """This function is used to create a new `Debugger` object. It takes as input the location of the binary to debug and returns a `Debugger` object.

    Args:
        argv (str | list[str]): The location of the binary to debug, and any additional arguments to pass to it.

    Returns:
        Debugger: The `Debugger` object.
    """

    return Debugger(argv)
