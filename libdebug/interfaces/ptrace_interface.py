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

from ctypes import (
    CDLL,
    c_char_p,
    c_int,
    c_long,
    get_errno,
    set_errno,
)
import errno
from libdebug.interfaces.debugging_interface import DebuggingInterface
import logging
from libdebug.utils.ptrace_constants import (
    PTRACE_ATTACH,
    PTRACE_CONT,
    PTRACE_DETACH,
    PTRACE_SETOPTIONS,
    PTRACE_SINGLESTEP,
    PTRACE_TRACEME,
    PTRACE_O_TRACEFORK,
    PTRACE_O_TRACEVFORK,
    PTRACE_O_TRACECLONE,
    PTRACE_O_TRACEEXIT,
)
import os


class PtraceInterface(DebuggingInterface):
    """The interface used by `Debugger` to communicate with the `ptrace` debugging backend."""

    def __init__(self):
        self.libc = CDLL("libc.so.6", use_errno=True)
        self.args_ptr = [c_int, c_long, c_long, c_char_p]
        self.args_int = [c_int, c_long, c_long, c_long]
        self.libc.ptrace.argtypes = self.args_ptr
        self.libc.ptrace.restype = c_long

        # The PID of the process being traced
        self.process_id = None

    def _set_options(self):
        """Sets the tracer options."""
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        options = (
            PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXIT
        )
        result = self.libc.ptrace(PTRACE_SETOPTIONS, self.process_id, 0, options)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])

    def _trace_self(self):
        """Traces the current process."""
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])

    def run(self, argv: str | list[str]) -> int:
        """Runs the specified process.

        Args:
            argv (str | list[str]): The command line to execute.

        Returns:
            int: The PID of the process.
        """
        logging.debug("Running %s", argv)
        child_pid = os.fork()
        if child_pid == 0:
            self._setup_child(argv)
            assert False
        else:
            self.process_id = child_pid
            return self._setup_parent()

    def _setup_child(self, argv):
        self._trace_self()

        try:
            if isinstance(argv, str):
                argv = [argv]

            os.execv(argv[0], argv)
        except OSError as e:
            logging.error("Unable to execute %s: %s", argv, e)
            os._exit(1)

    def _setup_parent(self):
        logging.debug("Polling child process status")
        self.wait_for_child()
        logging.debug("Child process ready, setting options")
        self._set_options()
        logging.debug("Options set, continuing execution")

    def attach(self, process_id: int):
        """Attaches to the specified process.

        Args:
            process_id (int): The PID of the process to attach to.
        """
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        # TODO: investigate errno handling
        set_errno(0)
        result = self.libc.ptrace(PTRACE_ATTACH, process_id, 0, 0)
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])
        else:
            self.process_id = process_id
            logging.debug("Attached PtraceInterface to process %d", process_id)

    def shutdown(self):
        """Shuts down the debugging backend."""
        if self.process_id is None:
            return

        try:
            os.kill(self.process_id, 9)
        except OSError:
            logging.debug("Process %d already dead", self.process_id)

        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_DETACH, self.process_id, 0, 0)

        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])

        os.wait()
        self.process_id = None

    def get_register_holder(self):
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    def wait_for_child(self):
        """Waits for the child process to be ready for commands."""
        assert self.process_id is not None
        # TODO: check what option this is, because I can't find it anywhere
        pid, status = os.waitpid(self.process_id, 1 << 30)
        logging.debug("Child process %d reported status %d", pid, status)

        if os.WIFEXITED(status):
            logging.debug("Child process %d exited with status %d", pid, status)

    def continue_execution(self):
        """Continues the execution of the process."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_CONT, self.process_id, 0, 0)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])

    def step_execution(self):
        """Executes a single instruction before stopping again."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_SINGLESTEP, self.process_id, 0, 0)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])
