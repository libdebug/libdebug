#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini, Gabriele Digregorio.
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
    create_string_buffer,
    get_errno,
    set_errno,
)
import errno
from libdebug.utils.pipe_manager import PipeManager
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.architectures.register_holder import RegisterHolder
from libdebug.architectures.ptrace_hardware_breakpoint_provider import (
    ptrace_hardware_breakpoint_manager_provider,
)
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.utils.elf_utils import is_pie
from libdebug.utils.debugging_utils import normalize_and_validate_address
from libdebug.utils.process_utils import (
    get_process_maps,
    get_open_fds,
    guess_base_address,
    invalidate_process_cache,
    disable_self_aslr,
)
from libdebug.utils.ptrace_constants import (
    PTRACE_ATTACH,
    PTRACE_CONT,
    PTRACE_DETACH,
    PTRACE_GETREGS,
    PTRACE_PEEKDATA,
    PTRACE_POKEDATA,
    PTRACE_PEEKUSER,
    PTRACE_POKEUSER,
    PTRACE_SETOPTIONS,
    PTRACE_SETREGS,
    PTRACE_SINGLESTEP,
    PTRACE_TRACEME,
    PTRACE_O_TRACEFORK,
    PTRACE_O_TRACEVFORK,
    PTRACE_O_TRACECLONE,
    PTRACE_O_TRACEEXIT,
)
import logging
import os
import signal


class PtraceInterface(DebuggingInterface):
    """The interface used by `Debugger` to communicate with the `ptrace` debugging backend."""

    args_ptr = [c_int, c_long, c_long, c_char_p]
    args_int = [c_int, c_long, c_long, c_long]

    def __init__(self):
        self.libc = CDLL("libc.so.6", use_errno=True)

        # The PID of the process being traced
        self.process_id = None
        self.software_breakpoints = {}
        self.hardware_bp_helper = None

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

    def run(self, argv: str | list[str], enable_aslr: bool) -> int:
        """Runs the specified process.

        Args:
            argv (str | list[str]): The command line to execute.
            enable_aslr (bool): Whether to enable ASLR or not.

        Returns:
            int: The PID of the process.
        """

        logging.debug("Running %s", argv)

         # Creating pipes for stdin, stdout, stderr
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = os.pipe()
        self.stderr_read, self.stderr_write = os.pipe()

        child_pid = os.fork()
        if child_pid == 0:
            self._setup_child(argv, enable_aslr)
            assert False
        else:
            self.process_id = child_pid
            return self._setup_parent()

    def _setup_child(self, argv, enable_aslr):
        self._trace_self()

        try:
            # Close the write end for stdin and the read ends for stdout and stderr
            # in the child process since it is going to read from stdin and write to
            # stdout and stderr
            os.close(self.stdin_write)
            os.close(self.stdout_read)
            os.close(self.stderr_read)

            # Redirect stdin, stdout, and stderr of child process
            os.dup2(self.stdin_read, 0)
            os.dup2(self.stdout_write, 1)
            os.dup2(self.stderr_write, 2)

            # Close the original fds in the child process since now they are duplicated
            # by 0, 1, and 2 (they point to the same location)
            os.close(self.stdin_read)
            os.close(self.stdout_write)
            os.close(self.stderr_write)
        except Exception as e:
            # TODO: custom exception
            raise Exception("Redirecting stdin, stdout, and stderr failed: %r" % e)

        try:
            if isinstance(argv, str):
                argv = [argv]

            if not enable_aslr:
                disable_self_aslr()

            os.execv(argv[0], argv)
        except OSError as e:
            logging.error("Unable to execute %s: %s", argv, e)
            os._exit(1)

    def _setup_parent(self):
        # Close the read end for stdin and the write ends for stdout and stderr
        # in the parent process since we are going to write to stdin and read from
        # stdout and stderr
        try:
            os.close(self.stdin_read)
            os.close(self.stdout_write)
            os.close(self.stderr_write)
        except Exception as e:
            # TODO: custom exception
            raise Exception("Closing fds failed: %r" % e)

        logging.debug("Polling child process status")
        self.wait_for_child()
        logging.debug("Child process ready, setting options")
        self._set_options()
        logging.debug("Options set")
        invalidate_process_cache()
        self.hardware_bp_helper = ptrace_hardware_breakpoint_manager_provider(
            self._peek_user, self._poke_user
        )

        return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

        

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

        try:
            os.close(self.stdin_write)
            os.close(self.stdout_read)
            os.close(self.stderr_read)
        except Exception as e:
            logging.debug("Closing fds failed: %r", e)

        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_DETACH, self.process_id, 0, 0)
        if result != -1:
            logging.debug("Detached PtraceInterface from process %d", self.process_id)
            os.wait()
        else:
            logging.debug("Unable to detach, process %d already dead", self.process_id)
        self.process_id = None

    def get_register_holder(self) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        # TODO: investigate size of register file
        register_file = create_string_buffer(1024)
        self.libc.ptrace.argtypes = self.args_ptr
        self.libc.ptrace.restype = c_int
        # TODO: investigate errno handling
        set_errno(0)
        logging.debug("Getting registers from process %d", self.process_id)
        result = self.libc.ptrace(PTRACE_GETREGS, self.process_id, 0, register_file)
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])
        else:
            return register_holder_provider(
                register_file, ptrace_setter=self._set_registers
            )

    def _set_registers(self, buffer):
        """Sets the value of all the available registers."""
        self.libc.ptrace.argtypes = self.args_ptr
        self.libc.ptrace.restype = c_int
        native_buffer = create_string_buffer(buffer)
        result = self.libc.ptrace(PTRACE_SETREGS, self.process_id, 0, native_buffer)
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])

    def wait_for_child(self):
        """Waits for the child process to be ready for commands.

        Returns:
            bool: Whether the child process is still alive.
        """
        assert self.process_id is not None
        # TODO: check what option this is, because I can't find it anywhere
        pid, status = os.waitpid(self.process_id, 1 << 30)
        logging.debug("Child process %d reported status %d", pid, status)

        if os.WIFEXITED(status):
            logging.debug("Child process %d exited with status %d", pid, status)

        return os.WIFSTOPPED(status)

    def provide_memory_view(self) -> MemoryView:
        """Returns a memory view of the process."""
        assert self.process_id is not None

        def getter(address) -> bytes:
            return self._peek_mem(address).to_bytes(8, "little", signed=True)

        def setter(address, value):
            self._poke_mem(address, int.from_bytes(value, "little", signed=True))

        return MemoryView(getter, setter, self.maps)

    def ensure_stopped(self):
        """Ensures that the process is stopped."""
        os.kill(self.process_id, signal.SIGSTOP)

    def continue_execution(self):
        """Continues the execution of the process."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_CONT, self.process_id, 0, 0)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])
        invalidate_process_cache()

    def _set_sw_breakpoint(self, address: int):
        """Sets a software breakpoint at the specified address.

        Args:
            address (int): The address where the breakpoint should be set.
        """
        assert self.process_id is not None
        instruction = self._peek_mem(address)
        self.software_breakpoints[address] = instruction
        # TODO: this is not correct for all architectures
        self._poke_mem(address, (instruction & ((2**56 - 1) << 8)) | 0xCC)

    def _unset_sw_breakpoint(self, address: int):
        """Unsets a software breakpoint at the specified address.

        Args:
            address (int): The address where the breakpoint should be unset.
        """
        assert self.process_id is not None
        self._poke_mem(address, self.software_breakpoints[address])

    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        if breakpoint.hardware:
            self.hardware_bp_helper.install_breakpoint(breakpoint)
        else:
            self._set_sw_breakpoint(breakpoint.address)

    def restore_breakpoint(self, breakpoint: Breakpoint):
        """Restores the breakpoint at the specified address.

        Args:
            address (int): The address where the breakpoint should be restored.
        """
        if breakpoint.hardware:
            self.hardware_bp_helper.remove_breakpoint(breakpoint)
        else:
            self._unset_sw_breakpoint(breakpoint.address)

    def step_execution(self):
        """Executes a single instruction before stopping again."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_int
        result = self.libc.ptrace(PTRACE_SINGLESTEP, self.process_id, 0, 0)
        # TODO: investigate errno handling
        if result == -1:
            raise OSError(get_errno(), errno.errorcode[get_errno()])
        invalidate_process_cache()

    def _peek_mem(self, address: int) -> int:
        """Reads the memory at the specified address."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_long
        set_errno(0)

        result = self.libc.ptrace(PTRACE_PEEKDATA, self.process_id, address, 0)
        logging.debug("PEEKDATA at address %d returned with result %x", address, result)

        error = get_errno()
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_mem(self, address: int, value: int):
        """Writes the memory at the specified address."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_long
        set_errno(0)

        result = self.libc.ptrace(PTRACE_POKEDATA, self.process_id, address, value)
        logging.debug("POKEDATA at address %d returned with result %d", address, result)

        error = get_errno()
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

    def _peek_user(self, address: int) -> int:
        """Reads the memory at the specified address."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_long
        set_errno(0)

        result = self.libc.ptrace(PTRACE_PEEKUSER, self.process_id, address, 0)
        logging.debug("PEEKUSER at address %d returned with result %x", address, result)

        error = get_errno()
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_user(self, address: int, value: int):
        """Writes the memory at the specified address."""
        assert self.process_id is not None
        self.libc.ptrace.argtypes = self.args_int
        self.libc.ptrace.restype = c_long
        set_errno(0)

        result = self.libc.ptrace(PTRACE_POKEUSER, self.process_id, address, value)
        logging.debug("POKEUSER at address %d returned with result %d", address, result)

        error = get_errno()
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

    def fds(self):
        """Returns the file descriptors of the process."""
        assert self.process_id is not None
        return get_open_fds(self.process_id)

    def maps(self):
        """Returns the memory maps of the process."""
        assert self.process_id is not None
        return get_process_maps(self.process_id)

    def base_address(self):
        """Returns the base address of the process."""
        assert self.process_id is not None
        return guess_base_address(self.process_id)

    def is_pie(self):
        """Returns whether the executable is PIE or not."""
        assert self.process_id is not None
        return is_pie(self.argv[0])

    def resolve_address(self, address: int) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.

        Returns:
            int: The normalized and validated address.

        Throws:
            ValueError: If the address is not valid.
        """
        maps = self.maps()
        return normalize_and_validate_address(address, maps)
