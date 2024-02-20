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

import errno
from libdebug.utils.pipe_manager import PipeManager
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.architectures.register_holder import RegisterHolder
from libdebug.architectures.ptrace_hardware_breakpoint_provider import (
    ptrace_hardware_breakpoint_manager_provider,
)
from libdebug.architectures.ptrace_software_breakpoint_patcher import install_software_breakpoint
from libdebug.cffi import _ptrace_cffi
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.utils.process_utils import invalidate_process_cache, disable_self_aslr
from libdebug.liblog import liblog
import os
import signal
import sys
import pty
import tty


class PtraceInterface(DebuggingInterface):
    """The interface used by `Debugger` to communicate with the `ptrace` debugging backend."""

    def __init__(self):
        self.lib_trace = _ptrace_cffi.lib
        self.ffi = _ptrace_cffi.ffi

        # The PID of the process being traced
        self.process_id = None
        self.thread_ids = []
        self.software_breakpoints = {}
        self.hardware_bp_helper = None

    def _set_options(self):
        """Sets the tracer options."""
        self.lib_trace.ptrace_set_options(self.process_id)

    def _trace_self(self):
        """Traces the current process."""
        result = self.lib_trace.ptrace_trace_me()
        # TODO: investigate errno handling
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def run(
        self, argv: str | list[str], enable_aslr: bool, env: dict[str, str] = None
    ) -> PipeManager:
        """Runs the specified process.

        Args:
            argv (str | list[str]): The command line to execute.
            enable_aslr (bool): Whether to enable ASLR or not.
            env (dict[str, str], optional): The environment variables to use. Defaults to None.

        Returns:
            int: The PID of the process.
        """

        liblog.debugger("Running %s", argv)

        # Creating pipes for stdin, stdout, stderr
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = pty.openpty()
        self.stderr_read, self.stderr_write = pty.openpty()

        child_pid = os.fork()
        if child_pid == 0:
            # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
            # output
            tty.setraw(self.stdout_write)
            tty.setraw(self.stderr_write)

            self._setup_child(argv, enable_aslr, env)
            sys.exit(-1)
        else:
            # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
            # output
            tty.setraw(self.stdout_read)
            tty.setraw(self.stderr_read)

            self.process_id = child_pid
            self.thread_ids = [child_pid]
            self._setup_parent()
            return self._setup_pipe()

    def kill(self):
        """Instantly terminates the process."""
        assert self.process_id is not None

        for thread_id in self.thread_ids:
            result = self.lib_trace.ptrace_detach(thread_id)
            if result == -1:
                liblog.debugger("Detaching from thread %d failed", thread_id)
            else:
                liblog.debugger("Detached from thread %d", thread_id)

        # send SIGKILL to the child process
        try:
            os.kill(self.process_id, signal.SIGKILL)
        except OSError as e:
            liblog.debugger("Killing process %d failed: %r", self.process_id, e)

        # wait for the child process to terminate, otherwise it will become a zombie
        os.wait()

        self.process_id = None
        self.thread_ids = []

    def cont(self):
        """Continues the execution of the process."""
        assert self.process_id is not None
        result = self.lib_trace.ptrace_cont(self.process_id)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step(self):
        """Executes a single instruction of the process."""
        assert self.process_id is not None
        result = self.lib_trace.ptrace_singlestep(self.process_id)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def _setup_child(self, argv, enable_aslr, env):
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
            raise RuntimeError("Redirecting stdin, stdout, and stderr failed: %r" % e)

        if isinstance(argv, str):
            argv = [argv]

        if not enable_aslr:
            disable_self_aslr()

        if env:
            os.execve(argv[0], argv, env)
        else:
            os.execv(argv[0], argv)

    def _setup_pipe(self):
        """
        Sets up the pipe manager for the child process.

        Close the read end for stdin and the write ends for stdout and stderr
        in the parent process since we are going to write to stdin and read from
        stdout and stderr
        """
        try:
            os.close(self.stdin_read)
            os.close(self.stdout_write)
            os.close(self.stderr_write)
        except Exception as e:
            # TODO: custom exception
            raise Exception("Closing fds failed: %r" % e)
        return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

    def _setup_parent(self):
        """
        Sets up the parent process after the child process has been created or attached to.
        """
        liblog.debugger("Polling child process status")
        self.wait()
        liblog.debugger("Child process ready, setting options")
        self._set_options()
        liblog.debugger("Options set")
        invalidate_process_cache()
        self.hardware_bp_helper = ptrace_hardware_breakpoint_manager_provider(
            self._peek_user, self._poke_user
        )

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        # TODO: this 512 is a magic number, it should be replaced with a constant
        register_file = self.ffi.new("char[512]")
        liblog.debugger(
            "Getting registers from process %d, thread %d", self.process_id, thread_id
        )
        result = self.lib_trace.ptrace_getregs(thread_id, register_file)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])
        else:
            buffer = self.ffi.unpack(register_file, 512)
            return register_holder_provider(buffer, ptrace_setter=self._set_registers)

    def _set_registers(self, buffer, thread_id: int):
        """Sets the value of all the available registers."""
        # TODO: this 512 is a magic number, it should be replaced with a constant
        register_file = self.ffi.new("char[512]", buffer)
        result = self.lib_trace.ptrace_setregs(thread_id, register_file)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def wait(self):
        """Waits for the process to stop."""

        assert self.process_id is not None
        # -1 means wait for any child process
        pid, status = os.waitpid(-1, 0)
        liblog.debugger("Child process %d reported status %d", pid, status)

        if os.WIFSTOPPED(status):
            signum = os.WSTOPSIG(status)
            signame = signal.Signals(signum).name
            liblog.debugger("Child process %d stopped with signal %s", pid, signame)

        if os.WIFEXITED(status):
            exitstatus = os.WEXITSTATUS(status)
            liblog.debugger("Child process %d exited with status %d", pid, exitstatus)

        if os.WIFSIGNALED(status):
            termsig = os.WTERMSIG(status)
            liblog.debugger("Child process %d exited with signal %d", pid, termsig)

    def provide_memory_view(self) -> MemoryView:
        """Returns a memory view of the process."""
        assert self.process_id is not None

        def getter(address) -> bytes:
            return self._peek_mem(address).to_bytes(8, "little", signed=False)

        def setter(address, value):
            self._poke_mem(address, int.from_bytes(value, "little", signed=False))

        return MemoryView(getter, setter, None)

    def continue_after_breakpoint(self, breakpoint: Breakpoint):
        """Continues the execution of the process after a breakpoint was hit."""

        if breakpoint.hardware:
            self.continue_execution()
            return

        assert self.process_id is not None
        assert breakpoint.address in self.software_breakpoints

        instruction = self.software_breakpoints[breakpoint.address]

        result = self.lib_trace.cont_after_bp(
            self.process_id,
            breakpoint.address,
            instruction,
            install_software_breakpoint(instruction),
        )

        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

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

    def _peek_mem(self, address: int) -> int:
        """Reads the memory at the specified address."""
        assert self.process_id is not None

        result = self.lib_trace.ptrace_peekdata(self.process_id, address)
        liblog.debugger(
            "PEEKDATA at address %d returned with result %x", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_mem(self, address: int, value: int):
        """Writes the memory at the specified address."""
        assert self.process_id is not None

        result = self.lib_trace.ptrace_pokedata(self.process_id, address, value)
        liblog.debugger(
            "POKEDATA at address %d returned with result %d", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

    def _peek_user(self, address: int) -> int:
        """Reads the memory at the specified address."""
        assert self.process_id is not None

        result = self.lib_trace.ptrace_peekuser(self.process_id, address)
        liblog.debugger(
            "PEEKUSER at address %d returned with result %x", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_user(self, address: int, value: int):
        """Writes the memory at the specified address."""
        assert self.process_id is not None

        result = self.lib_trace.ptrace_pokeuser(self.process_id, address, value)
        liblog.debugger(
            "POKEUSER at address %d returned with result %d", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])
