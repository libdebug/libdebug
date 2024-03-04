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
import os
import pty
import signal
import sys
import tty

from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.architectures.ptrace_hardware_breakpoint_provider import (
    ptrace_hardware_breakpoint_manager_provider,
)
from libdebug.architectures.ptrace_software_breakpoint_patcher import (
    install_software_breakpoint,
)
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.cffi import _ptrace_cffi
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.state.debugging_context import debugging_context
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.debugging_utils import normalize_and_validate_address
from libdebug.utils.elf_utils import get_entry_point
from libdebug.utils.pipe_manager import PipeManager
from libdebug.utils.process_utils import (
    disable_self_aslr,
    get_process_maps,
    invalidate_process_cache,
)


class PtraceInterface(DebuggingInterface):
    """The interface used by `Debugger` to communicate with the `ptrace` debugging backend."""

    hardware_bp_helpers: dict[int, PtraceHardwareBreakpointManager]
    """The hardware breakpoint managers (one for each thread)."""

    def __init__(self):
        super().__init__()

        self.lib_trace = _ptrace_cffi.lib
        self.ffi = _ptrace_cffi.ffi

        if not debugging_context.aslr_enabled:
            disable_self_aslr()

        setattr(
            PtraceInterface,
            "process_id",
            property(lambda _: debugging_context.process_id),
        )
        setattr(
            PtraceInterface,
            "thread_ids",
            property(lambda _: list(debugging_context.threads.keys())),
        )

        self.hardware_bp_helpers = {}

        self.reset()

    def reset(self):
        """Resets the state of the interface."""
        self.hardware_bp_helpers.clear()
        self.lib_trace.free_thread_list()
        self.lib_trace.free_breakpoints()

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

    def run(self):
        """Runs the specified process."""

        argv = debugging_context.argv
        env = debugging_context.env

        liblog.debugger("Running %s", argv)

        # Setup ptrace wait status handler after debugging_context has been properly initialized
        self.status_handler = PtraceStatusHandler()

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

            self._setup_child(argv, env)
            sys.exit(-1)
        else:
            # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
            # output
            tty.setraw(self.stdout_read)
            tty.setraw(self.stderr_read)

            debugging_context.process_id = child_pid
            self.register_new_thread(child_pid)
            continue_to_entry_point = debugging_context.autoreach_entrypoint
            self._setup_parent(continue_to_entry_point)
            debugging_context.pipe_manager = self._setup_pipe()

    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        # Setup ptrace wait status handler after debugging_context has been properly initialized
        self.status_handler = PtraceStatusHandler()

        res = self.lib_trace.ptrace_attach(pid)
        if res == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

        debugging_context.process_id = pid
        self.register_new_thread(pid)
        # If we are attaching to a process, we don't want to continue to the entry point
        # which we have probably already passed
        self._setup_parent(continue_to_entry_point=False)

    def kill(self):
        """Instantly terminates the process."""
        assert self.process_id is not None

        if not self.thread_ids:
            liblog.debugger("No threads to detach from")
            debugging_context.clear()
            return

        for thread_id in self.thread_ids:
            result = self.lib_trace.ptrace_detach(thread_id)
            if result == -1:
                liblog.debugger("Detaching from thread %d failed", thread_id)
            else:
                liblog.debugger("Detached from thread %d", thread_id)

        # send SIGKILL to the child process
        try:
            liblog.debugger("Killing process %d" % self.process_id)
            res = os.kill(self.process_id, signal.SIGKILL)
            if res == -1:
                liblog.debugger("Killing process %d failed", self.process_id)
        except OSError as e:
            liblog.debugger("Killing process %d failed: %r", self.process_id, e)

        liblog.debugger("Killed process %d" % self.process_id)

        # wait for the child process to terminate, otherwise it will become a zombie
        os.wait()

    def cont(self):
        """Continues the execution of the process."""
        # tids = set()

        # for bp in debugging_context.breakpoints.values():
        #     # Enable all breakpoints that were disabled for a single step
        #     bp._disabled_for_step = False

        #     # Determine if any software breakpoints were hit and need stepping
        #     tids.update(bp._linked_thread_ids)
        #     bp._linked_thread_ids.clear()

        # bp_count = len(tids)
        # bps = self.ffi.new("int[]", list(tids))

        # Call the CFFI implementation
        # result = self.lib_trace.cont_all_and_set_bps(self.process_id, bp_count, bps)
        result = self.lib_trace.cont_all_and_set_bps(self.process_id)
        if result < 0:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the process."""
        # Disable all breakpoints for the single step
        for bp in debugging_context.breakpoints.values():
            bp._disabled_for_step = True

        result = self.lib_trace.singlestep(thread.thread_id)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def _setup_child(self, argv, env):
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

    def _setup_parent(self, continue_to_entry_point: bool):
        """
        Sets up the parent process after the child process has been created or attached to.
        """
        liblog.debugger("Polling child process status")
        self.wait()
        liblog.debugger("Child process ready, setting options")
        self._set_options()
        liblog.debugger("Options set")

        if continue_to_entry_point:
            # Now that the process is running, we must continue until we have reached the entry point
            entry_point = get_entry_point(debugging_context.argv[0])

            # For PIE binaries, the entry point is a relative address
            entry_point = normalize_and_validate_address(entry_point, self.maps())

            bp = Breakpoint(entry_point, hardware=True)
            self.set_breakpoint(bp)

            self.cont()
            self.wait()

            self.unset_breakpoint(bp)

        invalidate_process_cache()

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        raise RuntimeError("This method should never be called.")

    def wait(self) -> bool:
        """Waits for the process to stop. Returns True if the wait has to be repeated."""
        result = self.lib_trace.wait_all_and_update_regs(self.process_id)

        repeat = False

        while result != self.ffi.NULL:
            repeat |= self.status_handler.handle_change(result.tid, result.status)
            result = result.next

        self.lib_trace.free_thread_status_list(result)

        return repeat

    def register_new_thread(self, new_thread_id: int):
        """Registers a new thread."""
        # The FFI implementation returns a pointer to the register file
        register_file = self.lib_trace.register_thread(new_thread_id)

        register_holder = register_holder_provider(register_file)

        thread = ThreadContext.new(new_thread_id, register_holder)

        debugging_context.insert_new_thread(thread)
        thread_hw_bp_helper = ptrace_hardware_breakpoint_manager_provider(
            thread, self._peek_user, self._poke_user
        )
        self.hardware_bp_helpers[new_thread_id] = thread_hw_bp_helper

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in debugging_context.breakpoints.values():
            if bp.hardware:
                thread_hw_bp_helper.install_breakpoint(bp)

    def unregister_thread(self, thread_id: int):
        """Unregisters a thread."""
        self.lib_trace.unregister_thread(thread_id)

        debugging_context.remove_thread(thread_id)

        # Remove the hardware breakpoint manager for the thread
        self.hardware_bp_helpers.pop(thread_id)

    def _set_sw_breakpoint(self, breakpoint: Breakpoint):
        """Sets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        assert self.process_id is not None
        instruction = self.peek_memory(breakpoint.address)
        breakpoint._original_instruction = instruction

        self.lib_trace.register_breakpoint(
            self.process_id, breakpoint.address, instruction, install_software_breakpoint(instruction)
        )

    def unset_hit_software_breakpoint(self, breakpoint: Breakpoint):
        """Unsets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        self.poke_memory(breakpoint.address, breakpoint._original_instruction)

    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        if breakpoint.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.install_breakpoint(breakpoint)
        else:
            self._set_sw_breakpoint(breakpoint)

        debugging_context.insert_new_breakpoint(breakpoint)

    def unset_breakpoint(self, breakpoint: Breakpoint):
        """Restores the breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        if breakpoint.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.remove_breakpoint(breakpoint)
        else:
            self.unset_hit_software_breakpoint(breakpoint)

        debugging_context.remove_breakpoint(breakpoint)

    def peek_memory(self, address: int) -> int:
        """Reads the memory at the specified address."""        
        result = self.lib_trace.ptrace_peekdata(self.process_id, address)
        liblog.debugger(
            "PEEKDATA at address %d returned with result %x", address, result
        )

        error = self.ffi.errno
        if error:
            raise OSError(error, errno.errorcode[error])

        return result

    def poke_memory(self, address: int, value: int):
        """Writes the memory at the specified address."""
        result = self.lib_trace.ptrace_pokedata(self.process_id, address, value)
        liblog.debugger(
            "POKEDATA at address %d returned with result %d", address, result
        )

        if result == -1:
            error = self.ffi.errno
            raise OSError(error, errno.errorcode[error])

    def _peek_user(self, thread_id: int, address: int) -> int:
        """Reads the memory at the specified address."""
        result = self.lib_trace.ptrace_peekuser(thread_id, address)
        liblog.debugger(
            "PEEKUSER at address %d returned with result %x", address, result
        )

        error = self.ffi.errno
        if error:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_user(self, thread_id: int, address: int, value: int):
        """Writes the memory at the specified address."""
        result = self.lib_trace.ptrace_pokeuser(thread_id, address, value)
        liblog.debugger(
            "POKEUSER at address %d returned with result %d", address, result
        )

        if result == -1:
            error = self.ffi.errno
            raise OSError(error, errno.errorcode[error])

    def _get_event_msg(self, thread_id: int) -> int:
        """Returns the event message."""
        return self.lib_trace.ptrace_geteventmsg(thread_id)

    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        assert self.process_id is not None

        return get_process_maps(self.process_id)
