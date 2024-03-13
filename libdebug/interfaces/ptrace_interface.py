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
import tty
from pathlib import Path

from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.architectures.ptrace_hardware_breakpoint_provider import (
    ptrace_hardware_breakpoint_manager_provider,
)
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.cffi import _ptrace_cffi
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.state.debugging_context import (
    context_extend_from,
    link_context,
    provide_context,
)
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.debugging_utils import normalize_and_validate_address
from libdebug.utils.elf_utils import get_entry_point
from libdebug.utils.pipe_manager import PipeManager
from libdebug.utils.process_utils import (
    disable_self_aslr,
    get_process_maps,
    invalidate_process_cache,
)


JUMPSTART_LOCATION = str(
    (Path(__file__) / ".." / ".." / "ptrace" / "jumpstart" / "jumpstart").resolve()
)

if hasattr(os, "posix_spawn"):
    POSIX_SPAWN_CLOSE = os.POSIX_SPAWN_CLOSE
    POSIX_SPAWN_DUP2 = os.POSIX_SPAWN_DUP2
    POSIX_SPAWN = os.posix_spawn
else:
    # Fallback to fork+exec if posix_spawn is not available
    # PyPy3 apparently does not have posix_spawn even if it should
    def simplified_posix_spawn(file, argv, env, file_actions, setpgroup):
        child_pid = os.fork()
        if child_pid == 0:
            for element in file_actions:
                if element[0] == POSIX_SPAWN_CLOSE:
                    os.close(element[1])
                elif element[0] == POSIX_SPAWN_DUP2:
                    os.dup2(element[1], element[2])
            if setpgroup == 0:
                os.setpgid(0, 0)
            os.execve(file, argv, env)

        return child_pid

    POSIX_SPAWN_CLOSE = 0
    POSIX_SPAWN_DUP2 = 1
    POSIX_SPAWN = simplified_posix_spawn


class PtraceInterface(DebuggingInterface):
    """The interface used by `Debugger` to communicate with the `ptrace` debugging backend."""

    hardware_bp_helpers: dict[int, PtraceHardwareBreakpointManager]
    """The hardware breakpoint managers (one for each thread)."""

    process_id: int | None
    """The process ID of the debugged process."""

    thread_ids: list[int]
    """The IDs of the threads of the debugged process."""

    def __init__(self):
        super().__init__()

        self.lib_trace = _ptrace_cffi.lib
        self.ffi = _ptrace_cffi.ffi

        if not provide_context(self).aslr_enabled:
            disable_self_aslr()

        self._global_state = self.ffi.new("struct global_state*")

        setattr(
            PtraceInterface,
            "process_id",
            property(lambda self: provide_context(self).process_id),
        )
        setattr(
            PtraceInterface,
            "thread_ids",
            property(lambda self: list(provide_context(self).threads.keys())),
        )

        self.hardware_bp_helpers = {}

        self.reset()

    def reset(self):
        """Resets the state of the interface."""
        self.hardware_bp_helpers.clear()
        self.lib_trace.free_thread_list(self._global_state)
        self.lib_trace.free_breakpoints(self._global_state)

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
        argv = provide_context(self).argv
        env = provide_context(self).env

        liblog.debugger("Running %s", argv)

        # Setup ptrace wait status handler after debugging_context has been properly initialized
        with context_extend_from(self):
            self.status_handler = PtraceStatusHandler()

        # Creating pipes for stdin, stdout, stderr
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = pty.openpty()
        self.stderr_read, self.stderr_write = pty.openpty()

        # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
        # output
        tty.setraw(self.stdout_read)
        tty.setraw(self.stderr_read)

        child_pid = POSIX_SPAWN(
            JUMPSTART_LOCATION,
            [JUMPSTART_LOCATION] + argv,
            env,
            file_actions=[
                (POSIX_SPAWN_CLOSE, self.stdin_write),
                (POSIX_SPAWN_CLOSE, self.stdout_read),
                (POSIX_SPAWN_CLOSE, self.stderr_read),
                (POSIX_SPAWN_DUP2, self.stdin_read, 0),
                (POSIX_SPAWN_DUP2, self.stdout_write, 1),
                (POSIX_SPAWN_DUP2, self.stderr_write, 2),
                (POSIX_SPAWN_CLOSE, self.stdin_read),
                (POSIX_SPAWN_CLOSE, self.stdout_write),
                (POSIX_SPAWN_CLOSE, self.stderr_write),
            ],
            setpgroup=0,
        )

        provide_context(self).process_id = child_pid
        self.register_new_thread(child_pid)
        continue_to_entry_point = provide_context(self).autoreach_entrypoint
        self._setup_parent(continue_to_entry_point)
        provide_context(self).pipe_manager = self._setup_pipe()

    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        # Setup ptrace wait status handler after debugging_context has been properly initialized
        with context_extend_from(self):
            self.status_handler = PtraceStatusHandler()

        res = self.lib_trace.ptrace_attach(pid)
        if res == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

        provide_context(self).process_id = pid
        self.register_new_thread(pid)
        # If we are attaching to a process, we don't want to continue to the entry point
        # which we have probably already passed
        self._setup_parent(continue_to_entry_point=False)

    def kill(self):
        """Instantly terminates the process."""
        assert self.process_id is not None

        self.lib_trace.ptrace_detach_all(self._global_state, self.process_id)

    def cont(self):
        """Continues the execution of the process."""
        # Enable all breakpoints if they were disabled for a single step
        for bp in provide_context(self).breakpoints.values():
            bp._disabled_for_step = False

        result = self.lib_trace.cont_all_and_set_bps(
            self._global_state, self.process_id
        )
        if result < 0:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the process."""
        # Disable all breakpoints for the single step
        for bp in provide_context(self).breakpoints.values():
            bp._disabled_for_step = True

        result = self.lib_trace.singlestep(self._global_state, thread.thread_id)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        # Disable all breakpoints for the single step
        for bp in provide_context(self).breakpoints.values():
            bp._disabled_for_step = True

        result = self.lib_trace.step_until(
            self._global_state, thread.thread_id, address, max_steps
        )
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

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
            entry_point = get_entry_point(provide_context(self).argv[0])

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
        result = self.lib_trace.wait_all_and_update_regs(
            self._global_state, self.process_id
        )
        cursor = result

        results = []

        while cursor != self.ffi.NULL:
            results.append((cursor.tid, cursor.status))
            cursor = cursor.next

        repeat = self.status_handler.check_result(results)

        self.lib_trace.free_thread_status_list(result)

        return repeat

    def register_new_thread(self, new_thread_id: int):
        """Registers a new thread."""
        # The FFI implementation returns a pointer to the register file
        register_file = self.lib_trace.register_thread(
            self._global_state, new_thread_id
        )

        register_holder = register_holder_provider(register_file)

        with context_extend_from(self):
            thread = ThreadContext.new(new_thread_id, register_holder)

        link_context(thread, self)

        provide_context(self).insert_new_thread(thread)
        thread_hw_bp_helper = ptrace_hardware_breakpoint_manager_provider(
            thread, self._peek_user, self._poke_user
        )
        self.hardware_bp_helpers[new_thread_id] = thread_hw_bp_helper

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in provide_context(self).breakpoints.values():
            if bp.hardware:
                thread_hw_bp_helper.install_breakpoint(bp)

    def unregister_thread(self, thread_id: int):
        """Unregisters a thread."""
        self.lib_trace.unregister_thread(self._global_state, thread_id)

        provide_context(self).remove_thread(thread_id)

        # Remove the hardware breakpoint manager for the thread
        self.hardware_bp_helpers.pop(thread_id)

    def _set_sw_breakpoint(self, breakpoint: Breakpoint):
        """Sets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        self.lib_trace.register_breakpoint(
            self._global_state, self.process_id, breakpoint.address
        )

    def _unset_hit_software_breakpoint(self, breakpoint: Breakpoint):
        """Unsets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        self.lib_trace.disable_breakpoint(
            self._global_state, self.process_id, breakpoint.address
        )

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

        provide_context(self).insert_new_breakpoint(breakpoint)

    def unset_breakpoint(self, breakpoint: Breakpoint):
        """Restores the breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        if breakpoint.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.remove_breakpoint(breakpoint)
        else:
            self._unset_hit_software_breakpoint(breakpoint)

        provide_context(self).remove_breakpoint(breakpoint)

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
