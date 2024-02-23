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
from libdebug.data.memory_view import MemoryView
from libdebug.data.register_holder import RegisterHolder
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.state.debugging_context import debugging_context
from libdebug.state.thread_context import ThreadContext
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
            self._setup_parent()
            debugging_context.pipe_manager = self._setup_pipe()

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

        debugging_context.clear()

    def cont(self):
        """Continues the execution of the process."""
        # Set registers for all threads
        for thread in self.threads.values():
            thread._flush_registers()

        # Determine if any breakpoints need to be restored
        bps_to_restore = [
            bp for bp in debugging_context.breakpoints.values() if bp._needs_restore
        ]

        if bps_to_restore:
            # If any, allocate the cffi struct
            # and fill it with the information of the breakpoints that need to be restored
            bp_count = sum(len(bp._linked_thread_ids) for bp in bps_to_restore)
            bps = self.ffi.new("ptrace_hit_bp[]", bp_count)

            i = 0
            while i < bp_count:
                bp = bps_to_restore.pop(0)
                for thread_id in bp._linked_thread_ids:
                    liblog.debugger(
                        "Restoring breakpoint at address %x, hit by thread %d",
                        bp.address,
                        thread_id,
                    )
                    bps[i].pid = thread_id
                    bps[i].addr = bp.address
                    bps[i].prev_instruction = bp._original_instruction
                    bps[i].bp_instruction = install_software_breakpoint(
                        bp._original_instruction
                    )
                    i += 1
                bp._linked_thread_ids.clear()
                bp._needs_restore = False
        else:
            # Otherwise, pass NULL
            bp_count = 0
            bps = self.ffi.NULL

        # Construct the cffi array of pids
        pids = self.ffi.new("int[]", self.thread_ids)
        pid_count = len(self.thread_ids)

        liblog.debugger(f"Continuing threads {self.thread_ids}")

        # Call the CFFI implementation
        result = self.lib_trace.cont_all_and_set_bps(pid_count, pids, bp_count, bps)
        if result < 0:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the process."""
        # Set registers for all threads
        for thread in self.threads.values():
            thread._flush_registers()

        thread_id = thread.thread_id

        result = self.lib_trace.ptrace_singlestep(thread_id)
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

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        # TODO: this 512 is a magic number, it should be replaced with a constant
        register_file = self.ffi.new("struct user_regs_struct*")
        liblog.debugger(
            "Getting registers from process %d, thread %d", self.process_id, thread_id
        )
        result = self.lib_trace.ptrace_getregs(thread_id, register_file)
        if result == -1:
            errno_val = self.ffi.errno
            if errno_val == errno.ESRCH:
                liblog.debugger("Thread %d not found", thread_id)
                return None
            else:
                raise OSError(errno_val, errno.errorcode[errno_val])
        else:
            return register_holder_provider(
                register_file, ptrace_setter=self._set_registers
            )

    def _set_registers(self, register_file, thread_id: int):
        """Sets the value of all the available registers."""
        # TODO: this 512 is a magic number, it should be replaced with a constant
        result = self.lib_trace.ptrace_setregs(thread_id, register_file)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def wait(self):
        """Waits for the process to stop."""
        assert self.process_id is not None

        # -1 means wait for any child process
        # 1 << 30 is for __WALL, in order to wait for any child thread
        pid, status = os.waitpid(-1, 1 << 30)
        liblog.debugger("Child thread %d reported status %d", pid, status)

        # Interrupt any other running thread
        if len(self.thread_ids) > 1:
            wait_results = [(pid, status)]

            other_threads = [tid for tid in self.thread_ids if tid != pid]

            # Send a process-wide SIGSTOP signal to stop all threads
            os.kill(self.process_id, signal.SIGSTOP)

            # Wait for the threads to stop and poll their status
            for thread_id in other_threads:
                liblog.debugger(f"Waiting for thread {thread_id}")

                # 0 means "wait blocking"
                option = 0

                # threads might have more than one status change to report
                while True:
                    try:
                        npid, nstatus = os.waitpid(thread_id, option)
                        if npid != 0:
                            liblog.debugger(
                                "Child process %d reported status %d", npid, nstatus
                            )
                            wait_results.append((npid, nstatus))
                        else:
                            break
                    except ChildProcessError:
                        liblog.debugger("Could not find thread %d", thread_id)
                        break
                    # After the first iteration, we want to return immediately if no result is available
                    # This is because we are polling the status of the threads, to see if there's anything
                    # waiting in the queue, but we don't want to block if there's nothing to report
                    option = os.WNOHANG

            liblog.debugger("All threads stopped")

            for pid, status in wait_results:
                self.status_handler.handle_change(pid, status)
        else:
            self.status_handler.handle_change(pid, status)

    def register_new_thread(self, new_thread_id: int):
        """Registers a new thread."""
        thread = ThreadContext.new(new_thread_id)
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
        debugging_context.remove_thread(thread_id)

        # Remove the hardware breakpoint manager for the thread
        self.hardware_bp_helpers.pop(thread_id)

    def provide_memory_view(self) -> MemoryView:
        """Returns a memory view of the process."""
        assert self.process_id is not None

        def getter(address) -> bytes:
            return self._peek_mem(address).to_bytes(8, "little", signed=False)

        def setter(address, value):
            self._poke_mem(address, int.from_bytes(value, "little", signed=False))

        return MemoryView(getter, setter, self.maps)

    def _set_sw_breakpoint(self, breakpoint: Breakpoint):
        """Sets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        assert self.process_id is not None
        instruction = self._peek_mem(breakpoint.address)
        breakpoint._original_instruction = instruction
        self._poke_mem(breakpoint.address, install_software_breakpoint(instruction))

    def _unset_sw_breakpoint(self, breakpoint: Breakpoint):
        """Unsets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        self._poke_mem(breakpoint.address, breakpoint._original_instruction)

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
            self._unset_sw_breakpoint(breakpoint)

        debugging_context.remove_breakpoint(breakpoint)

    def unset_hit_software_breakpoint(self, breakpoint: Breakpoint):
        """Unsets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        return self._unset_sw_breakpoint(breakpoint)

    def _peek_mem(self, address: int) -> int:
        """Reads the memory at the specified address."""
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
        result = self.lib_trace.ptrace_pokedata(self.process_id, address, value)
        liblog.debugger(
            "POKEDATA at address %d returned with result %d", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

    def _peek_user(self, thread_id: int, address: int) -> int:
        """Reads the memory at the specified address."""
        result = self.lib_trace.ptrace_peekuser(thread_id, address)
        liblog.debugger(
            "PEEKUSER at address %d returned with result %x", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_user(self, thread_id: int, address: int, value: int):
        """Writes the memory at the specified address."""
        result = self.lib_trace.ptrace_pokeuser(thread_id, address, value)
        liblog.debugger(
            "POKEUSER at address %d returned with result %d", address, result
        )

        error = self.ffi.errno
        if error == errno.EIO:
            raise OSError(error, errno.errorcode[error])

    def _get_event_msg(self, thread_id: int) -> int:
        """Returns the event message."""
        return self.lib_trace.ptrace_geteventmsg(thread_id)

    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        assert self.process_id is not None

        return get_process_maps(self.process_id)
