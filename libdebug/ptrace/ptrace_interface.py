#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import errno
import os
import pty
import tty
from pathlib import Path
from typing import TYPE_CHECKING

from libdebug.architectures.ptrace_hardware_breakpoint_provider import (
    ptrace_hardware_breakpoint_manager_provider,
)
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.cffi import _ptrace_cffi
from libdebug.data.breakpoint import Breakpoint
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.state.debugging_context import (
    DebuggingContext,
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
    (Path(__file__) / ".." / ".." / "ptrace" / "jumpstart" / "jumpstart").resolve(),
)

if hasattr(os, "posix_spawn"):
    from os import POSIX_SPAWN_CLOSE, POSIX_SPAWN_DUP2, posix_spawn
else:
    from libdebug.utils.posix_spawn import (
        POSIX_SPAWN_CLOSE,
        POSIX_SPAWN_DUP2,
        posix_spawn,
    )

if TYPE_CHECKING:
    from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
        PtraceHardwareBreakpointManager,
    )
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.signal_hook import SignalHook
    from libdebug.data.syscall_hook import SyscallHook


class PtraceInterface(DebuggingInterface):
    """The interface used by `_InternalDebugger` to communicate with the `ptrace` debugging backend."""

    context: DebuggingContext
    """The debugging context."""

    hardware_bp_helpers: dict[int, PtraceHardwareBreakpointManager]
    """The hardware breakpoint managers (one for each thread)."""

    process_id: int | None
    """The process ID of the debugged process."""

    detached: bool
    """Whether the process was detached or not."""

    def __init__(self: PtraceInterface) -> None:
        super().__init__()

        self.lib_trace = _ptrace_cffi.lib
        self.ffi = _ptrace_cffi.ffi

        self.context = provide_context(self)

        if not self.context.aslr_enabled:
            disable_self_aslr()

        self._global_state = self.ffi.new("struct global_state*")

        self.process_id = 0
        self.detached = False

        self.hardware_bp_helpers = {}

        self.reset()

    def reset(self: PtraceInterface) -> None:
        """Resets the state of the interface."""
        self.hardware_bp_helpers.clear()
        self.lib_trace.free_thread_list(self._global_state)
        self.lib_trace.free_breakpoints(self._global_state)

    def _set_options(self: PtraceInterface) -> None:
        """Sets the tracer options."""
        self.lib_trace.ptrace_set_options(self.process_id)

    def run(self: PtraceInterface) -> None:
        """Runs the specified process."""
        argv = self.context.argv
        env = self.context.env

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

        # argv[1] is the length of the custom environment variables
        # argv[2:2 + env_len] is the custom environment variables
        # argv[2 + env_len] should be NULL
        # argv[2 + env_len + 1:] is the new argv
        if env is None:
            env_len = -1
            env = {}
        else:
            env_len = len(env)

        argv = [
            JUMPSTART_LOCATION,
            str(env_len),
            *[
                f"{key}={value}"
                for key, value in env.items()
            ],
            "NULL",
            *argv,
        ]

        child_pid = posix_spawn(
            JUMPSTART_LOCATION,
            argv,
            os.environ,
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

        self.process_id = child_pid
        self.detached = False
        self.context.process_id = child_pid
        self.register_new_thread(child_pid)
        continue_to_entry_point = self.context.autoreach_entrypoint
        self._setup_parent(continue_to_entry_point)
        self.context.pipe_manager = self._setup_pipe()

    def attach(self: PtraceInterface, pid: int) -> None:
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

        self.process_id = pid
        self.detached = False
        self.context.process_id = pid
        self.register_new_thread(pid)
        # If we are attaching to a process, we don't want to continue to the entry point
        # which we have probably already passed
        self._setup_parent(continue_to_entry_point=False)

    def detach(self: PtraceInterface) -> None:
        """Detaches from the process."""
        # We must disable all breakpoints before detaching
        for bp in list(self.context.breakpoints.values()):
            if bp.enabled:
                self.unset_breakpoint(bp, delete=True)

        self.lib_trace.ptrace_detach_and_cont(self._global_state, self.process_id)

        self.detached = True

    def kill(self: PtraceInterface) -> None:
        """Instantly terminates the process."""
        if not self.detached:
            self.lib_trace.ptrace_detach_for_kill(self._global_state, self.process_id)
        else:
            # If we detached from the process, there's no reason to attempt to detach again
            # We can just kill the process
            os.kill(self.process_id, 9)
            os.waitpid(self.process_id, 0)

    def cont(self: PtraceInterface) -> None:
        """Continues the execution of the process."""

        # Forward signals to the threads
        if len(self.context._resume_context.threads_with_signals_to_forward) > 0:
            self.forward_signal()

        # Enable all breakpoints if they were disabled for a single step
        changed = []

        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = False
            if bp._changed:
                changed.append(bp)
                bp._changed = False

        for bp in changed:
            if bp.enabled:
                self.set_breakpoint(bp, insert=False)
            else:
                self.unset_breakpoint(bp, delete=False)

        for hook in self.context.syscall_hooks.values():
            if hook.enabled:
                self._global_state.syscall_hooks_enabled = True
                break
        else:
            self._global_state.syscall_hooks_enabled = False

        result = self.lib_trace.cont_all_and_set_bps(
            self._global_state,
            self.process_id,
        )
        if result < 0:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

    def step(self: PtraceInterface, thread: ThreadContext) -> None:
        """Executes a single instruction of the process."""
        # Disable all breakpoints for the single step
        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = True

        result = self.lib_trace.singlestep(self._global_state, thread.thread_id)
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

        self.context._resume_context.is_a_step = True

    def step_until(self: PtraceInterface, thread: ThreadContext, address: int, max_steps: int) -> None:
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        # Disable all breakpoints for the single step
        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = True

        result = self.lib_trace.step_until(
            self._global_state,
            thread.thread_id,
            address,
            max_steps,
        )
        if result == -1:
            errno_val = self.ffi.errno
            raise OSError(errno_val, errno.errorcode[errno_val])

        # As the wait is done internally, we must invalidate the cache
        invalidate_process_cache()

    def finish(self: PtraceInterface, thread: ThreadContext, exact: bool) -> None:
        """Executes instructions of the specified thread until the current function returns.

        Args:
            thread (ThreadContext): The thread to step.
            exact (bool): If True, the command is implemented as a series of `step` commands.
        """
        if exact:
            result = self.lib_trace.exact_finish(
                self._global_state,
                thread.thread_id,
            )

            if result == -1:
                errno_val = self.ffi.errno
                raise OSError(errno_val, errno.errorcode[errno_val])

            # As the wait is done internally, we must invalidate the cache
            invalidate_process_cache()
        else:
            # Breakpoint to return address
            last_saved_instruction_pointer = thread.current_return_address()

            # If a breakpoint already exists at the return address, we don't need to set a new one
            found = False
            ip_breakpoint = None

            for bp in self.context.breakpoints.values():
                if bp.address == last_saved_instruction_pointer:
                    found = True
                    ip_breakpoint = bp
                    break

            if not found:
                # Check if we have enough hardware breakpoints available
                # Otherwise we use a software breakpoint
                install_hw_bp = self.hardware_bp_helpers[thread.thread_id].available_breakpoints() > 0

                ip_breakpoint = Breakpoint(last_saved_instruction_pointer, hardware=install_hw_bp)
                self.set_breakpoint(ip_breakpoint)
            elif not ip_breakpoint.enabled:
                self._enable_breakpoint(ip_breakpoint)

            self.cont()
            self.wait()

            # Remove the breakpoint if it was set by us
            if not found:
                self.unset_breakpoint(ip_breakpoint)

    def _setup_pipe(self: PtraceInterface) -> None:
        """Sets up the pipe manager for the child process.

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
            raise Exception("Closing fds failed: %r", e) from e
        return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

    def _setup_parent(self: PtraceInterface, continue_to_entry_point: bool) -> None:
        """Sets up the parent process after the child process has been created or attached to."""
        liblog.debugger("Polling child process status")
        self.context._resume_context.is_startup = True
        self.wait()
        self.context._resume_context.is_startup = False
        liblog.debugger("Child process ready, setting options")
        self._set_options()
        liblog.debugger("Options set")

        if continue_to_entry_point:
            # Now that the process is running, we must continue until we have reached the entry point
            entry_point = get_entry_point(self.context.argv[0])

            # For PIE binaries, the entry point is a relative address
            entry_point = normalize_and_validate_address(entry_point, self.maps())

            bp = Breakpoint(entry_point, hardware=True)
            self.set_breakpoint(bp)
            self.cont()
            self.wait()

            self.unset_breakpoint(bp)

        invalidate_process_cache()

    def wait(self: PtraceInterface) -> None:
        """Waits for the process to stop. Returns True if the wait has to be repeated."""
        result = self.lib_trace.wait_all_and_update_regs(
            self._global_state,
            self.process_id,
        )
        cursor = result

        invalidate_process_cache()

        results = []

        while cursor != self.ffi.NULL:
            results.append((cursor.tid, cursor.status))
            cursor = cursor.next

        # Check the result of the waitpid and handle the changes.
        self.status_handler.manage_change(results)

        self.lib_trace.free_thread_status_list(result)

    def forward_signal(self: PtraceInterface) -> None:
        """Set the signals to forward to the threads."""
        # change the global_state
        cursor = self._global_state.t_HEAD
        threads = self.context._resume_context.threads_with_signals_to_forward

        while cursor != self.ffi.NULL:
            if cursor.tid in threads:
                thread = self.context.get_thread_by_id(cursor.tid)
                if thread is None:
                    # The thread is dead in the meantime
                    continue
                if thread._signal_number != 0 and thread._signal_number not in self.context._signal_to_block:
                    liblog.debugger(
                        f"Forward signal {thread._signal_number} to thread {cursor.tid}",
                    )
                    # Set the signal to forward
                    cursor.signal_to_forward = thread._signal_number
                    # Reset the signal to forward
                    thread._signal_number = 0
            cursor = cursor.next

        # Clear the list of threads with signals to forward
        self.context._resume_context.threads_with_signals_to_forward.clear()

    def migrate_to_gdb(self: PtraceInterface) -> None:
        """Migrates the current process to GDB."""
        self.lib_trace.ptrace_detach_for_migration(self._global_state, self.process_id)

    def migrate_from_gdb(self: PtraceInterface) -> None:
        """Migrates the current process from GDB."""
        self.lib_trace.ptrace_reattach_from_gdb(self._global_state, self.process_id)

        invalidate_process_cache()
        self.status_handler.check_for_new_threads(self.process_id)

        # We have to reinstall any hardware breakpoint
        for bp in self.context.breakpoints.values():
            if bp.hardware and bp.enabled:
                for helper in self.hardware_bp_helpers.values():
                    helper.remove_breakpoint(bp)
                    helper.install_breakpoint(bp)

    def register_new_thread(self: PtraceInterface, new_thread_id: int) -> None:
        """Registers a new thread."""
        # The FFI implementation returns a pointer to the register file
        register_file = self.lib_trace.register_thread(
            self._global_state,
            new_thread_id,
        )

        register_holder = register_holder_provider(register_file)

        with context_extend_from(self):
            thread = ThreadContext.new(new_thread_id, register_holder)

        link_context(thread, self)

        self.context.insert_new_thread(thread)
        thread_hw_bp_helper = ptrace_hardware_breakpoint_manager_provider(
            thread,
            self._peek_user,
            self._poke_user,
        )
        self.hardware_bp_helpers[new_thread_id] = thread_hw_bp_helper

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in self.context.breakpoints.values():
            if bp.hardware:
                thread_hw_bp_helper.install_breakpoint(bp)

    def unregister_thread(self: PtraceInterface, thread_id: int) -> None:
        """Unregisters a thread."""
        self.lib_trace.unregister_thread(self._global_state, thread_id)

        self.context.set_thread_as_dead(thread_id)

        # Remove the hardware breakpoint manager for the thread
        self.hardware_bp_helpers.pop(thread_id)

    def _set_sw_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Sets a software breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to set.
        """
        self.lib_trace.register_breakpoint(
            self._global_state,
            self.process_id,
            bp.address,
        )

    def _unset_sw_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Unsets a software breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to unset.
        """
        self.lib_trace.unregister_breakpoint(self._global_state, bp.address)

    def _enable_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Enables a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to enable.
        """
        self.lib_trace.enable_breakpoint(self._global_state, bp.address)

    def _disable_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Disables a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to disable.
        """
        self.lib_trace.disable_breakpoint(self._global_state, bp.address)

    def set_breakpoint(self: PtraceInterface, bp: Breakpoint, insert: bool = True) -> None:
        """Sets a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to set.
            insert (bool): Whether the breakpoint has to be inserted or just enabled.
        """
        if bp.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.install_breakpoint(bp)
        elif insert:
            self._set_sw_breakpoint(bp)
        else:
            self._enable_breakpoint(bp)

        if insert:
            self.context.insert_new_breakpoint(bp)

    def unset_breakpoint(self: PtraceInterface, bp: Breakpoint, delete: bool = True) -> None:
        """Restores the breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to unset.
            delete (bool): Whether the breakpoint has to be deleted or just disabled.
        """
        if bp.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.remove_breakpoint(bp)
        elif delete:
            self._unset_sw_breakpoint(bp)
        else:
            self._disable_breakpoint(bp)

        if delete:
            self.context.remove_breakpoint(bp)

    def set_syscall_hook(self: PtraceInterface, hook: SyscallHook) -> None:
        """Sets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to set.
        """
        self.context.insert_new_syscall_hook(hook)

    def unset_syscall_hook(self: PtraceInterface, hook: SyscallHook) -> None:
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """
        self.context.remove_syscall_hook(hook)

    def set_signal_hook(self: PtraceInterface, hook: SignalHook) -> None:
        """Sets a signal hook.

        Args:
            hook (SignalHook): The signal hook to set.
        """
        self.context.insert_new_signal_hook(hook)

    def unset_signal_hook(self: PtraceInterface, hook: SignalHook) -> None:
        """Unsets a signal hook.

        Args:
            hook (SignalHook): The signal hook to unset.
        """
        self.context.remove_signal_hook(hook)

    def peek_memory(self: PtraceInterface, address: int) -> int:
        """Reads the memory at the specified address."""
        result = self.lib_trace.ptrace_peekdata(self.process_id, address)
        liblog.debugger(
            "PEEKDATA at address %d returned with result %x",
            address,
            result,
        )

        error = self.ffi.errno
        if error:
            raise OSError(error, errno.errorcode[error])

        return result

    def poke_memory(self: PtraceInterface, address: int, value: int) -> None:
        """Writes the memory at the specified address."""
        result = self.lib_trace.ptrace_pokedata(self.process_id, address, value)
        liblog.debugger(
            "POKEDATA at address %d returned with result %d",
            address,
            result,
        )

        if result == -1:
            error = self.ffi.errno
            raise OSError(error, errno.errorcode[error])

    def _peek_user(self: PtraceInterface, thread_id: int, address: int) -> int:
        """Reads the memory at the specified address."""
        result = self.lib_trace.ptrace_peekuser(thread_id, address)
        liblog.debugger(
            "PEEKUSER at address %d returned with result %x",
            address,
            result,
        )

        error = self.ffi.errno
        if error:
            raise OSError(error, errno.errorcode[error])

        return result

    def _poke_user(self: PtraceInterface, thread_id: int, address: int, value: int) -> None:
        """Writes the memory at the specified address."""
        result = self.lib_trace.ptrace_pokeuser(thread_id, address, value)
        liblog.debugger(
            "POKEUSER at address %d returned with result %d",
            address,
            result,
        )

        if result == -1:
            error = self.ffi.errno
            raise OSError(error, errno.errorcode[error])

    def _get_event_msg(self: PtraceInterface, thread_id: int) -> int:
        """Returns the event message."""
        return self.lib_trace.ptrace_geteventmsg(thread_id)

    def maps(self: PtraceInterface) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        return get_process_maps(self.process_id)