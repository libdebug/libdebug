#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import errno
import os
import pty
import sys
import tty
from fcntl import F_GETFL, F_SETFL, fcntl
from pathlib import Path
from typing import TYPE_CHECKING

from libdebug.architectures.call_utilities_provider import call_utilities_provider
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.commlink.pipe_manager import PipeManager
from libdebug.data.breakpoint import Breakpoint
from libdebug.debugger.internal_debugger_instance_manager import (
    extend_internal_debugger,
    provide_internal_debugger,
)
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.ptrace.native import libdebug_ptrace_binding
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.debugging_utils import normalize_and_validate_address
from libdebug.utils.elf_utils import get_entry_point
from libdebug.utils.process_utils import (
    disable_self_aslr,
    get_process_maps,
    get_process_tasks,
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
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.data.registers import Registers
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.debugger.internal_debugger import InternalDebugger


class PtraceInterface(DebuggingInterface):
    """The interface used by `_InternalDebugger` to communicate with the `ptrace` debugging backend."""

    process_id: int | None
    """The process ID of the debugged process."""

    detached: bool
    """Whether the process was detached or not."""

    _internal_debugger: InternalDebugger
    """The internal debugger instance."""

    def __init__(self: PtraceInterface) -> None:
        """Initializes the PtraceInterface."""
        self.lib_trace = libdebug_ptrace_binding.LibdebugPtraceInterface()

        self._internal_debugger = provide_internal_debugger(self)
        self.process_id = 0
        self.detached = False
        self._disabled_aslr = False

    def reset(self: PtraceInterface) -> None:
        """Resets the state of the interface."""
        self.lib_trace.cleanup()

    def _set_options(self: PtraceInterface) -> None:
        """Sets the tracer options."""
        self.lib_trace.set_ptrace_options()

    def run(self: PtraceInterface, redirect_pipes: bool) -> None:
        """Runs the specified process."""
        if not self._disabled_aslr and not self._internal_debugger.aslr_enabled:
            disable_self_aslr()
            self._disabled_aslr = True

        argv = self._internal_debugger.argv
        env = self._internal_debugger.env

        liblog.debugger("Running %s", argv)

        # Setup ptrace wait status handler after debugging_context has been properly initialized
        with extend_internal_debugger(self):
            self.status_handler = PtraceStatusHandler()

        file_actions = []

        if redirect_pipes:
            # Creating pipes for stdin, stdout, stderr
            self.stdin_read, self.stdin_write = os.pipe()
            self.stdout_read, self.stdout_write = pty.openpty()
            self.stderr_read, self.stderr_write = pty.openpty()

            # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
            # output
            tty.setraw(self.stdout_read)
            tty.setraw(self.stderr_read)

            flags = fcntl(self.stdout_read, F_GETFL)
            fcntl(self.stdout_read, F_SETFL, flags | os.O_NONBLOCK)

            flags = fcntl(self.stderr_read, F_GETFL)
            fcntl(self.stderr_read, F_SETFL, flags | os.O_NONBLOCK)

            file_actions.extend(
                [
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
            )

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
            *[f"{key}={value}" for key, value in env.items()],
            "NULL",
            *argv,
        ]

        child_pid = posix_spawn(
            JUMPSTART_LOCATION,
            argv,
            os.environ,
            file_actions=file_actions,
            setpgroup=0,
        )

        self.process_id = child_pid
        self.detached = False
        self._internal_debugger.process_id = child_pid
        self.register_new_thread(child_pid)
        continue_to_entry_point = self._internal_debugger.autoreach_entrypoint
        self._setup_parent(continue_to_entry_point)

        if redirect_pipes:
            self._internal_debugger.pipe_manager = self._setup_pipe()
        else:
            self._internal_debugger.pipe_manager = None

            # https://stackoverflow.com/questions/58918188/why-is-stdin-not-propagated-to-child-process-of-different-process-group
            # We need to set the foreground process group to the child process group, otherwise the child process
            # will not receive the input from the terminal
            try:
                os.tcsetpgrp(0, child_pid)
            except OSError as e:
                liblog.debugger("Failed to set the foreground process group: %r", e)

    def attach(self: PtraceInterface, pid: int) -> None:
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        # Setup ptrace wait status handler after debugging_context has been properly initialized
        with extend_internal_debugger(self):
            self.status_handler = PtraceStatusHandler()

        # Attach to all the tasks of the process
        self._attach_to_all_tasks(pid)

        self.process_id = pid
        self.detached = False
        self._internal_debugger.process_id = pid
        # If we are attaching to a process, we don't want to continue to the entry point
        # which we have probably already passed
        self._setup_parent(False)

    def _attach_to_all_tasks(self: PtraceInterface, pid: int) -> None:
        """Attach to all the tasks of the process."""
        tids = get_process_tasks(pid)
        for tid in tids:
            errno_val = self.lib_trace.attach(tid)
            if errno_val == errno.EPERM:
                raise PermissionError(
                    errno_val,
                    errno.errorcode[errno_val],
                    "You don't have permission to attach to the process. Did you check the ptrace_scope?",
                )
            if errno_val:
                raise OSError(errno_val, errno.errorcode[errno_val])
            self.register_new_thread(tid)

    def detach(self: PtraceInterface) -> None:
        """Detaches from the process."""
        # We must disable all breakpoints before detaching
        for bp in list(self._internal_debugger.breakpoints.values()):
            if bp.enabled:
                try:
                    self.unset_breakpoint(bp, delete=True)
                except RuntimeError as e:
                    liblog.debugger("Error unsetting breakpoint %r", e)

        self.lib_trace.detach_and_cont()

        self.detached = True

        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

    def kill(self: PtraceInterface) -> None:
        """Instantly terminates the process."""
        if not self.detached:
            self.lib_trace.detach_for_kill()
        else:
            # If we detached from the process, there's no reason to attempt to detach again
            # We can just kill the process
            os.kill(self.process_id, 9)
            os.waitpid(self.process_id, 0)

    def cont(self: PtraceInterface) -> None:
        """Continues the execution of the process."""
        # Forward signals to the threads
        if self._internal_debugger.resume_context.threads_with_signals_to_forward:
            self.forward_signal()

        # Enable all breakpoints if they were disabled for a single step
        changed = []

        for bp in self._internal_debugger.breakpoints.values():
            bp._disabled_for_step = False
            if bp._changed:
                changed.append(bp)
                bp._changed = False

        for bp in changed:
            if bp.enabled:
                self.set_breakpoint(bp, insert=False)
            else:
                self.unset_breakpoint(bp, delete=False)

        handle_syscalls = any(
            handler.enabled or handler.on_enter_pprint or handler.on_exit_pprint
            for handler in self._internal_debugger.handled_syscalls.values()
        )

        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

        self.lib_trace.cont_all_and_set_bps(handle_syscalls)

    def step(self: PtraceInterface, thread: ThreadContext) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext): The thread to step.
        """
        # Disable all breakpoints for the single step
        for bp in self._internal_debugger.breakpoints.values():
            bp._disabled_for_step = True

        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

        self.lib_trace.step(thread.thread_id)

        self._internal_debugger.resume_context.is_a_step = True

    def step_until(self: PtraceInterface, thread: ThreadContext, address: int, max_steps: int) -> None:
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        # Disable all breakpoints for the single step
        for bp in self._internal_debugger.breakpoints.values():
            bp._disabled_for_step = True

        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

        self.lib_trace.step_until(thread.thread_id, address, max_steps)

        # As the wait is done internally, we must invalidate the cache
        invalidate_process_cache()

    def finish(self: PtraceInterface, thread: ThreadContext, heuristic: str) -> None:
        """Continues execution until the current function returns.

        Args:
            thread (ThreadContext): The thread to step.
            heuristic (str): The heuristic to use.
        """
        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

        if heuristic == "step-mode":
            self.lib_trace.stepping_finish(thread.thread_id, self._internal_debugger.arch == "i386")
            # As the wait is done internally, we must invalidate the cache
            invalidate_process_cache()
        elif heuristic == "backtrace":
            # Breakpoint to return address
            last_saved_instruction_pointer = thread.saved_ip

            # If a breakpoint already exists at the return address, we don't need to set a new one
            found = False
            ip_breakpoint = None

            for bp in self._internal_debugger.breakpoints.values():
                if bp.address == last_saved_instruction_pointer:
                    found = True
                    ip_breakpoint = bp
                    break

            # If we find an existing breakpoint that is disabled, we enable it
            # but we need to disable it back after the command
            should_disable = False

            if not found:
                # Check if we have enough hardware breakpoints available
                # Otherwise we use a software breakpoint
                install_hw_bp = self.lib_trace.get_remaining_hw_breakpoint_count(thread.thread_id) > 0

                ip_breakpoint = Breakpoint(last_saved_instruction_pointer, hardware=install_hw_bp)
                self.set_breakpoint(ip_breakpoint)
            elif not ip_breakpoint.enabled:
                self._enable_breakpoint(ip_breakpoint)
                should_disable = True

            self.cont()
            self.wait()

            # Remove the breakpoint if it was set by us
            if not found:
                self.unset_breakpoint(ip_breakpoint)
            # Disable the breakpoint if it was just enabled by us
            elif should_disable:
                self._disable_breakpoint(ip_breakpoint)
        else:
            raise ValueError(f"Unimplemented heuristic {heuristic}")

    def next(self: PtraceInterface, thread: ThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        # Reset the event type
        self._internal_debugger.resume_context.event_type.clear()

        # Reset the breakpoint hit
        self._internal_debugger.resume_context.event_hit_ref.clear()

        opcode_window = thread.memory.read(thread.instruction_pointer, 8)

        # Check if the current instruction is a call and its skip amount
        is_call, skip = call_utilities_provider(self._internal_debugger.arch).get_call_and_skip_amount(opcode_window)

        if is_call:
            skip_address = thread.instruction_pointer + skip

            # If a breakpoint already exists at the return address, we don't need to set a new one
            found = False
            ip_breakpoint = self._internal_debugger.breakpoints.get(skip_address)

            if ip_breakpoint is not None:
                found = True

            # If we find an existing breakpoint that is disabled, we enable it
            # but we need to disable it back after the command
            should_disable = False

            if not found:
                # Check if we have enough hardware breakpoints available
                # Otherwise we use a software breakpoint
                install_hw_bp = self.lib_trace.get_remaining_hw_breakpoint_count(thread.thread_id) > 0
                ip_breakpoint = Breakpoint(skip_address, hardware=install_hw_bp)
                self.set_breakpoint(ip_breakpoint)
            elif not ip_breakpoint.enabled:
                self._enable_breakpoint(ip_breakpoint)
                should_disable = True

            self.cont()
            self.wait()

            # Remove the breakpoint if it was set by us
            if not found:
                self.unset_breakpoint(ip_breakpoint)
            # Disable the breakpoint if it was just enabled by us
            elif should_disable:
                self._disable_breakpoint(ip_breakpoint)
        else:
            # Step forward
            self.step(thread)
            self.wait()

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
            raise Exception("Closing fds failed: %r", e) from e
        with extend_internal_debugger(self):
            return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

    def _setup_parent(self: PtraceInterface, continue_to_entry_point: bool) -> None:
        """Sets up the parent process after the child process has been created or attached to."""
        liblog.debugger("Polling child process status")
        self._internal_debugger.resume_context.is_startup = True
        self.wait()
        self._internal_debugger.resume_context.is_startup = False
        liblog.debugger("Child process ready, setting options")
        self._set_options()
        liblog.debugger("Options set")

        if continue_to_entry_point:
            # Now that the process is running, we must continue until we have reached the entry point
            entry_point = get_entry_point(self._internal_debugger.argv[0])

            # For PIE binaries, the entry point is a relative address
            entry_point = normalize_and_validate_address(entry_point, self.get_maps())

            bp = Breakpoint(entry_point, hardware=True)
            self.set_breakpoint(bp)
            self.cont()
            self.wait()

            self.unset_breakpoint(bp)

        invalidate_process_cache()

    def wait(self: PtraceInterface) -> None:
        """Waits for the process to stop. Returns True if the wait has to be repeated."""
        statuses = self.lib_trace.wait_all_and_update_regs()

        invalidate_process_cache()

        # Check the result of the waitpid and handle the changes.
        self.status_handler.manage_change(statuses)

    def forward_signal(self: PtraceInterface) -> None:
        """Set the signals to forward to the threads."""
        # change the global_state
        threads_with_signals_to_forward = self._internal_debugger.resume_context.threads_with_signals_to_forward

        signals_to_forward = []

        for thread in self._internal_debugger.threads:
            if (
                thread.thread_id in threads_with_signals_to_forward
                and thread._signal_number != 0
                and thread._signal_number not in self._internal_debugger.signals_to_block
            ):
                liblog.debugger(
                    f"Forwarding signal {thread.signal_number} to thread {thread.thread_id}",
                )
                # Add the signal to the list of signals to forward
                signals_to_forward.append((thread.thread_id, thread.signal_number))
                # Reset the signal number
                thread._signal_number = 0

        self.lib_trace.forward_signals(signals_to_forward)

        # Clear the list of threads with signals to forward
        self._internal_debugger.resume_context.threads_with_signals_to_forward.clear()

    def migrate_to_gdb(self: PtraceInterface) -> None:
        """Migrates the current process to GDB."""
        # Delete any hardware breakpoint
        for bp in self._internal_debugger.breakpoints.values():
            if bp.hardware:
                for thread in self._internal_debugger.threads:
                    self.lib_trace.unregister_hw_breakpoint(
                        self._global_state,
                        thread.thread_id,
                        bp.address,
                    )

        self.lib_trace.detach_for_migration()

    def migrate_from_gdb(self: PtraceInterface) -> None:
        """Migrates the current process from GDB."""
        invalidate_process_cache()
        self.status_handler.check_for_changes_in_threads(self.process_id)

        self.lib_trace.reattach_from_migration()

        # We have to reinstall any hardware breakpoint
        for bp in self._internal_debugger.breakpoints.values():
            if bp.hardware:
                for thread in self._internal_debugger.threads:
                    self.lib_trace.register_hw_breakpoint(
                        thread.thread_id,
                        bp.address,
                        int.from_bytes(bp.condition.encode(), sys.byteorder),
                        bp.length,
                    )

    def register_new_thread(self: PtraceInterface, new_thread_id: int) -> None:
        """Registers a new thread.

        Args:
            new_thread_id (int): The new thread ID.
        """
        # The FFI implementation returns a pointer to the register file
        register_file, fp_register_file = self.lib_trace.register_thread(new_thread_id)

        register_holder = register_holder_provider(self._internal_debugger.arch, register_file, fp_register_file)

        with extend_internal_debugger(self._internal_debugger):
            thread = ThreadContext(new_thread_id, register_holder)

        self._internal_debugger.insert_new_thread(thread)

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in self._internal_debugger.breakpoints.values():
            if bp.hardware:
                self.lib_trace.register_hw_breakpoint(
                    thread.thread_id,
                    bp.address,
                    int.from_bytes(bp.condition.encode(), sys.byteorder),
                    bp.length,
                )

    def unregister_thread(
        self: PtraceInterface,
        thread_id: int,
        exit_code: int | None,
        exit_signal: int | None,
    ) -> None:
        """Unregisters a thread.

        Args:
            thread_id (int): The thread ID.
            exit_code (int): The exit code of the thread.
            exit_signal (int): The exit signal of the thread.
        """
        self.lib_trace.unregister_thread(thread_id)

        self._internal_debugger.set_thread_as_dead(thread_id, exit_code=exit_code, exit_signal=exit_signal)

    def _set_sw_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Sets a software breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to set.
        """
        self.lib_trace.register_breakpoint(bp.address)

    def _unset_sw_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Unsets a software breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to unset.
        """
        self.lib_trace.unregister_breakpoint(bp.address)

    def _enable_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Enables a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to enable.
        """
        self.lib_trace.enable_breakpoint(bp.address)

    def _disable_breakpoint(self: PtraceInterface, bp: Breakpoint) -> None:
        """Disables a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to disable.
        """
        self.lib_trace.disable_breakpoint(bp.address)

    def set_breakpoint(self: PtraceInterface, bp: Breakpoint, insert: bool = True) -> None:
        """Sets a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to set.
            insert (bool): Whether the breakpoint has to be inserted or just enabled.
        """
        if bp.hardware:
            for thread in self._internal_debugger.threads:
                if bp.condition == "x":
                    remaining = self.lib_trace.get_remaining_hw_breakpoint_count(thread.thread_id)
                else:
                    remaining = self.lib_trace.get_remaining_hw_watchpoint_count(thread.thread_id)

                if not remaining:
                    raise ValueError("No more hardware breakpoints of this type available")

                self.lib_trace.register_hw_breakpoint(
                    thread.thread_id,
                    bp.address,
                    int.from_bytes(bp.condition.encode(), sys.byteorder),
                    bp.length,
                )
        elif insert:
            self._set_sw_breakpoint(bp)
        else:
            self._enable_breakpoint(bp)

        if insert:
            self._internal_debugger.breakpoints[bp.address] = bp

    def unset_breakpoint(self: PtraceInterface, bp: Breakpoint, delete: bool = True) -> None:
        """Restores the breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to unset.
            delete (bool): Whether the breakpoint has to be deleted or just disabled.
        """
        if bp.hardware:
            for thread in self._internal_debugger.threads:
                self.lib_trace.unregister_hw_breakpoint(thread.thread_id, bp.address)
        elif delete:
            self._unset_sw_breakpoint(bp)
        else:
            self._disable_breakpoint(bp)

        if delete:
            del self._internal_debugger.breakpoints[bp.address]

    def set_syscall_handler(self: PtraceInterface, handler: SyscallHandler) -> None:
        """Sets a handler for a syscall.

        Args:
            handler (HandledSyscall): The syscall to set.
        """
        self._internal_debugger.handled_syscalls[handler.syscall_number] = handler

    def unset_syscall_handler(self: PtraceInterface, handler: SyscallHandler) -> None:
        """Unsets a handler for a syscall.

        Args:
            handler (HandledSyscall): The syscall to unset.
        """
        del self._internal_debugger.handled_syscalls[handler.syscall_number]

    def set_signal_catcher(self: PtraceInterface, catcher: SignalCatcher) -> None:
        """Sets a catcher for a signal.

        Args:
            catcher (CaughtSignal): The signal to set.
        """
        self._internal_debugger.caught_signals[catcher.signal_number] = catcher

    def unset_signal_catcher(self: PtraceInterface, catcher: SignalCatcher) -> None:
        """Unset a catcher for a signal.

        Args:
            catcher (CaughtSignal): The signal to unset.
        """
        del self._internal_debugger.caught_signals[catcher.signal_number]

    def peek_memory(self: PtraceInterface, address: int) -> int:
        """Reads the memory at the specified address."""
        try:
            result = self.lib_trace.peek_data(address)
        except RuntimeError as e:
            raise OSError("Invalid memory location") from e

        liblog.debugger(
            "PEEKDATA at address %d returned with result %x",
            address,
            result,
        )
        return result

    def poke_memory(self: PtraceInterface, address: int, value: int) -> None:
        """Writes the memory at the specified address."""
        result = self.lib_trace.poke_data(address, value)
        liblog.debugger(
            "POKEDATA at address %d returned with result %d",
            address,
            result,
        )

    def fetch_fp_registers(self: PtraceInterface, registers: Registers) -> None:
        """Fetches the floating-point registers of the specified thread.

        Args:
            registers (Registers): The registers instance to update.
        """
        liblog.debugger("Fetching floating-point registers for thread %d", registers._thread_id)
        self.lib_trace.get_fp_regs(registers._thread_id)

    def flush_fp_registers(self: PtraceInterface, _: Registers) -> None:
        """Flushes the floating-point registers of the specified thread.

        Args:
            registers (Registers): The registers instance to update.
        """
        raise NotImplementedError("Flushing floating-point registers is automatically handled by the native code.")

    def _get_event_msg(self: PtraceInterface, thread_id: int) -> int:
        """Returns the event message."""
        return self.lib_trace.get_event_msg(thread_id)

    def get_maps(self: PtraceInterface) -> MemoryMapList[MemoryMap]:
        """Returns the memory maps of the process."""
        with extend_internal_debugger(self._internal_debugger):
            return get_process_maps(self.process_id)

    def get_hit_watchpoint(self: PtraceInterface, thread_id: int) -> Breakpoint:
        """Returns the watchpoint that has been hit."""
        address = self.lib_trace.get_hit_hw_breakpoint(thread_id)

        if not address:
            return None

        bp = self._internal_debugger.breakpoints[address]

        if bp.condition != "x":
            return bp

        return None
