#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import signal
from typing import TYPE_CHECKING

from libdebug.architectures.ptrace_software_breakpoint_patcher import (
    software_breakpoint_byte_size,
)
from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import SYSCALL_SIGTRAP, StopEvents
from libdebug.state.resume_context import EventType
from libdebug.utils.process_utils import get_process_tasks
from libdebug.utils.signal_utils import resolve_signal_name

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.ptrace.ptrace_interface import PtraceInterface
    from libdebug.state.thread_context import ThreadContext


class PtraceStatusHandler:
    """This class handles the states return by the waitpid calls on the debugger process."""

    def __init__(self: PtraceStatusHandler) -> None:
        """Initializes the PtraceStatusHandler class."""
        self.internal_debugger = provide_internal_debugger(self)
        self.ptrace_interface: PtraceInterface = self.internal_debugger.debugging_interface
        self.forward_signal: bool = True
        self._assume_race_sigstop: bool = (
            True  # Assume the stop is due to a race condition with SIGSTOP sent by the debugger
        )
        self.executing_arbitrary_syscall: bool = False

    def _handle_clone(self: PtraceStatusHandler, thread_id: int, results: list) -> None:
        # https://go.googlesource.com/debug/+/a09ead70f05c87ad67bd9a131ff8352cf39a6082/doc/ptrace-nptl.txt
        # "At this time, the new thread will exist, but will initially
        # be stopped with a SIGSTOP.  The new thread will automatically be
        # traced and will inherit the PTRACE_O_TRACECLONE option from its
        # parent.  The attached process should wait on the new thread to receive
        # the SIGSTOP notification."

        # Check if we received the SIGSTOP notification for the new thread
        # If not, we need to wait for it
        # 4991 == (WIFSTOPPED && WSTOPSIG(status) == SIGSTOP)
        if (thread_id, 4991) not in results:
            os.waitpid(thread_id, 0)
        self.ptrace_interface.register_new_thread(thread_id)

    def _handle_exit(
        self: PtraceStatusHandler,
        thread_id: int,
        exit_code: int | None,
        exit_signal: int | None,
    ) -> None:
        if self.internal_debugger.get_thread_by_id(thread_id):
            self.ptrace_interface.unregister_thread(thread_id, exit_code=exit_code, exit_signal=exit_signal)

    def _handle_breakpoints(self: PtraceStatusHandler, thread_id: int) -> None:
        thread = self.internal_debugger.get_thread_by_id(thread_id)

        if not hasattr(thread, "instruction_pointer"):
            # This is a signal trap hit on process startup
            # Do not resume the process until the user decides to do so
            self.internal_debugger.resume_context.event_type[thread_id] = EventType.STARTUP
            self.internal_debugger.resume_context.resume = False
            self.forward_signal = False
            return

        ip = thread.instruction_pointer

        bp: None | Breakpoint

        bp = self.internal_debugger.breakpoints.get(ip)
        if bp and bp._enabled and not bp._disabled_for_step:
            # Hardware breakpoint hit
            liblog.debugger("Hardware breakpoint hit at 0x%x", ip)
        else:
            # If the trap was caused by a software breakpoint, we need to restore the original instruction
            # and set the instruction pointer to the previous instruction.
            ip -= software_breakpoint_byte_size(self.internal_debugger.arch)

            bp = self.internal_debugger.breakpoints.get(ip)
            if bp and bp._enabled and not bp._disabled_for_step:
                # Software breakpoint hit
                liblog.debugger("Software breakpoint hit at 0x%x", ip)

                # Set the instruction pointer to the previous instruction
                thread.instruction_pointer = ip

                # Link the breakpoint to the thread, so that we can step over it
                bp._linked_thread_ids.append(thread_id)
            else:
                # If the breakpoint has been hit but is not enabled, we need to reset the bp variable
                bp = None

        # Manage watchpoints
        if not bp:
            bp = self.ptrace_interface.get_hit_watchpoint(thread_id)
            if bp:
                liblog.debugger("Watchpoint hit at 0x%x", bp.address)
        if bp:
            self.internal_debugger.resume_context.event_hit_ref[thread_id] = bp
            self.internal_debugger.resume_context.event_type[thread_id] = EventType.BREAKPOINT
            self.forward_signal = False
            bp.hit_count += 1

            if bp.callback:
                try:
                    bp.callback(thread, bp)
                except Exception as e:  # noqa: BLE001
                    liblog.error('Exception raised while executing callback for breakpoint at "%s": %s', bp.symbol, e)
                    raise RuntimeError("Unhandled exception in breakpoint callback") from e
            else:
                # If the breakpoint has no callback, we need to stop the process despite the other signals
                self.internal_debugger.resume_context.resume = False

    def _manage_syscall_on_enter(
        self: PtraceStatusHandler,
        handler: SyscallHandler,
        thread: ThreadContext,
        syscall_number: int,
        hijacked_set: set[int],
    ) -> None:
        """Manage the on_enter callback of a syscall."""
        # Call the user-defined callback if it exists
        if handler.on_enter_user and handler._enabled:
            old_args = [
                thread.syscall_arg0,
                thread.syscall_arg1,
                thread.syscall_arg2,
                thread.syscall_arg3,
                thread.syscall_arg4,
                thread.syscall_arg5,
            ]
            try:
                handler.on_enter_user(thread, handler)
            except Exception as e:  # noqa: BLE001
                liblog.error("Exception raised in on-enter callback for syscall %d: %s", handler.syscall_number, e)
                raise RuntimeError("Unhandled exception in syscall callback") from e

            if not handler.enabled:
                # The syscall has been disabled by the user, we will never hit the on_exit
                # so we have to increment the hit count here
                handler.hit_count += 1

            # Check if the syscall number has changed
            syscall_number_after_callback = thread.syscall_number

            if syscall_number_after_callback != syscall_number:
                if self.executing_arbitrary_syscall:
                    liblog.warning("Syscall hijacking callback is active, syscall invocation will be changed accordingly")
                # The syscall number has changed
                # Pretty print the syscall number before the callback
                if handler.on_enter_pprint:
                    handler.on_enter_pprint(
                        thread,
                        syscall_number,
                        hijacked=True,
                        old_args=old_args,
                    )
                if syscall_number_after_callback in self.internal_debugger.handled_syscalls:
                    callback_hijack = self.internal_debugger.handled_syscalls[syscall_number_after_callback]

                    # Check if the new syscall has to be handled recursively
                    if handler.recursive:
                        if syscall_number_after_callback not in hijacked_set:
                            hijacked_set.add(syscall_number_after_callback)
                        else:
                            # The syscall has already been hijacked in the current chain
                            raise RuntimeError(
                                "Syscall hijacking loop detected. Check your code to avoid infinite loops.",
                            )

                        # Call recursively the function to manage the new syscall
                        self._manage_syscall_on_enter(
                            callback_hijack,
                            thread,
                            syscall_number_after_callback,
                            hijacked_set,
                        )
                    elif callback_hijack.on_enter_pprint:
                        # Pretty print the syscall number
                        callback_hijack.on_enter_pprint(thread, syscall_number_after_callback, hijacker=True)
                        callback_hijack._has_entered = True
                        callback_hijack._skip_exit = True
                    else:
                        # Skip the exit callback of the syscall that has been hijacked
                        callback_hijack._has_entered = True
                        callback_hijack._skip_exit = True
            elif handler.on_enter_pprint:
                # Pretty print the syscall number
                handler.on_enter_pprint(thread, syscall_number, callback=True, old_args=old_args)
                handler._has_entered = True
            else:
                handler._has_entered = True
        elif handler.on_enter_pprint:
            # Pretty print the syscall number
            handler.on_enter_pprint(thread, syscall_number, callback=(handler.on_exit_user is not None))
            handler._has_entered = True
        elif handler.on_exit_pprint or handler.on_exit_user:
            # The syscall has been entered but the user did not define an on_enter callback
            handler._has_entered = True
        if not handler.on_enter_user and not handler.on_exit_user and handler._enabled:
            # If the syscall has no callback, we need to stop the process despite the other signals
            self.internal_debugger.resume_context.event_type[thread.thread_id] = EventType.SYSCALL
            handler._has_entered = True
            self.internal_debugger.resume_context.resume = False

    def handle_syscall(self: PtraceStatusHandler, thread_id: int) -> bool:
        """Handle a syscall trap."""
        thread = self.internal_debugger.get_thread_by_id(thread_id)

        if not hasattr(thread, "syscall_number"):
            # This is another spurious trap, we don't know what to do with it
            return

        syscall_number = thread.syscall_number

        if syscall_number in self.internal_debugger.handled_syscalls:
            handler = self.internal_debugger.handled_syscalls[syscall_number]
        elif -1 in self.internal_debugger.handled_syscalls:
            # Handle all syscalls is enabled
            handler = self.internal_debugger.handled_syscalls[-1]
        elif self.executing_arbitrary_syscall:
            self.internal_debugger.resume_context.event_type[thread_id] = EventType.SYSCALL
            self.internal_debugger.resume_context.event_hit_ref[thread_id] = None
            self.internal_debugger.resume_context.resume = False
            return
        else:
            # This is a syscall we don't care about
            # Resume the execution
            return

        self.internal_debugger.resume_context.event_hit_ref[thread_id] = handler

        if not handler._has_entered:
            # The syscall is being entered
            liblog.debugger(
                "Syscall %d entered on thread %d",
                syscall_number,
                thread_id,
            )

            self._manage_syscall_on_enter(
                handler,
                thread,
                syscall_number,
                {syscall_number},
            )

        else:
            # The syscall is being exited
            liblog.debugger("Syscall %d exited on thread %d", syscall_number, thread_id)

            if handler._enabled and not handler._skip_exit:
                # Increment the hit count only if the syscall has been handled
                handler.hit_count += 1

            # Call the user-defined callback if it exists
            if handler.on_exit_user and handler._enabled and not handler._skip_exit:
                # Pretty print the return value before the callback
                if handler.on_exit_pprint:
                    return_value_before_callback = thread.syscall_return

                try:
                    handler.on_exit_user(thread, handler)
                except Exception as e: # noqa: BLE001
                    liblog.error("Exception raised in on-exit callback for syscall %d: %s", handler.syscall_number, e)
                    raise RuntimeError("Unhandled exception in syscall callback") from e

                if handler.on_exit_pprint:
                    return_value_after_callback = thread.syscall_return
                    if return_value_after_callback != return_value_before_callback:
                        handler.on_exit_pprint(
                            thread,
                            (return_value_before_callback, return_value_after_callback),
                        )
                    else:
                        handler.on_exit_pprint(thread, return_value_after_callback)
            elif handler.on_exit_pprint:
                # Pretty print the return value
                handler.on_exit_pprint(thread, thread.syscall_return)

            handler._has_entered = False
            handler._skip_exit = False
            if (
                not handler.on_enter_user and not handler.on_exit_user and handler.enabled
            ) or self.executing_arbitrary_syscall:
                # If the syscall has no callback, we need to stop the process despite the other signals
                self.internal_debugger.resume_context.event_type[thread_id] = EventType.SYSCALL
                self.internal_debugger.resume_context.resume = False

    def _manage_caught_signal(
        self: PtraceStatusHandler,
        catcher: SignalCatcher,
        thread: ThreadContext,
        signal_number: int,
        hijacked_set: set[int],
    ) -> None:
        if catcher._enabled:
            catcher.hit_count += 1
            liblog.debugger(
                "Caught signal %s (%d) hit on thread %d",
                resolve_signal_name(signal_number),
                signal_number,
                thread.thread_id,
            )
            if catcher.callback:
                # Execute the user-defined callback
                try:
                    catcher.callback(thread, catcher)
                except Exception as e:
                    liblog.error(
                        "Exception raised in callback for signal %s: %s",
                        resolve_signal_name(signal_number),
                        e,
                    )
                    raise RuntimeError("Unhandled exception in signal callback") from e

                new_signal_number = thread._signal_number

                if new_signal_number != signal_number:
                    # The signal number has changed
                    liblog.debugger(
                        "Signal %s (%d) has been hijacked to %s (%d)",
                        resolve_signal_name(signal_number),
                        signal_number,
                        resolve_signal_name(new_signal_number),
                        new_signal_number,
                    )

                    if catcher.recursive and new_signal_number in self.internal_debugger.caught_signals:
                        hijack_cath_signal = self.internal_debugger.caught_signals[new_signal_number]
                        if new_signal_number not in hijacked_set:
                            hijacked_set.add(new_signal_number)
                        else:
                            # The signal has already been replaced in the current chain
                            raise RuntimeError(
                                "Signal hijacking loop detected. Check your script to avoid infinite loops.",
                            )
                        # Call recursively the function to manage the new signal
                        self._manage_caught_signal(
                            hijack_cath_signal,
                            thread,
                            new_signal_number,
                            hijacked_set,
                        )
            else:
                # If the caught signal has no callback, we need to stop the process despite the other signals
                self.internal_debugger.resume_context.event = EventType.SIGNAL
                self.internal_debugger.resume_context.resume = False

    def _handle_signal(self: PtraceStatusHandler, thread: ThreadContext) -> bool:
        """Handle the signal trap."""
        signal_number = thread._signal_number

        if signal_number in self.internal_debugger.caught_signals:
            catcher = self.internal_debugger.caught_signals[signal_number]

            self._manage_caught_signal(catcher, thread, signal_number, {signal_number})
        elif -1 in self.internal_debugger.caught_signals and signal_number not in (
            signal.SIGSTOP,
            signal.SIGKILL,
        ):
            # Handle all signals is enabled
            catcher = self.internal_debugger.caught_signals[-1]

            self.internal_debugger.resume_context.event_hit_ref[thread.thread_id] = catcher

            self._manage_caught_signal(catcher, thread, signal_number, {signal_number})

    def _internal_signal_handler(
        self: PtraceStatusHandler,
        pid: int,
        signum: int,
        results: list,
        status: int,
        thread: ThreadContext,
    ) -> None:
        """Internal handler for signals used by the debugger."""
        if signum == SYSCALL_SIGTRAP:
            # We hit a syscall
            liblog.debugger("Child thread %d stopped on syscall", pid)
            self.handle_syscall(pid)
            self.forward_signal = False
        elif signum == signal.SIGSTOP and self.internal_debugger.resume_context.force_interrupt:
            # The user has requested an interrupt, we need to stop the process despite the ohter signals
            liblog.debugger(
                "Child thread %d stopped with signal %s",
                pid,
                resolve_signal_name(signum),
            )
            self.internal_debugger.resume_context.event_type[pid] = EventType.USER_INTERRUPT
            self.internal_debugger.resume_context.resume = False
            self.internal_debugger.resume_context.force_interrupt = False
            self.forward_signal = False
        elif signum == signal.SIGTRAP:
            # The trap decides if we hit a breakpoint. If so, it decides whether we should stop or
            # continue the execution and wait for the next trap
            self._handle_breakpoints(pid)

            if self.internal_debugger.resume_context.is_a_step:
                # The process is stepping, we need to stop the execution
                self.internal_debugger.resume_context.event_type[pid] = EventType.STEP
                self.internal_debugger.resume_context.resume = False
                self.internal_debugger.resume_context.is_a_step = False
                self.forward_signal = False

            event = status >> 8
            match event:
                case StopEvents.CLONE_EVENT:
                    # The process has been cloned
                    message = self.ptrace_interface._get_event_msg(pid)
                    liblog.debugger(
                        f"Process {pid} cloned, new thread_id: {message}",
                    )
                    self._handle_clone(message, results)
                    self.forward_signal = False
                    self.internal_debugger.resume_context.event_type[pid] = EventType.CLONE
                case StopEvents.SECCOMP_EVENT:
                    # The process has installed a seccomp
                    liblog.debugger(f"Process {pid} installed a seccomp")
                    self.forward_signal = False
                    self.internal_debugger.resume_context.event_type[pid] = EventType.SECCOMP
                case StopEvents.EXIT_EVENT:
                    # The tracee is still alive; it needs
                    # to be PTRACE_CONTed or PTRACE_DETACHed to finish exiting.
                    # so we don't call self._handle_exit(pid) here
                    # it will be called at the next wait (hopefully)
                    message = self.ptrace_interface._get_event_msg(pid)
                    # Mark the thread as a zombie
                    thread._zombie = True
                    liblog.debugger(
                        f"Thread {pid} exited with status: {message}",
                    )
                    self.forward_signal = False
                    self.internal_debugger.resume_context.event_type[pid] = EventType.EXIT
                case StopEvents.FORK_EVENT:
                    # The process has been forked
                    message = self.ptrace_interface._get_event_msg(pid)
                    liblog.debugger(
                        f"Process {pid} forked with new pid: {message}",
                    )
                    # We need to detach from the child process and attach to it again with a new debugger
                    self.ptrace_interface.lib_trace.detach_from_child(message, self.internal_debugger.follow_children)
                    if self.internal_debugger.follow_children:
                        self.internal_debugger.set_child_debugger(message)
                    self.forward_signal = False
                    self.internal_debugger.resume_context.event_type[pid] = EventType.FORK

    def _handle_change(self: PtraceStatusHandler, pid: int, status: int, results: list) -> None:
        """Handle a change in the status of a traced process."""
        # Initialize the forward_signal flag
        self.forward_signal = True

        if os.WIFSTOPPED(status):
            if self.internal_debugger.resume_context.is_startup:
                # The process has just started
                return
            signum = os.WSTOPSIG(status)

            if signum != signal.SIGSTOP:
                self._assume_race_sigstop = False

            thread = self.internal_debugger.get_thread_by_id(pid)

            # Check if the debugger needs to handle the signal
            self._internal_signal_handler(pid, signum, results, status, thread)

            if signum != SYSCALL_SIGTRAP and thread is not None:
                thread._signal_number = signum & 0x7F

                # Handle the signal
                if self.internal_debugger.resume_context.event_type.get(pid, None) is None:
                    self._handle_signal(thread)

                if self.forward_signal and signum != signal.SIGSTOP:
                    # We have to forward the signal to the thread
                    self.internal_debugger.resume_context.threads_with_signals_to_forward.append(pid)

        if os.WIFEXITED(status):
            # The thread has exited normally
            exit_code = os.WEXITSTATUS(status)
            liblog.debugger("Child process %d exited with exit code %d", pid, exit_code)
            self._handle_exit(pid, exit_code=exit_code, exit_signal=None)

        if os.WIFSIGNALED(status):
            # The thread has exited with a signal
            exit_signal = os.WTERMSIG(status)
            liblog.debugger("Child process %d exited with signal %d", pid, exit_signal)
            self._handle_exit(pid, exit_code=None, exit_signal=exit_signal)

    def manage_change(self: PtraceStatusHandler, result: list[tuple]) -> None:
        """Manage the result of the waitpid and handle the changes."""
        # Assume that the stop depends on SIGSTOP sent by the debugger
        # This is a workaround for some race conditions that may happen
        self._assume_race_sigstop = True

        # We declare in the ResumeContext that we are executing a few callbacks
        self.internal_debugger.resume_context.is_in_callback = True

        for pid, status in result:
            if pid != -1:
                # Otherwise, this is a spurious trap
                self._handle_change(pid, status, result)

        # Callbacks are done
        self.internal_debugger.resume_context.is_in_callback = False

        if self._assume_race_sigstop:
            # Resume the process if the stop was due to a race condition with SIGSTOP sent by the debugger
            return

    def check_for_changes_in_threads(self: PtraceStatusHandler, pid: int) -> None:
        """Check for new threads in the process and register them."""
        tids = get_process_tasks(pid)
        for tid in tids:
            if not self.internal_debugger.get_thread_by_id(tid):
                self.ptrace_interface.register_new_thread(tid)
                liblog.debugger("Manually registered new thread %d" % tid)

        for thread in self.internal_debugger.threads:
            if not thread.dead and thread.thread_id not in tids:
                self.ptrace_interface.unregister_thread(thread.thread_id, None, None)
                liblog.debugger("Manually unregistered thread %d" % thread.thread_id)

    def is_in_syscall_callback(self: PtraceStatusHandler, thread: ThreadContext) -> bool:
        """Check if we are in a syscall callback.

        Args:
            thread (ThreadContext): The thread to check.

        Returns:
            bool: True if we are in a syscall callback, False otherwise.
        """
        resume_context = self.internal_debugger.resume_context

        return resume_context.is_in_callback and \
        resume_context.event_type == EventType.SYSCALL and \
        resume_context.event_hit_ref[thread.thread_id] is not None
