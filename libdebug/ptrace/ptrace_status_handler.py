#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import signal
from typing import TYPE_CHECKING

from libdebug.architectures.ptrace_software_breakpoint_patcher import (
    software_breakpoint_byte_size,
)
from libdebug.data.syscall_hook import SyscallHook
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import SYSCALL_SIGTRAP, StopEvents
from libdebug.state.debugging_context import provide_context
from libdebug.state.thread_context import ThreadContext

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


class PtraceStatusHandler:
    def __init__(self):
        self.context = provide_context(self)
        self.ptrace_interface = self.context.debugging_interface

    def _handle_clone(self, thread_id: int, results: list):
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

    def _handle_exit(self, thread_id: int):
        if self.context.get_thread_by_id(thread_id):
            self.ptrace_interface.unregister_thread(thread_id)

    def _handle_trap(self, thread_id: int) -> bool:
        if thread_id == -1:
            # This is a spurious trap, we don't know what to do with it
            return False

        thread = self.context.get_thread_by_id(thread_id)

        if not hasattr(thread, "instruction_pointer"):
            # This is a signal trap hit on process startup
            return False

        ip = thread.instruction_pointer

        bp: None | "Breakpoint"

        enabled_breakpoints = {}
        for bp in self.context.breakpoints.values():
            if bp.enabled and not bp._disabled_for_step:
                enabled_breakpoints[bp.address] = bp

        bp = None

        if ip in enabled_breakpoints:
            # Hardware breakpoint hit
            liblog.debugger("Hardware breakpoint hit at 0x%x", ip)
            bp = self.context.breakpoints[ip]
        else:
            # If the trap was caused by a software breakpoint, we need to restore the original instruction
            # and set the instruction pointer to the previous instruction.
            ip -= software_breakpoint_byte_size()

            if ip in enabled_breakpoints:
                # Software breakpoint hit
                liblog.debugger("Software breakpoint hit at 0x%x", ip)
                bp = self.context.breakpoints[ip]

                # Set the instruction pointer to the previous instruction
                thread.instruction_pointer = ip

                # Link the breakpoint to the thread, so that we can step over it
                bp._linked_thread_ids.append(thread_id)

        if bp:
            bp.hit_count += 1

            if bp.callback:
                # This is a bit of a hack, but we will make it work for now
                # Better than swapping global variables for everyone
                thread._in_background_op = True
                bp.callback(thread, bp)
                thread._in_background_op = False
                return True

        return False

    def _manage_on_enter(
        self,
        hook: SyscallHook,
        thread: ThreadContext,
        syscall_number: int,
        hijacked_list: list[int],
    ):
        """Manage the on_enter hook of a syscall."""
        # Call the user-defined hook if it exists
        if hook.on_enter_user and hook.enabled:
            old_args = [
                thread.syscall_arg0,
                thread.syscall_arg1,
                thread.syscall_arg2,
                thread.syscall_arg3,
                thread.syscall_arg4,
                thread.syscall_arg5,
            ]
            hook.on_enter_user(thread, syscall_number)

            # Check if the syscall number has changed
            syscall_number_after_hook = thread.syscall_number

            if syscall_number_after_hook != syscall_number:
                # Pretty print the syscall number before the hook
                if hook.on_enter_pprint:
                    hook.on_enter_pprint(thread, syscall_number, hijacked=True, old_args=old_args)

                # The syscall number has changed
                if syscall_number_after_hook in self.context.syscall_hooks:
                    hook_hijack = self.context.syscall_hooks[syscall_number_after_hook]

                    # Check if the new syscall has to be hooked
                    if hook.hook_hijack:
                        if syscall_number_after_hook not in hijacked_list: 
                            hijacked_list.append(syscall_number_after_hook)
                        else:
                            # The syscall has already been hijacked in the current chain
                            raise RuntimeError(
                                "Syscall hijacking loop detected. Check your hooks to avoid infinite loops."
                            )

                        # Call recursively the function to manage the new syscall
                        self._manage_on_enter(
                            hook_hijack,
                            thread,
                            syscall_number_after_hook,
                            hijacked_list,
                        )
                    elif hook_hijack.on_enter_pprint:
                        # Pretty print the syscall number
                        hook_hijack.on_enter_pprint(thread, syscall_number_after_hook)
                        hook_hijack._has_entered = True
                        hook_hijack._skip_exit = True
                    else:
                        # Skip the exit hook of the syscall that has been hijacked
                        hook_hijack._has_entered = True
                        hook_hijack._skip_exit = True
            elif hook.on_enter_pprint:
                # Pretty print the syscall number
                hook.on_enter_pprint(thread, syscall_number, user_hooked=True)
                hook._has_entered = True
            else:
                hook._has_entered = True
        elif hook.on_enter_pprint:
            # Pretty print the syscall number
            hook.on_enter_pprint(thread, syscall_number)
            hook._has_entered = True
        elif hook.on_exit_pprint or hook.on_exit_user:
            # The syscall has been entered but the user did not define an on_enter hook
            hook._has_entered = True

    def _handle_syscall(self, thread_id: int) -> bool:
        """Handle a syscall trap."""
        if thread_id == -1:
            # This is a spurious trap, we don't know what to do with it
            return False

        thread = self.context.get_thread_by_id(thread_id)

        if not hasattr(thread, "syscall_number"):
            # This is another spurious trap, we don't know what to do with it
            return False

        syscall_number = thread.syscall_number

        if syscall_number not in self.context.syscall_hooks:
            # This is a syscall we don't care about
            # Resume the execution
            return True

        hook = self.context.syscall_hooks[syscall_number]

        thread._in_background_op = True

        if not hook._has_entered:
            # The syscall is being entered
            liblog.debugger(
                "Syscall %d entered on thread %d", syscall_number, thread_id
            )

            self._manage_on_enter(hook, thread, syscall_number, [syscall_number])

        else:
            # The syscall is being exited
            liblog.debugger("Syscall %d exited on thread %d", syscall_number, thread_id)

            if hook.enabled and not hook._skip_exit:
                # Increment the hit count only if the syscall hook is enabled
                hook.hit_count += 1

            # Call the user-defined hook if it exists
            if hook.on_exit_user and hook.enabled and not hook._skip_exit:
                # Pretty print the return value before the hook
                if hook.on_exit_pprint:
                    return_value_before_hook = thread.syscall_return
                hook.on_exit_user(thread, syscall_number)
                if hook.on_exit_pprint:
                    return_value_after_hook = thread.syscall_return
                    if return_value_after_hook != return_value_before_hook:
                        hook.on_exit_pprint(
                            (return_value_before_hook, return_value_after_hook)
                        )
                    else:
                        hook.on_exit_pprint(return_value_after_hook)
            elif hook.on_exit_pprint:
                # Pretty print the return value
                hook.on_exit_pprint(thread.syscall_return)

            hook._has_entered = False
            hook._skip_exit = False

        thread._in_background_op = False

        return True

    def _handle_change(self, pid: int, status: int, results: list) -> bool:
        """Handle a change in the status of a traced process. Return True if the process should start waiting again."""
        event = status >> 8

        # By default, we block at the first wait we don't recognize
        restart_wait = False

        if os.WIFSTOPPED(status):
            signum = os.WSTOPSIG(status)

            if signum == SYSCALL_SIGTRAP:
                liblog.debugger("Child thread %d stopped on syscall hook", pid)
                return self._handle_syscall(pid)

            signame = signal.Signals(signum).name
            liblog.debugger("Child thread %d stopped with signal %s", pid, signame)

            if signum == signal.SIGTRAP:
                # The trap decides if we hit a breakpoint
                # And if so, it returns whether we should stop or
                # continue the execution and wait for the next trap
                restart_wait |= self._handle_trap(pid)

            match event:
                case StopEvents.CLONE_EVENT:
                    message = self.ptrace_interface._get_event_msg(pid)
                    liblog.debugger(
                        "Process {} cloned, new thread_id: {}".format(pid, message)
                    )
                    self._handle_clone(message, results)

                case StopEvents.SECCOMP_EVENT:
                    liblog.debugger("Process {} installed a seccomp".format(pid))

                case StopEvents.EXIT_EVENT:
                    # The tracee is still alive; it needs
                    # to be PTRACE_CONTed or PTRACE_DETACHed to finish exiting.
                    # so we don't call self._handle_exit(pid) here
                    # it will be called at the next wait (hopefully)
                    message = self.ptrace_interface._get_event_msg(pid)
                    liblog.debugger(
                        "Thread {} exited with status: {}".format(pid, message)
                    )

        if os.WIFEXITED(status):
            exitstatus = os.WEXITSTATUS(status)
            liblog.debugger("Child process %d exited with status %d", pid, exitstatus)
            self._handle_exit(pid)

        if os.WIFSIGNALED(status):
            termsig = os.WTERMSIG(status)
            liblog.debugger("Child process %d exited with signal %d", pid, termsig)
            self._handle_exit(pid)

        return restart_wait

    def check_result(self, result):
        repeat = False

        for pid, status in result:
            repeat |= self._handle_change(pid, status, result)

        return repeat

    def check_for_new_threads(self, pid: int):
        """Check for new threads in the process and register them."""
        if not os.path.exists(f"/proc/{pid}/task"):
            return

        tids = [int(x) for x in os.listdir(f"/proc/{pid}/task")]
        for tid in tids:
            if not self.context.get_thread_by_id(tid):
                self.ptrace_interface.register_new_thread(tid)
                print("Manually registered new thread %d", tid)
