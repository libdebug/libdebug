#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import Commands
from libdebug.state.debugging_context import provide_context
from libdebug.state.thread_context import ThreadContext


def install_antidebug_hook(d: ThreadContext):
    """Installs a syscall hook that will detect any attempt to ptrace the process, and emulate the expected return value."""

    def on_enter_ptrace(d, syscall_number):
        this_hook = provide_context(d).syscall_hooks[syscall_number]

        this_hook._command = d.syscall_arg0

        command = Commands(d.syscall_arg0)
        liblog.debugger(f"entered ptrace syscall with request: {command.name}")

    def on_exit_ptrace(d, syscall_number):
        this_hook = provide_context(d).syscall_hooks[syscall_number]

        if this_hook._command is None:
            liblog.error(
                "ptrace onexit called without corresponding onenter. This should not happen."
            )
            return

        match this_hook._command:
            case Commands.PTRACE_TRACEME:
                if not this_hook._traceme_called:
                    this_hook._traceme_called = True
                    d.syscall_return = 0
            case _:
                liblog.error(
                    f"ptrace syscall with request {this_hook._command} not supported"
                )

    hook = d.hook_syscall("ptrace", on_enter_ptrace, on_exit_ptrace)

    # setup hidden state for the hook
    hook._traceme_called = False
    hook._command = None
