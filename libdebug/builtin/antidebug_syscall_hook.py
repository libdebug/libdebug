#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import Commands
from libdebug.state.thread_context import ThreadContext


def on_enter_ptrace(t: ThreadContext, syscall_number: int) -> None:
    """Callback for ptrace syscall onenter."""
    this_hook = t._internal_debugger.syscall_hooks[syscall_number]

    this_hook._command = t.syscall_arg0

    command = Commands(t.syscall_arg0)
    liblog.debugger(f"entered ptrace syscall with request: {command.name}")


def on_exit_ptrace(t: ThreadContext, syscall_number: int) -> None:
    """Callback for ptrace syscall onexit."""
    this_hook = t._internal_debugger.syscall_hooks[syscall_number]

    if this_hook._command is None:
        liblog.error("ptrace onexit called without corresponding onenter. This should not happen.")
        return

    match this_hook._command:
        case Commands.PTRACE_TRACEME:
            if not this_hook._traceme_called:
                this_hook._traceme_called = True
                t.syscall_return = 0
        case _:
            liblog.error(f"ptrace syscall with request {this_hook._command} not supported")
