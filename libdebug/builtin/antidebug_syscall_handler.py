#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.syscall_handler import SyscallHandler
from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import Commands
from libdebug.state.thread_context import ThreadContext


def on_enter_ptrace(t: ThreadContext, handler: SyscallHandler) -> None:
    """Callback for ptrace syscall onenter."""
    handler._command = t.syscall_arg0

    command = Commands(t.syscall_arg0)
    liblog.debugger(f"entered ptrace syscall with request: {command.name}")


def on_exit_ptrace(t: ThreadContext, handler: SyscallHandler) -> None:
    """Callback for ptrace syscall onexit."""
    if handler._command is None:
        liblog.error("ptrace onexit called without corresponding onenter. This should not happen.")
        return

    match handler._command:
        case Commands.PTRACE_TRACEME:
            if not handler._traceme_called:
                handler._traceme_called = True
                t.syscall_return = 0
        case _:
            liblog.error(f"ptrace syscall with request {handler._command} not supported")
