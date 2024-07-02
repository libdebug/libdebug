#
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.debugger.debugger import Debugger
from libdebug.debugger.internal_debugger import InternalDebugger


def debugger(
    argv: str | list[str] = [],
    aslr: bool = False,
    env: dict[str, str] | None = None,
    escape_antidebug: bool = False,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = False,
) -> Debugger:
    """This function is used to create a new `Debugger` object. It returns a `Debugger` object.

    Args:
        argv (str | list[str], optional): The location of the binary to debug, and any additional arguments to pass to it.
        aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        escape_antidebug (bool): Whether to automatically attempt to patch antidebugger detectors based on the ptrace syscall.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to False.

    Returns:
        Debugger: The `Debugger` object.
    """
    if isinstance(argv, str):
        argv = [argv]

    internal_debugger = InternalDebugger()
    internal_debugger.argv = argv
    internal_debugger.env = env
    internal_debugger.aslr_enabled = aslr
    internal_debugger.autoreach_entrypoint = continue_to_binary_entrypoint
    internal_debugger.auto_interrupt_on_command = auto_interrupt_on_command
    internal_debugger.escape_antidebug = escape_antidebug

    debugger = Debugger()
    debugger.post_init_(internal_debugger)

    return debugger
