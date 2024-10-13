#
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.debugger.debugger import Debugger
from libdebug.debugger.internal_debugger import InternalDebugger
from libdebug.utils.elf_utils import elf_architecture, resolve_argv_path


def debugger(
    argv: str | list[str] = [],
    aslr: bool = True,
    env: dict[str, str] | None = None,
    escape_antidebug: bool = False,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = False,
    fast_memory: bool = False,
    kill_on_exit: bool = True,
) -> Debugger:
    """This function is used to create a new `Debugger` object. It returns a `Debugger` object.

    Args:
        argv (str | list[str], optional): The location of the binary to debug and any arguments to pass to it.
        aslr (bool, optional): Whether to enable ASLR. Defaults to True.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        escape_antidebug (bool): Whether to automatically attempt to patch antidebugger detectors based on the ptrace syscall.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to False.
        fast_memory (bool, optional): Whether to use a faster memory reading method. Defaults to False.
        kill_on_exit (bool, optional): Whether to kill the debugged process when the debugger exits. Defaults to True.

    Returns:
        Debugger: The `Debugger` object.
    """
    if isinstance(argv, str):
        argv = [resolve_argv_path(argv)]
    else:
        argv[0] = resolve_argv_path(argv[0])

    internal_debugger = InternalDebugger()
    internal_debugger.argv = argv
    internal_debugger.env = env
    internal_debugger.aslr_enabled = aslr
    internal_debugger.autoreach_entrypoint = continue_to_binary_entrypoint
    internal_debugger.auto_interrupt_on_command = auto_interrupt_on_command
    internal_debugger.escape_antidebug = escape_antidebug
    internal_debugger.fast_memory = fast_memory
    internal_debugger.kill_on_exit = kill_on_exit

    debugger = Debugger()
    debugger.post_init_(internal_debugger)

    internal_debugger.debugger = debugger

    # If we are attaching, we assume the architecture is the same as the current platform
    if argv:
        debugger.arch = elf_architecture(argv[0])

    return debugger
