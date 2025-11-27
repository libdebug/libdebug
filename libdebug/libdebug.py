#
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from elftools.common.exceptions import ELFError

from libdebug.data.argument_list import ArgumentList
from libdebug.data.env_dict import EnvDict
from libdebug.debugger.debugger import Debugger
from libdebug.debugger.internal_debugger import InternalDebugger
from libdebug.liblog import liblog
from libdebug.utils.elf_utils import elf_architecture, resolve_argv_path
from libdebug.utils.libcontext import libcontext
from libdebug.utils.thread_exceptions import setup_signal_handler


def debugger(
    argv: str | list[str] | None = None,
    *, # We enforce keyword-only arguments to avoid confusion with argv
    path: str | None = None,
    aslr: bool = True,
    env: dict[str, str] | None = None,
    escape_antidebug: bool = False,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = False,
    fast_memory: bool = True,
    kill_on_exit: bool = True,
    follow_children: bool = True,
) -> Debugger:
    """This function is used to create a new `Debugger` object. It returns a `Debugger` object.

    Args:
        argv (str | list[str], optional): The argument, or list of arguments, passed to the debugged binary.
        path (str, optional): The path to the binary to debug. If this is not provided, the first argument in `argv` will be used.
        aslr (bool, optional): Whether to enable ASLR. Defaults to True.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        escape_antidebug (bool): Whether to automatically attempt to patch antidebugger detectors based on the ptrace syscall.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to False.
        fast_memory (bool, optional): Whether to use a faster memory reading method. Defaults to True.
        kill_on_exit (bool, optional): Whether to kill the debugged process when the debugger exits. Defaults to True.
        follow_children (bool, optional): Whether to follow child processes. Defaults to True, which means that a new debugger will be created for each child process automatically.

    Returns:
        Debugger: The `Debugger` object.

    Notes:
        The public constructor is the `debugger` factory. The `Debugger` class itself is
        composed of mixins and expects an `InternalDebugger` when instantiated; this keeps
        advanced users free to subclass with their own mixins while everyday users rely on
        the factory for setup.
    """
    if isinstance(argv, str):
        argv = ArgumentList([argv])
    elif isinstance(argv, list):
        argv = ArgumentList(argv)
    elif argv is None:
        argv = ArgumentList()

    # We must note inside the debugger if the path is different from the first argument in argv
    # We use this parameter to determine if we need to resolve the path again
    has_path_different_from_argv0 = path is not None

    if path:
        path = resolve_argv_path(path)
    elif argv:
        path = resolve_argv_path(argv[0])

    if env is not None:
        if not isinstance(env, dict):
            raise TypeError("env must be a dictionary or None")
        env = EnvDict(env)

    internal_debugger = InternalDebugger()
    internal_debugger.argv = argv
    internal_debugger.path = path
    internal_debugger.env = env
    internal_debugger.aslr_enabled = aslr
    internal_debugger.autoreach_entrypoint = continue_to_binary_entrypoint
    internal_debugger.auto_interrupt_on_command = auto_interrupt_on_command
    internal_debugger.escape_antidebug = escape_antidebug
    internal_debugger.fast_memory = fast_memory
    internal_debugger.kill_on_exit = kill_on_exit
    internal_debugger.follow_children = follow_children
    internal_debugger._has_path_different_from_argv0 = has_path_different_from_argv0

    debugger = Debugger(internal_debugger)
    internal_debugger.debugger = debugger

    # If we are attaching, we assume the architecture is the same as the current platform
    if argv:
        try:
            debugger.arch = elf_architecture(path)
        except (ValueError, ELFError) as e:
            liblog.error(f"Failed to get the architecture of the binary: {e} "
                        "Assuming the architecture is the same as the current platform.")
            debugger.arch = libcontext.platform

    return debugger


# At import time, we register a signal handler for exceptions
setup_signal_handler()
