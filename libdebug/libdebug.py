#
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TypeVar

from elftools.common.exceptions import ELFError

from libdebug.data.argument_list import ArgumentList
from libdebug.data.env_dict import EnvDict
from libdebug.debugger.debugger import Debugger
from libdebug.debugger.internal_debugger import InternalDebugger
from libdebug.liblog import liblog
from libdebug.utils.container import (
    detect_runtime,
    discard_tempfile,
    extract_container_binary,
    get_container_init_pid,
)
from libdebug.utils.elf_utils import elf_architecture, resolve_argv_path
from libdebug.utils.libcontext import libcontext
from libdebug.utils.thread_exceptions import setup_signal_handler

DebuggerT = TypeVar("DebuggerT", bound=Debugger)


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
    stop_on_fork: bool = False,
    stop_on_exec: bool = False,
    stop_on_clone: bool = False,
    preserve_event_hooks_on_exec: bool = True,
    cls: type[DebuggerT] = Debugger,
    container: str | None = None,
    runtime: str | None = None,
) -> DebuggerT:
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
        stop_on_fork (bool, optional): Whether to stop the debugged process on fork. Defaults to False.
        stop_on_exec (bool, optional): Whether to stop the debugged process on exec. Defaults to False.
        stop_on_clone (bool, optional): Whether to stop the debugged process on clone. Defaults to False.
        preserve_event_hooks_on_exec (bool, optional): Keep event hooks across exec. If False, remove existing
            user hooks after the current exec callbacks finish. Defaults to True.
        cls (type[DebuggerT], optional): The `Debugger` subclass to instantiate. Defaults to `Debugger`.
        container (str, optional): If set, spawn and trace the target inside the named, already-running container (Docker or Podman). The `path` argument is then interpreted as an absolute path *inside the container*. Defaults to None (host-side debugging).
        runtime (str, optional): Force a specific container runtime ("docker" or "podman"). Defaults to None (auto-detect which runtime knows the named container).

    Returns:
        DebuggerT: The `Debugger` object (or subclass if `cls` is provided).

    Notes:
        The public constructor is the `debugger` factory. The `Debugger` class itself is
        composed of mixins and expects an `InternalDebugger` when instantiated; this keeps
        advanced users free to subclass with their own mixins while everyday users rely on
        the factory for setup. Use `cls` to inject a custom subclass with extra mixins.
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

    container_path: str | None = None
    resolved_runtime: str | None = None
    container_init_pid: int = 0

    if container is not None:
        # ASLR is governed by the container's personality, not the host's. Refusing here avoids
        # the surprising "aslr=False but addresses still randomize" outcome.
        if not aslr:
            raise ValueError(
                "aslr=False is not supported when container= is set; ASLR inside the container is "
                "governed by the container, not the host's personality flags.",
            )

        container_path = path if path is not None else (argv[0] if argv else None)
        if container_path is None:
            raise ValueError("container= requires either path= or argv[0] to point at the in-container binary.")

        # The POSIX-sh wrapper we use to spawn inside the container has no portable way to set
        # argv[0] independently of the executable path. Rather than silently replacing the
        # user's argv[0], we refuse the combination — they can drop argv[0] (we'll synthesize
        # container_path) or fix it to match.
        if argv and len(argv) >= 1 and argv[0] != container_path:
            raise ValueError(
                f"Custom argv[0] is not supported in container mode: argv[0]={argv[0]!r} != "
                f"path={container_path!r}. POSIX sh cannot preserve a distinct argv[0] across the "
                "in-container exec. Either set argv[0] to the binary path, or omit it entirely.",
            )

        resolved_runtime = detect_runtime(container, runtime)
        container_init_pid = get_container_init_pid(resolved_runtime, container)
        path = extract_container_binary(resolved_runtime, container, container_path)
        # In container mode the on-host binary path (a docker-cp'd tempfile) differs from
        # argv[0] (the container-internal path) by construction. Flag this so downstream
        # re-resolution paths don't try to interpret argv[0] as a host filesystem path.
        has_path_different_from_argv0 = True
    else:
        if runtime is not None:
            raise ValueError("runtime= is only meaningful together with container=.")

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
    internal_debugger.container = container
    internal_debugger.runtime = resolved_runtime
    internal_debugger.container_init_pid = container_init_pid
    internal_debugger.container_path = container_path

    debugger = cls(internal_debugger)
    debugger.stop_on_fork = stop_on_fork
    debugger.stop_on_exec = stop_on_exec
    debugger.stop_on_clone = stop_on_clone
    debugger.preserve_event_hooks_on_exec = preserve_event_hooks_on_exec

    internal_debugger.debugger = debugger

    # If we are attaching, we assume the architecture is the same as the current platform
    if argv or container is not None:
        try:
            debugger.arch = elf_architecture(path)
        except (ValueError, ELFError) as e:
            liblog.error(f"Failed to get the architecture of the binary: {e} "
                        "Assuming the architecture is the same as the current platform.")
            debugger.arch = libcontext.platform

        # Tracing across CPU architectures is not possible with ptrace; fail fast with a clear
        # message instead of letting the user discover this via a confusing ptrace error. In
        # container mode, also delete the docker-cp'd tempfile so it doesn't linger.
        if container is not None and debugger.arch != libcontext.platform:
            discard_tempfile(path)
            raise ValueError(
                f"Container binary architecture ({debugger.arch}) does not match the host "
                f"({libcontext.platform}). ptrace cannot cross architectures.",
            )

    return debugger


# At import time, we register a signal handler for exceptions
setup_signal_handler()
