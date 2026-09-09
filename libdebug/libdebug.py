#
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TypeVar, overload

from elftools.common.exceptions import ELFError

from libdebug.data.argument_list import ArgumentList
from libdebug.data.env_dict import EnvDict
from libdebug.debugger.debugger import Debugger
from libdebug.debugger.docker_internal_debugger import DockerInternalDebugger
from libdebug.debugger.internal_debugger import InternalDebugger
from libdebug.debugger.mixins.docker import DockerDebuggerMixin
from libdebug.liblog import liblog
from libdebug.utils.elf_utils import elf_architecture, resolve_argv_path
from libdebug.utils.libcontext import libcontext
from libdebug.utils.thread_exceptions import setup_signal_handler

DebuggerT = TypeVar("DebuggerT", bound=Debugger)
DockerDebuggerT = TypeVar("DockerDebuggerT", bound=DockerDebuggerMixin)


def _normalize_argv(argv: str | list[str] | None) -> ArgumentList:
    """Normalize the public argv forms to ArgumentList."""
    if isinstance(argv, str):
        return ArgumentList([argv])
    if isinstance(argv, list):
        return ArgumentList(argv)
    if argv is None:
        return ArgumentList()
    raise TypeError("argv must be a string, a list of strings, or None")


def _validate_container_options(
    cls: type[Debugger | DockerDebuggerMixin],
    container: str | None,
    runtime: str | None,
    cache_path: str | None,
    aslr: bool | None,
) -> None:
    if not isinstance(cls, type) or not issubclass(cls, Debugger):
        raise TypeError("cls must be a Debugger subclass")
    docker_enabled = issubclass(cls, DockerDebuggerMixin)
    if not docker_enabled and any(value is not None for value in (container, runtime, cache_path)):
        raise TypeError("Container options require cls to include DockerDebuggerMixin")
    if docker_enabled and (not isinstance(container, str) or not container):
        raise ValueError("A DockerDebuggerMixin class requires a nonempty container name")
    if docker_enabled and aslr is not None:
        raise ValueError("aslr= is not supported for containers; ASLR is controlled by the container")


@overload
def debugger(
    argv: str | list[str] | None = None,
    *,
    path: str | None = None,
    aslr: bool | None = None,
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
) -> Debugger: ...


@overload
def debugger(
    argv: str | list[str] | None = None,
    *,
    path: str | None = None,
    aslr: bool | None = None,
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
    cls: type[DebuggerT],
) -> DebuggerT: ...


@overload
def debugger(
    argv: str | list[str] | None = None,
    *,
    path: str | None = None,
    aslr: bool | None = None,
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
    cls: type[DockerDebuggerT],
    container: str,
    runtime: str | None = None,
    container_cache_path: str | None = None,
) -> DockerDebuggerT: ...


def debugger(
    argv: str | list[str] | None = None,
    *,  # We enforce keyword-only arguments to avoid confusion with argv
    path: str | None = None,
    aslr: bool | None = None,
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
    cls: type[Debugger | DockerDebuggerMixin] = Debugger,
    container: str | None = None,
    runtime: str | None = None,
    container_cache_path: str | None = None,
) -> Debugger | DockerDebuggerMixin:
    """This function is used to create a new `Debugger` object. It returns a `Debugger` object.

    Args:
        argv (str | list[str], optional): The argument, or list of arguments, passed to the debugged binary.
        path (str, optional): The path to the binary to debug. If omitted, argv[0] is used.
        aslr (bool, optional): Whether to enable ASLR. Host debugging defaults to True. Container debugging does not
            accept this argument because ASLR is controlled by the container.
        env (dict[str, str], optional): Environment variables for the debuggee. None inherits the host environment
            for host targets, or the container environment for container targets. A dictionary replaces it.
        escape_antidebug (bool): Whether to patch ptrace-based antidebugger detectors automatically.
        continue_to_binary_entrypoint (bool, optional): Whether to continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether commands interrupt a running process. Defaults to False.
        fast_memory (bool, optional): Whether to use a faster memory reading method. Defaults to True.
        kill_on_exit (bool, optional): Whether to kill the debugged process when the debugger exits. Defaults to True.
        follow_children (bool, optional): Whether to create a debugger for each child process. Defaults to True.
        stop_on_fork (bool, optional): Whether to stop on fork. Defaults to False.
        stop_on_exec (bool, optional): Whether to stop on exec. Defaults to False.
        stop_on_clone (bool, optional): Whether to stop on clone. Defaults to False.
        preserve_event_hooks_on_exec (bool, optional): Keep event hooks across exec. If False, remove existing
            user hooks after the current exec callbacks finish. Defaults to True.
        cls (type[Debugger], optional): Debugger subclass; container options require DockerDebuggerMixin.
        container (str, optional): Named running container in which to spawn and trace the target. In this mode, path
            is interpreted inside the container. Defaults to None.
        runtime (str, optional): Force a container runtime executable. Defaults to None (auto-detect docker or podman).
        container_cache_path (str, optional): Directory used to cache files copied out of the container. Defaults to
            the platform cache directory.

    Returns:
        Debugger: The `Debugger` object.
    """
    _validate_container_options(cls, container, runtime, container_cache_path, aslr)

    argv = _normalize_argv(argv)
    if env is not None:
        if not isinstance(env, dict):
            raise TypeError("env must be a dictionary or None")
        env = EnvDict(env)

    has_path_different_from_argv0 = path is not None
    target_path = path if path is not None else (argv[0] if argv else None)
    if issubclass(cls, DockerDebuggerMixin):
        if container is None:
            raise ValueError("Container debugging requires a container")
        if not target_path:
            raise ValueError("Container debugging requires path= or argv[0]")
        if argv and argv[0] != target_path:
            raise ValueError("Custom argv[0] is not supported in container mode")
        resolved_runtime, init_pid, cache, path = cls._prepare_container(
            container,
            runtime,
            container_cache_path,
            target_path,
        )
        internal_debugger = DockerInternalDebugger(resolved_runtime, init_pid, target_path, cache)
    else:
        path = resolve_argv_path(target_path) if target_path else None
        internal_debugger = InternalDebugger()

    if not issubclass(cls, Debugger):
        raise TypeError("cls must be a Debugger subclass")

    internal_debugger.argv = argv
    internal_debugger.path = path
    internal_debugger.env = env
    internal_debugger.aslr_enabled = True if aslr is None else aslr
    internal_debugger.autoreach_entrypoint = continue_to_binary_entrypoint
    internal_debugger.auto_interrupt_on_command = auto_interrupt_on_command
    internal_debugger.escape_antidebug = escape_antidebug
    internal_debugger.fast_memory = fast_memory
    internal_debugger.kill_on_exit = kill_on_exit
    internal_debugger.follow_children = follow_children
    internal_debugger._has_path_different_from_argv0 = has_path_different_from_argv0
    debugger_instance = cls(internal_debugger)
    debugger_instance.stop_on_fork = stop_on_fork
    debugger_instance.stop_on_exec = stop_on_exec
    debugger_instance.stop_on_clone = stop_on_clone
    debugger_instance.preserve_event_hooks_on_exec = preserve_event_hooks_on_exec

    internal_debugger.debugger = debugger_instance

    # If we are attaching, we assume the architecture is the same as the current platform
    if argv or container is not None:
        try:
            debugger_instance.arch = elf_architecture(path)
        except (ValueError, ELFError) as e:
            liblog.error(
                f"Failed to get the architecture of the binary: {e} "
                "Assuming the architecture is the same as the current platform.",
            )
            debugger_instance.arch = libcontext.platform

    return debugger_instance


# At import time, we register a signal handler for exceptions
setup_signal_handler()
