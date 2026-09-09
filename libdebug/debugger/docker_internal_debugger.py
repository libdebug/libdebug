#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger import InternalDebugger
from libdebug.ptrace.docker_ptrace_interface import DockerPtraceInterface
from libdebug.utils.arch_mappings import map_arch
from libdebug.utils.container import get_container_init_pid
from libdebug.utils.elf_utils import elf_architecture

if TYPE_CHECKING:
    from libdebug.commlink.pipe_manager import PipeManager
    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.utils.container import ContainerFileCache


class DockerInternalDebugger(InternalDebugger):
    """Internal debugger state for a target running inside a container."""

    container: str
    """The immutable ID of the container in which the debuggee runs."""

    runtime: str
    """The container runtime executable."""

    container_init_pid: int
    """The host-visible PID of the container's init process."""

    container_path: str
    """The path to the debuggee binary inside the container."""

    container_file_cache: ContainerFileCache
    """The cache containing host-readable copies of in-container files."""

    def __init__(
        self: DockerInternalDebugger,
        runtime: str,
        container_init_pid: int,
        container_path: str,
        container_file_cache: ContainerFileCache,
    ) -> None:
        """Initialize container-specific debugger state."""
        super().__init__()
        self.container = container_file_cache.container_id
        self.runtime = runtime
        self.container_init_pid = container_init_pid
        self.container_path = container_path
        self.container_file_cache = container_file_cache

    def run(
        self: DockerInternalDebugger,
        timeout: float = -1,
        redirect_pipes: bool = True,
    ) -> PipeManager | None:
        """Validate container I/O before changing the debugger's running state."""
        if not redirect_pipes:
            raise NotImplementedError("redirect_pipes=False is not supported for container targets")
        self.container_init_pid = get_container_init_pid(self.runtime, self.container)
        return super().run(timeout, redirect_pipes)

    def _provide_debugging_interface(self: DockerInternalDebugger) -> DebuggingInterface:
        """Create the container-specific ptrace interface."""
        return DockerPtraceInterface(self)

    def _ensure_file_executable(self: DockerInternalDebugger) -> None:
        """Validate argv against the executable used by the container wrapper."""
        if self.argv and self.argv[0] != self.container_path:
            raise ValueError("Custom argv[0] is not supported in container mode")

    def _get_target_path(self: DockerInternalDebugger) -> str:
        return self.container_path

    def _set_target_path(self: DockerInternalDebugger, path: str) -> None:
        host_path = self.container_file_cache.copy_required_file(path)
        architecture = elf_architecture(host_path)
        self.clear_all_caches()
        self.container_path = path
        self.path = host_path
        self.arch = map_arch(architecture)

    def _host_path_from_target_path(self: DockerInternalDebugger, path: str) -> str | None:
        """Return the cached host copy of an in-container path."""
        return self.container_file_cache.copy_file(path)

    def _new_child_internal_debugger(self: DockerInternalDebugger) -> DockerInternalDebugger:
        """Create container-aware state for a followed child process."""
        return DockerInternalDebugger(
            self.runtime,
            self.container_init_pid,
            self.container_path,
            self.container_file_cache,
        )
