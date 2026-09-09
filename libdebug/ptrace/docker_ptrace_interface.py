#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from threading import Thread
from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.ptrace.ptrace_constants import StopEvents
from libdebug.ptrace.ptrace_interface import PtraceInterface
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
from libdebug.utils.container import ContainerError, kill_in_container, spawn_in_container
from libdebug.utils.process_utils import invalidate_process_cache

if TYPE_CHECKING:
    from libdebug.debugger.docker_internal_debugger import DockerInternalDebugger


class DockerPtraceInterface(PtraceInterface):
    """Ptrace interface for targets started inside a container."""

    _internal_debugger: DockerInternalDebugger

    def __init__(self: DockerPtraceInterface, internal_debugger: DockerInternalDebugger) -> None:
        """Initialize the container ptrace interface."""
        super().__init__(internal_debugger)
        self._container_popen: subprocess.Popen | None = None
        self._container_ns_pid = 0

    def run(self: DockerPtraceInterface, redirect_pipes: bool) -> None:
        """Start a stopped target in the container and attach to its host PID."""
        if not redirect_pipes:
            raise NotImplementedError("redirect_pipes=False is not supported for container targets")
        internal_debugger = self._internal_debugger
        liblog.debugger("Running %s inside container %s", internal_debugger.argv, internal_debugger.container)

        self.process_id = self._container_ns_pid = 0
        self.stdin_read = self.stdin_write = -1
        self.stdout_read = self.stdout_write = -1
        self.stderr_read = self.stderr_write = -1

        try:
            self.stdin_read, self.stdin_write = os.pipe()
            self.stdout_read, self.stdout_write = os.pipe()
            self.stderr_read, self.stderr_write = os.pipe()

            os.set_blocking(self.stdout_read, False)
            os.set_blocking(self.stderr_read, False)

            self.status_handler = PtraceStatusHandler(internal_debugger)
            env_dict = dict(internal_debugger.env) if internal_debugger.env is not None else None

            host_pid, ns_pid, popen = spawn_in_container(
                runtime=internal_debugger.runtime,
                container=internal_debugger.container,
                container_path=internal_debugger.container_path,
                argv=list(internal_debugger.argv),
                env=env_dict,
                init_pid=internal_debugger.container_init_pid,
                stdin_child_fd=self.stdin_read,
                stdout_child_fd=self.stdout_write,
                stderr_child_fd=self.stderr_write,
                pid_read_fd=self.stdout_read,
            )
            self._container_popen = popen
            self._container_ns_pid = ns_pid

            try:
                self._attach_to_all_tasks(host_pid)
            except PermissionError as e:
                raise PermissionError(
                    e.errno,
                    e.strerror,
                    "PTRACE_ATTACH was rejected. The host debugger needs permission to trace the target UID. "
                    "Check user IDs, tracer capabilities, Yama, and the container security profile. "
                    "Container capabilities do not grant privileges to the host debugger.",
                ) from e

            self.process_id = host_pid
            self.detached = False
            internal_debugger.process_id = host_pid
            internal_debugger.resume_context.is_startup = True

            self.wait()
            self._set_options()
            os.kill(host_pid, signal.SIGCONT)
            self._wait_for_exec()

            internal_debugger.resume_context.is_startup = False
            if internal_debugger.autoreach_entrypoint:
                self._continue_to_entry_point()
            invalidate_process_cache()

            internal_debugger.pipe_manager = self._setup_pipe()
        except BaseException:
            if self.process_id:
                with contextlib.suppress(OSError, RuntimeError):
                    super().kill()

            if self._container_ns_pid > 0:
                kill_in_container(
                    internal_debugger.runtime,
                    internal_debugger.container,
                    self._container_ns_pid,
                )
            self._reap_container_popen()
            internal_debugger.is_debugging = False
            internal_debugger.instanced = False
            internal_debugger.resume_context.is_startup = False
            internal_debugger.process_id = self.process_id = 0
            self._close_startup_pipes()
            raise

    def _close_startup_pipes(self: DockerPtraceInterface) -> None:
        for fd in (
            self.stdin_read,
            self.stdin_write,
            self.stdout_read,
            self.stdout_write,
            self.stderr_read,
            self.stderr_write,
        ):
            if fd != -1:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def _wait_for_exec(self: DockerPtraceInterface) -> None:
        """Advance the stopped shell until exec installs the target address space."""
        while True:
            self.lib_trace.cont_all_and_set_bps(False)
            statuses = self.lib_trace.wait_all_and_update_regs(False)
            invalidate_process_cache()
            for pid, status, _extra_info in statuses:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    raise ContainerError("Container wrapper exited before executing the target")
                if not os.WIFSTOPPED(status):
                    continue
                event = status >> 8
                if event == StopEvents.EXEC_EVENT:
                    return
                if event == StopEvents.EXIT_EVENT:
                    raise ContainerError("Container wrapper could not execute the target")
                signum = os.WSTOPSIG(status)
                if signum not in (signal.SIGSTOP, signal.SIGCONT):
                    self.lib_trace.forward_signals([(pid, signum)])

    def wait(self: DockerPtraceInterface) -> None:
        """Handle tracee events and reap the runtime client after normal exit."""
        super().wait()
        if self._internal_debugger.threads and all(thread.dead for thread in self._internal_debugger.threads):
            self._reap_container_popen()

    def detach(self: DockerPtraceInterface) -> None:
        """Detach without waiting for or killing the still-running target."""
        super().detach()
        if self._container_popen is not None:
            Thread(target=self._container_popen.wait, name="libdebug_container_reaper", daemon=True).start()
            self._container_popen = None
        self._container_ns_pid = 0

    def kill(self: DockerPtraceInterface) -> None:
        """Instantly terminate the process and reap the container-runtime client."""
        try:
            super().kill()
        except (RuntimeError, OSError) as e:
            if self._container_ns_pid <= 0:
                raise
            liblog.debugger("Killing the tracee through ptrace failed; falling back to the runtime: %r", e)
            kill_in_container(
                self._internal_debugger.runtime,
                self._internal_debugger.container,
                self._container_ns_pid,
            )
        finally:
            self._reap_container_popen()

    def _reap_container_popen(self: DockerPtraceInterface) -> None:
        """Reap the local container-runtime client process."""
        self._container_ns_pid = 0
        if self._container_popen is None:
            return
        try:
            self._container_popen.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._container_popen.kill()
            self._container_popen.wait()
        self._container_popen = None
