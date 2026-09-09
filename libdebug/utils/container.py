#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import hashlib
import os
import re
import select
import shlex
import shutil
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

from libdebug.liblog import liblog

_PID_RECORD_SIZE = 16
_WRAPPER_SCRIPT = f'printf "%0{_PID_RECORD_SIZE}d" "$$"; kill -STOP "$$"; exec "$@"'
_NSPID_RE = re.compile(rb"^NSpid:\s*(.*)$", re.MULTILINE)
_DEFAULT_CACHE_PATH = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "libdebug" / "containers"


class ContainerError(RuntimeError):
    """Raised when libdebug cannot interact with the container runtime."""


class ContainerStartupCancelledError(ContainerError):
    """Raised internally when the caller cancels the PID handshake."""


def detect_runtime(container: str, preferred: str | None) -> str:
    """Find a runtime that knows about the requested container."""
    runtimes = (
        (preferred,)
        if preferred is not None
        else tuple(runtime for runtime in ("docker", "podman") if shutil.which(runtime) is not None)
    )
    if preferred is not None and shutil.which(preferred) is None:
        raise ContainerError(f"Container runtime {preferred!r} is not on PATH.")
    if not runtimes:
        raise ContainerError("Neither docker nor podman was found on PATH.")

    attempted_commands = []
    for runtime in runtimes:
        command = [runtime, "inspect", container]
        attempted_commands.append(shlex.join(command))
        liblog.debugger("Running container command: %s", attempted_commands[-1])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return runtime

    raise ContainerError(
        f"Container {container!r} was not found. Attempted: {', '.join(attempted_commands)}.",
    )


def get_container_init_pid(runtime: str, container: str) -> int:
    """Return the host-visible PID of the container's init process."""
    command = [runtime, "inspect", "-f", "{{.State.Pid}}", container]
    liblog.debugger("Running container command: %s", shlex.join(command))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ContainerError(
            f"Command {shlex.join(command)!r} failed: {result.stderr.strip() or 'unknown error'}",
        )

    try:
        init_pid = int(result.stdout.strip())
    except ValueError as e:
        raise ContainerError(f"Unexpected output from {shlex.join(command)!r}: {result.stdout.strip()!r}") from e

    if init_pid <= 0:
        raise ContainerError(f"Container {container!r} is not running.")
    return init_pid


class ContainerFileCache:
    """Persistent cache of host-readable copies of files from one container."""

    def __init__(
        self: ContainerFileCache,
        runtime: str,
        container: str,
        cache_path: str | Path | None = None,
    ) -> None:
        """Create a cache for one runtime/container pair."""
        self.runtime = runtime
        self.container = container
        command = [runtime, "inspect", "-f", "{{.Id}}", container]
        liblog.debugger("Running container command: %s", shlex.join(command))
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            raise ContainerError(f"Command {shlex.join(command)!r} failed: {result.stderr.strip()}")
        self.container_id = result.stdout.strip()
        self.cache_path = Path(cache_path).expanduser() if cache_path is not None else _DEFAULT_CACHE_PATH
        self.cache_path.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, str] = {}

    def copy_file(self: ContainerFileCache, container_path: str) -> str | None:
        """Return an optional mapped file, logging runtime copy failures."""
        if not container_path.startswith("/") or container_path.startswith("/proc/"):
            return None
        try:
            return self.copy_required_file(container_path)
        except ContainerError as error:
            liblog.debugger("%s", error)
            return None

    def copy_required_file(self: ContainerFileCache, container_path: str) -> str:
        """Return a persistent copy; files changed in place require clearing the cache."""
        if not container_path.startswith("/") or container_path.startswith("/proc/"):
            raise ContainerError(f"Container path must be an absolute file path: {container_path!r}")
        if container_path in self._entries:
            return self._entries[container_path]

        digest = hashlib.sha256(f"{self.runtime}\0{self.container_id}\0{container_path}".encode()).hexdigest()
        destination = self.cache_path / f"{digest}-{Path(container_path).name}"
        if destination.is_file():
            self._entries[container_path] = str(destination)
            return str(destination)

        with NamedTemporaryFile(dir=self.cache_path, prefix=".libdebug-copy-", delete=False) as temporary_file:
            temporary_path = Path(temporary_file.name)
        command = [self.runtime, "cp", "-L", f"{self.container_id}:{container_path}", str(temporary_path)]
        liblog.debugger("Running container command: %s", shlex.join(command))
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0 or not temporary_path.is_file():
                raise ContainerError(f"Command {shlex.join(command)!r} failed: {result.stderr.strip()}")
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)
        self._entries[container_path] = str(destination)
        return str(destination)


def _read_proc_file(pid: int, name: str) -> bytes | None:
    """Read one per-process procfs file if it is accessible."""
    try:
        return Path(f"/proc/{pid}/{name}").read_bytes()
    except OSError:
        return None


def _cgroup_v2_path(cgroup_content: bytes) -> str | None:
    """Extract the unified hierarchy path from cgroup v2 data."""
    for line in cgroup_content.splitlines():
        if line.startswith(b"0::"):
            path = line[3:].decode(errors="replace")
            return path if path.startswith("/") else None
    return None


def _candidates_from_cgroup(expected_cgroup: bytes) -> list[int] | None:
    """Read the host PIDs in a cgroup v2 hierarchy when available."""
    cgroup_path = _cgroup_v2_path(expected_cgroup)
    if cgroup_path is None:
        liblog.debugger("No cgroup v2 path found; scanning procfs for the container PID.")
        return None

    procs_file = Path(f"/sys/fs/cgroup{cgroup_path}/cgroup.procs")
    try:
        content = procs_file.read_bytes()
        return [int(line) for line in content.split()]
    except (OSError, ValueError):
        liblog.debugger("Could not read container PIDs from %s; scanning procfs.", procs_file)
        return None


def resolve_ns_pid_to_host_pid(init_pid: int, ns_pid: int) -> int:
    """Resolve an in-container PID by matching NSpid and cgroup data in procfs."""
    expected_cgroup = _read_proc_file(init_pid, "cgroup")
    if expected_cgroup is None:
        raise ContainerError(f"Container init pid {init_pid} is not accessible; did the container exit?")

    fast_candidates = _candidates_from_cgroup(expected_cgroup)
    if fast_candidates is None:
        candidates = (int(entry) for entry in os.listdir("/proc") if entry.isdigit())
        verify_cgroup = True
    else:
        candidates = iter(fast_candidates)
        verify_cgroup = False

    for host_pid in candidates:
        status = _read_proc_file(host_pid, "status")
        match = _NSPID_RE.search(status) if status is not None else None
        if match is None:
            continue
        columns = match.group(1).split()
        try:
            matches_pid = bool(columns) and int(columns[-1]) == ns_pid
        except ValueError:
            continue
        if not matches_pid or (verify_cgroup and _read_proc_file(host_pid, "cgroup") != expected_cgroup):
            continue
        return host_pid

    raise ContainerError(f"Could not resolve in-container PID {ns_pid} below container init {init_pid}.")


def _build_target_argv(container_path: str, user_argv: list[str]) -> list[str]:
    """Build the arguments passed from the wrapper to the target."""
    return [container_path, *user_argv[1:]] if len(user_argv) > 1 else [container_path]


def spawn_in_container(
    runtime: str,
    container: str,
    container_path: str,
    argv: list[str],
    env: dict[str, str] | None,
    stdin_child_fd: int | None,
    stdout_child_fd: int | None,
    stderr_child_fd: int | None,
) -> subprocess.Popen:
    """Start the runtime client; the caller owns it before reading the PID handshake."""
    command: list[str] = [runtime, "exec", "-i", container]
    if env is None:
        command += ["/bin/sh", "-c", _WRAPPER_SCRIPT, "--"]
    else:
        command += [
            "env",
            "-i",
            "/bin/sh",
            "-c",
            _WRAPPER_SCRIPT,
            "--",
            "/usr/bin/env",
            "-i",
            *[f"{key}={value}" for key, value in env.items()],
        ]
    command += _build_target_argv(container_path, argv)

    liblog.debugger("Running container command: %s", shlex.join(command))
    return subprocess.Popen(
        command,
        stdin=stdin_child_fd,
        stdout=stdout_child_fd,
        stderr=stderr_child_fd,
        close_fds=True,
    )


def read_container_pid(read_fd: int, cancel_fd: int) -> int:
    """Wait for a complete PID record, EOF, or an explicit cancellation wakeup."""
    record = bytearray()
    while len(record) < _PID_RECORD_SIZE:
        readable, _, _ = select.select([read_fd, cancel_fd], [], [])
        # Consume available PID bytes first so cancellation can clean up a reported target.
        if read_fd not in readable:
            raise ContainerStartupCancelledError("Container startup cancelled")
        chunk = os.read(read_fd, _PID_RECORD_SIZE - len(record))
        if not chunk:
            raise ContainerError(f"Container exec closed stdout before reporting its PID: {bytes(record)!r}")
        record.extend(chunk)
    if not record.isdigit() or int(record) <= 0:
        raise ContainerError(f"Container exec produced an invalid PID record {bytes(record)!r}")
    return int(record)


def kill_in_container(runtime: str, container: str, ns_pid: int) -> None:
    """Best-effort fallback that kills a process through the container runtime."""
    if ns_pid <= 0:
        raise ValueError("Container PID must be positive")
    command = [runtime, "exec", container, "kill", "-KILL", str(ns_pid)]
    liblog.debugger("Running container command: %s", shlex.join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as e:
        liblog.debugger("Container kill command could not be started: %s", e)
        return
    if result.returncode != 0:
        liblog.debugger(
            "Container kill command failed with status %d: %s",
            result.returncode,
            result.stderr.strip() or "unknown error",
        )
