#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import atexit
import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

SUPPORTED_RUNTIMES: tuple[str, ...] = ("docker", "podman")

# `printf` is a builtin in sh/dash/bash/busybox and writes via write(2) without
# stdio buffering, so the PID line is guaranteed to reach our parent process
# before the wrapper's `kill -STOP $$`. Using `printf` instead of `echo` also
# dodges shells that re-implement `echo` with non-standard options.
_WRAPPER_SCRIPT = 'printf "%d\\n" "$$"; kill -STOP "$$"; exec "$@"'

# Time budget for the wrapper to write its PID and for the kernel to populate
# /proc/<host_pid>/status with the matching NSpid row.
_NS_PID_RESOLVE_TIMEOUT = 5.0
_NS_PID_RESOLVE_INTERVAL = 0.01

_NSPID_RE = re.compile(rb"^NSpid:\s*(.*)$", re.MULTILINE)


class ContainerError(RuntimeError):
    """Raised when libdebug cannot interact with the container runtime."""


def detect_runtime(container: str, preferred: str | None) -> str:
    """Return the container runtime CLI name ("docker" or "podman") that knows the named container.

    Args:
        container: Name or ID of the container to debug.
        preferred: If set, the runtime to use without probing the alternatives. Must be one of SUPPORTED_RUNTIMES.

    Returns:
        The resolved runtime CLI name.

    Raises:
        ContainerError: When ``preferred`` is unsupported, when no runtime CLI is on PATH, or when the container is
            not found by any supported runtime.
    """
    if preferred is not None:
        if preferred not in SUPPORTED_RUNTIMES:
            raise ContainerError(
                f"Unsupported runtime '{preferred}'. Supported runtimes: {', '.join(SUPPORTED_RUNTIMES)}.",
            )
        if shutil.which(preferred) is None:
            raise ContainerError(f"Runtime '{preferred}' is not on PATH.")
        if not _container_exists(preferred, container):
            raise ContainerError(f"Container '{container}' not found via '{preferred}'.")
        return preferred

    available = [r for r in SUPPORTED_RUNTIMES if shutil.which(r) is not None]
    if not available:
        raise ContainerError(
            f"No supported container runtime found on PATH (looked for: {', '.join(SUPPORTED_RUNTIMES)}).",
        )

    for runtime in available:
        if _container_exists(runtime, container):
            return runtime

    raise ContainerError(
        f"Container '{container}' not found via {', '.join(available)}. "
        "Is it running and is the name correct?",
    )


def _container_exists(runtime: str, container: str) -> bool:
    """Return True if `<runtime> inspect <container>` succeeds, False otherwise."""
    result = subprocess.run(
        [runtime, "inspect", container],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def get_container_init_pid(runtime: str, container: str) -> int:
    """Return the host-visible PID of PID 1 inside the named container.

    Args:
        runtime: Resolved runtime CLI name ("docker" or "podman").
        container: Container name or ID.

    Raises:
        ContainerError: When the container is not running or the runtime CLI fails.
    """
    result = subprocess.run(
        [runtime, "inspect", "-f", "{{.State.Pid}}", container],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ContainerError(
            f"`{runtime} inspect` failed for container '{container}': {result.stderr.strip() or 'unknown error'}",
        )

    raw = result.stdout.strip()
    try:
        init_pid = int(raw)
    except ValueError as e:
        raise ContainerError(f"Unexpected output from `{runtime} inspect`: {raw!r}") from e

    if init_pid <= 0:
        raise ContainerError(
            f"Container '{container}' is not running (init pid is {init_pid}). Start it first.",
        )
    return init_pid


# Tempfiles created by `extract_container_binary`. A single atexit handler sweeps the set so
# the registration cost is constant regardless of how many debugger() calls happen in a session.
_TEMPFILES: set[str] = set()
_ATEXIT_REGISTERED = False


def _register_tempfile(path: str) -> None:
    global _ATEXIT_REGISTERED  # noqa: PLW0603
    _TEMPFILES.add(path)
    if not _ATEXIT_REGISTERED:
        atexit.register(_sweep_tempfiles)
        _ATEXIT_REGISTERED = True


def _sweep_tempfiles() -> None:
    for path in list(_TEMPFILES):
        discard_tempfile(path)


def discard_tempfile(path: str) -> None:
    """Drop a tempfile created by extract_container_binary, removing it both from disk and from
    the atexit sweep list. Idempotent.
    """
    _TEMPFILES.discard(path)
    with contextlib.suppress(FileNotFoundError, PermissionError, OSError):
        Path(path).unlink()


def extract_container_binary(runtime: str, container: str, container_path: str) -> str:
    """Copy a binary out of the container to a host temp file so libdebug can parse its ELF.

    The procfs trick `/proc/<init>/root/<path>` does not work for non-root debuggers (procfs
    enforces same-uid-or-CAP_SYS_PTRACE on root traversal), so we shell out to ``<runtime> cp``.
    Symlinks inside the container are resolved by the runtime, so this works for distros where
    `/bin` is a symlink to `/usr/bin`. The temp file is registered for deletion at interpreter
    exit; only the ELF header is needed by libdebug, so the cost is bounded by the binary size.

    Args:
        runtime: Resolved runtime CLI name.
        container: Container name or ID.
        container_path: Absolute path inside the container.

    Returns:
        Absolute path to a host-readable copy of the binary.

    Raises:
        ContainerError: When the path is not absolute, or when ``<runtime> cp`` fails.
    """
    if not container_path.startswith("/"):
        raise ContainerError(
            f"Container path must be absolute (got '{container_path}'). The path is resolved inside the container, "
            "not against the host CWD.",
        )

    fd, host_path = tempfile.mkstemp(prefix="libdebug-container-", suffix=Path(container_path).name)
    os.close(fd)
    _register_tempfile(host_path)

    result = subprocess.run(
        [runtime, "cp", f"{container}:{container_path}", host_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        discard_tempfile(host_path)
        raise ContainerError(
            f"`{runtime} cp {container}:{container_path}` failed: {result.stderr.strip() or 'unknown error'}",
        )

    if not Path(host_path).is_file():
        discard_tempfile(host_path)
        raise ContainerError(
            f"`{runtime} cp` produced no regular file at '{host_path}' for container path '{container_path}'.",
        )
    return host_path


def _read_status(pid: int) -> bytes | None:
    """Best-effort read of /proc/<pid>/status. Returns None if the process is gone."""
    try:
        with Path(f"/proc/{pid}/status").open("rb") as f:
            return f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def _read_cgroup(pid: int) -> bytes | None:
    """Best-effort read of /proc/<pid>/cgroup. Returns None if the process is gone."""
    try:
        with Path(f"/proc/{pid}/cgroup").open("rb") as f:
            return f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def resolve_ns_pid_to_host_pid(init_pid: int, ns_pid: int, timeout: float = _NS_PID_RESOLVE_TIMEOUT) -> int:
    """Locate the host-visible PID of a process whose innermost-namespace PID is ``ns_pid``.

    Walks /proc/<pid>/status looking for a process whose ``NSpid:`` row last column matches
    ``ns_pid`` AND whose /proc/<pid>/cgroup is identical to the container init's cgroup. The
    cgroup check disambiguates between unrelated containers that share a numeric NS pid: every
    process inside a given container shares its cgroup path (e.g. ``docker-<id>.scope``).
    We cannot use the ns/pid symlink for disambiguation because reading it requires
    CAP_SYS_PTRACE on the target process; cgroup is world-readable and equally unique.

    Args:
        init_pid: Host-visible PID of the container init.
        ns_pid: PID as observed inside the container.
        timeout: Seconds to wait for the host-side procfs entry to appear.

    Raises:
        ContainerError: When no matching host PID is found within ``timeout``.
    """
    expected_cgroup = _read_cgroup(init_pid)
    if expected_cgroup is None:
        raise ContainerError(f"Container init pid {init_pid} is not accessible — did the container exit?")

    deadline = time.monotonic() + timeout
    while True:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            host_pid = int(entry)
            status = _read_status(host_pid)
            if status is None:
                continue
            match = _NSPID_RE.search(status)
            if match is None:
                continue
            columns = match.group(1).split()
            if not columns:
                continue
            # Innermost-namespace pid is the last column; host pid is the first.
            if int(columns[-1]) != ns_pid:
                continue
            if _read_cgroup(host_pid) != expected_cgroup:
                continue
            return host_pid

        if time.monotonic() >= deadline:
            raise ContainerError(
                f"Timed out waiting for host PID matching in-container PID {ns_pid} (container init {init_pid}).",
            )
        time.sleep(_NS_PID_RESOLVE_INTERVAL)


def _build_target_argv(container_path: str, user_argv: list[str]) -> list[str]:
    """Build the positional args the wrapper passes to `exec`.

    POSIX `sh` has no portable way to override argv[0]; the target receives argv[0] == container_path.
    If the user supplied a custom argv[0] that differs from container_path, it is dropped — argv[1:]
    is preserved.
    """
    return [container_path, *user_argv[1:]] if len(user_argv) > 1 else [container_path]


def spawn_in_container(
    runtime: str,
    container: str,
    container_path: str,
    argv: list[str],
    env: dict[str, str] | None,
    init_pid: int,
    stdin_child_fd: int | None,
    stdout_child_fd: int | None,
    stderr_child_fd: int | None,
    pid_read_fd: int,
) -> tuple[int, int, subprocess.Popen]:
    """Spawn the target inside the container in a paused state and resolve its host PID.

    Issues ``<runtime> exec -i [--env K=V]... <container> sh -c '<wrapper>' -- <target>...``. The wrapper:
    prints its in-container PID on stdout, ``kill -STOP``s itself, then ``exec``s the target. We read
    the first stdout line to recover the in-container PID, then resolve it to a host-visible PID.
    The caller is responsible for ``PTRACE_ATTACH``ing on the returned host PID before resuming the
    wrapper.

    Args:
        runtime: Resolved runtime CLI name.
        container: Container name or ID.
        container_path: Absolute path of the target binary inside the container.
        argv: User-supplied argv list. argv[0] is dropped (see ``_build_target_argv``).
        env: Environment variables to pass via ``--env`` flags. None means no overrides.
        init_pid: Host-visible PID of container init (for NS pid resolution).
        stdin_child_fd: Read end of the stdin pipe, handed to the child as fd 0. None means inherit.
        stdout_child_fd: Write end of the stdout pipe, handed to the child as fd 1.
        stderr_child_fd: Write end of the stderr pipe, handed to the child as fd 2.
        pid_read_fd: Parent-side read end of the stdout pipe. Used to recover the wrapper's PID.

    Returns:
        Tuple of (host_pid, ns_pid, popen). The Popen is the docker-exec client process; caller must reap it.
    """
    cmd: list[str] = [runtime, "exec", "-i"]
    for key, value in (env or {}).items():
        cmd += ["--env", f"{key}={value}"]
    cmd.append(container)
    cmd += ["sh", "-c", _WRAPPER_SCRIPT, "--"]
    cmd += _build_target_argv(container_path, argv)

    popen = subprocess.Popen(
        cmd,
        stdin=stdin_child_fd,
        stdout=stdout_child_fd,
        stderr=stderr_child_fd,
        close_fds=True,
    )

    ns_pid = _read_pid_line(pid_read_fd, popen)
    host_pid = resolve_ns_pid_to_host_pid(init_pid, ns_pid)
    return host_pid, ns_pid, popen


def _read_pid_line(read_fd: int, popen: subprocess.Popen, timeout: float = 5.0) -> int:
    """Read the first newline-terminated line from ``read_fd`` and parse it as an integer.

    Reads byte-by-byte so the trailing newline is the last byte we consume — anything the target
    binary writes after exec stays in the pipe for PipeManager to deliver to the user. The
    wrapper's ``kill -STOP $$`` blocks before the target gets to run, but byte-at-a-time is the
    cheapest way to make the contract robust to future wrapper-script changes.
    """
    deadline = time.monotonic() + timeout
    buf = bytearray()
    while True:
        try:
            chunk = os.read(read_fd, 1)
        except BlockingIOError:
            chunk = b""

        if chunk:
            buf.extend(chunk)
            if buf.endswith(b"\n"):
                line = bytes(buf[:-1])
                try:
                    return int(line.decode().strip())
                except ValueError as e:
                    raise ContainerError(f"Wrapper produced unexpected PID line: {line!r}") from e

        if popen.poll() is not None:
            raise ContainerError(
                f"Container exec exited before reporting the wrapper PID (status {popen.returncode}). "
                "Check that /bin/sh exists in the container and that the target path is correct.",
            )

        if time.monotonic() >= deadline:
            raise ContainerError("Timed out waiting for the in-container wrapper to report its PID.")

        time.sleep(0.005)


def kill_in_container(runtime: str, container: str, ns_pid: int) -> None:
    """Last-resort cleanup: `<runtime> exec <container> kill -KILL <ns_pid>`.

    Failures are swallowed — this is best-effort cleanup used when PTRACE_KILL has already failed
    (typically because the container exited under us).
    """
    subprocess.run(
        [runtime, "exec", container, "kill", "-KILL", str(ns_pid)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
