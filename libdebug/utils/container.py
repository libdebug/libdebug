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


# Cache of (runtime, container, container_path) → host_tempfile (or None on cached failure),
# populated lazily by `cache_container_path`. Each successful entry is also tracked in
# _TEMPFILES so the atexit sweep removes the on-disk file at interpreter exit. We never
# invalidate — within a single libdebug session we assume container filesystems are stable.
_PATH_CACHE: dict[tuple[str, str, str], str | None] = {}


def cache_container_path(runtime: str, container: str, container_path: str) -> str | None:
    """Return a host-readable copy of an in-container file, ``docker cp``ing it on first access.

    Memoized per (runtime, container, container_path) to avoid repeated copies. Returns None
    when the path cannot be copied — e.g. anonymous mappings like ``[heap]``/``[stack]`` and
    libdebug's own ``anon_<addr>`` placeholders, both of which have no on-disk backing — so
    callers can simply skip those entries. Failed copies are also cached as None so we don't
    retry on every symbol lookup.
    """
    if not container_path or not container_path.startswith("/"):
        return None
    if container_path.startswith("[") or container_path.startswith("/proc/"):
        return None

    key = (runtime, container, container_path)
    if key in _PATH_CACHE:
        return _PATH_CACHE[key]

    fd, host_path = tempfile.mkstemp(prefix="libdebug-container-", suffix="-" + Path(container_path).name)
    os.close(fd)
    _register_tempfile(host_path)

    result = subprocess.run(
        [runtime, "cp", f"{container}:{container_path}", host_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not Path(host_path).is_file():
        # The mapped path may not exist (e.g. unlinked-while-mapped) or may be unreadable.
        # Discard the empty tempfile and remember the failure so we don't retry on every lookup.
        discard_tempfile(host_path)
        _PATH_CACHE[key] = None
        return None

    _PATH_CACHE[key] = host_path
    return host_path


def host_path_for_backing_file(
    runtime: str | None,
    container: str | None,
    backing_file: str,
) -> str:
    """Return the path to open for ELF/symbol parsing of a memory map's backing file.

    In host mode (``container is None``) this is identity. In container mode it returns the
    cached docker-cp'd copy on the host. Falls back to the original path when we cannot copy
    (anon mappings, unreadable paths) so callers see no behavior change for those entries.
    """
    if container is None or runtime is None:
        return backing_file
    cached = cache_container_path(runtime, container, backing_file)
    return cached if cached else backing_file


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


def _cgroup_v2_path(cgroup_content: bytes) -> str | None:
    """Extract the cgroup v2 unified-hierarchy path from /proc/<pid>/cgroup content.

    cgroup v2 format is one line: ``0::<path>``. Returns None for cgroup v1 (multiple lines
    with ``numeric:controller:path``) so callers can fall back to the full /proc scan.
    """
    for line in cgroup_content.split(b"\n"):
        line = line.strip()
        if line.startswith(b"0::"):
            path = line[3:].decode(errors="replace")
            return path if path.startswith("/") else None
    return None


def _candidates_from_cgroup(expected_cgroup: bytes) -> list[int] | None:
    """Return host PIDs in the container's cgroup, or None if the fast path is unavailable.

    Reads ``/sys/fs/cgroup<path>/cgroup.procs`` where ``<path>`` comes from the cgroup v2 line
    in /proc/<init>/cgroup. This is O(processes-in-container) — typically 1-50 entries —
    instead of O(all-host-processes). Returns None for cgroup v1, missing cgroup fs,
    restricted permissions, or any parse failure, so the caller can transparently fall back
    to the full /proc walk.
    """
    cgroup_path = _cgroup_v2_path(expected_cgroup)
    if cgroup_path is None:
        return None

    procs_file = Path(f"/sys/fs/cgroup{cgroup_path}/cgroup.procs")
    try:
        with procs_file.open("rb") as f:
            content = f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return None

    try:
        return [int(line) for line in content.split() if line]
    except ValueError:
        return None


def resolve_ns_pid_to_host_pid(init_pid: int, ns_pid: int, timeout: float = _NS_PID_RESOLVE_TIMEOUT) -> int:
    """Locate the host-visible PID of a process whose innermost-namespace PID is ``ns_pid``.

    Inspects /proc/<pid>/status for processes whose ``NSpid:`` row last column matches
    ``ns_pid``, verifying via /proc/<pid>/cgroup that the candidate really belongs to the
    target container (different containers can share an in-NS PID; the cgroup uniquely
    identifies a container). We cannot use the ns/pid symlink for disambiguation because
    reading it requires CAP_SYS_PTRACE on the target; cgroup is world-readable and equally
    unique.

    Fast path: on cgroup v2 hosts (the modern default) we read the container's
    ``cgroup.procs`` directly — that's the exact set of in-container PIDs, no scan needed —
    and skip the per-candidate cgroup verification since membership is already guaranteed.
    Fallback path: full /proc walk with per-candidate cgroup verification, used for cgroup v1
    or restricted setups.

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
        fast_candidates = _candidates_from_cgroup(expected_cgroup)
        if fast_candidates is not None:
            # cgroup.procs guarantees membership; skip per-candidate cgroup re-read.
            candidates: object = fast_candidates
            verify_cgroup = False
        else:
            candidates = (int(e) for e in os.listdir("/proc") if e.isdigit())
            verify_cgroup = True

        for host_pid in candidates:
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
            # Deferred verification: only read /proc/<host>/cgroup after NSpid matches, and
            # only on the fallback path where membership isn't already guaranteed.
            if verify_cgroup and _read_cgroup(host_pid) != expected_cgroup:
                continue
            return host_pid

        if time.monotonic() >= deadline:
            raise ContainerError(
                f"Timed out waiting for host PID matching in-container PID {ns_pid} (container init {init_pid}).",
            )
        time.sleep(_NS_PID_RESOLVE_INTERVAL)


def _build_target_argv(container_path: str, user_argv: list[str]) -> list[str]:
    """Build the positional args the wrapper passes to `exec`.

    POSIX `sh` has no portable way to override argv[0], so the target receives argv[0] ==
    container_path. The factory enforces argv[0] == container_path (or argv empty) before we
    get here, so the drop is purely cosmetic — argv[1:] is what carries actual user args.
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
