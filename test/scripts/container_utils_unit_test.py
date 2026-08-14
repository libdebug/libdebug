#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import fcntl
import os
from unittest import TestCase
from unittest.mock import patch

from libdebug.utils.container import (
    ContainerError,
    SUPPORTED_RUNTIMES,
    _PATH_CACHE,
    _build_target_argv,
    _read_pid_line,
    cache_container_path,
    detect_runtime,
    extract_container_binary,
    host_path_for_backing_file,
    resolve_ns_pid_to_host_pid,
    spawn_in_container,
)
from utils.container_fixture_utils import SYMLINK_TARGET_BYTES, symlink_cp_container


def _make_pipe(nonblocking=True):
    """Return (r, w) with the read end set to non-blocking — mirrors `_run_in_container`."""
    r, w = os.pipe()
    if nonblocking:
        flags = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    return r, w


class _FakePopen:
    """Minimal Popen stand-in for _read_pid_line tests."""

    def __init__(self, returncode=None):
        self.returncode = returncode
        self.wait_called = False
        self.kill_called = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_called = True
        return self.returncode

    def kill(self):
        self.kill_called = True


def _effective_env_from_fake_exec_cmd(cmd):
    """Return the environment a fake container wrapper would observe."""
    container_env = {"PATH": "/usr/bin", "KEEP": "container-default"}

    if "env" not in cmd:
        return container_env

    env_index = cmd.index("env")
    if cmd[env_index + 1] != "-i":
        return container_env

    effective = {}
    for token in cmd[env_index + 2:]:
        if token == "/bin/sh":
            break
        key, value = token.split("=", 1)
        effective[key] = value
    return effective


class ContainerUtilsUnitTest(TestCase):
    def test_build_target_argv_empty(self):
        self.assertEqual(_build_target_argv("/bin/ls", []), ["/bin/ls"])

    def test_build_target_argv_one_arg(self):
        # argv[0] convention can't be preserved in POSIX sh — argv[0] gets replaced by path
        self.assertEqual(_build_target_argv("/bin/ls", ["ls"]), ["/bin/ls"])

    def test_build_target_argv_many(self):
        self.assertEqual(
            _build_target_argv("/bin/ls", ["ls", "-la", "/tmp"]),
            ["/bin/ls", "-la", "/tmp"],
        )

    def test_build_target_argv_drops_argv0_in_practice(self):
        """The factory enforces argv[0] == path before we get here, but the helper is permissive:
        if some future caller passes a mismatched argv[0], it still drops it cleanly so the
        wrapper command is well-formed."""
        self.assertEqual(
            _build_target_argv("/bin/foo", ["custom-name", "arg"]),
            ["/bin/foo", "arg"],
        )

    def test_debugger_factory_rejects_custom_argv0(self):
        """The factory must refuse `argv[0] != container_path` rather than silently drop it."""
        from libdebug import debugger
        with self.assertRaises(ValueError) as ctx:
            debugger(argv=["custom-name", "-x"], path="/bin/foo", container="nonexistent_for_argv_test")
        self.assertIn("argv[0]", str(ctx.exception))

    def test_detect_runtime_invalid_preferred(self):
        with self.assertRaises(ContainerError) as ctx:
            detect_runtime("any", "kubectl")
        self.assertIn("Unsupported runtime", str(ctx.exception))

    def test_supported_runtimes(self):
        self.assertEqual(SUPPORTED_RUNTIMES, ("docker", "podman"))

    def test_read_pid_line_simple(self):
        r, w = _make_pipe()
        try:
            os.write(w, b"42\n")
            popen = _FakePopen()
            self.assertEqual(_read_pid_line(r, popen, timeout=1.0), 42)
        finally:
            os.close(r)
            os.close(w)

    def test_read_pid_line_leaves_bytes_after_newline(self):
        """Bytes after the newline must remain in the pipe for PipeManager to drain."""
        r, w = _make_pipe()
        try:
            os.write(w, b"42\ntarget output\n")
            popen = _FakePopen()
            self.assertEqual(_read_pid_line(r, popen, timeout=1.0), 42)
            # The trailing bytes are still in the pipe
            remaining = os.read(r, 64)
            self.assertEqual(remaining, b"target output\n")
        finally:
            os.close(r)
            os.close(w)

    def test_read_pid_line_non_numeric(self):
        r, w = _make_pipe()
        try:
            os.write(w, b"not_a_pid\n")
            popen = _FakePopen()
            with self.assertRaises(ContainerError) as ctx:
                _read_pid_line(r, popen, timeout=1.0)
            self.assertIn("unexpected PID line", str(ctx.exception))
        finally:
            os.close(r)
            os.close(w)

    def test_read_pid_line_popen_exits_first(self):
        r, w = _make_pipe()
        try:
            os.close(w)  # eof on read side
            popen = _FakePopen(returncode=1)
            with self.assertRaises(ContainerError) as ctx:
                _read_pid_line(r, popen, timeout=1.0)
            self.assertIn("Container exec exited", str(ctx.exception))
        finally:
            os.close(r)

    def test_read_pid_line_timeout(self):
        r, w = _make_pipe()
        try:
            popen = _FakePopen()
            with self.assertRaises(ContainerError) as ctx:
                _read_pid_line(r, popen, timeout=0.1)
            self.assertIn("Timed out", str(ctx.exception))
        finally:
            os.close(r)
            os.close(w)

    def test_resolve_ns_pid_fallback_uses_last_column(self):
        """Fallback path (cgroup fast-path unavailable): last column of NSpid is the innermost
        (container) PID, and the per-candidate cgroup read disambiguates between unrelated
        containers that share a numeric NS pid.
        """
        listed = ["1234", "5678", "self", "nondigit"]
        cgroup_for_init = b"0::/system.slice/docker-deadbeef.scope\n"
        cgroup_other = b"0::/user.slice/user-1000.slice\n"
        # 1234 is our nested-namespace candidate: NSpid: 1234  9  42
        # 5678 has matching last column but a different cgroup → must be rejected
        status_for = {
            5678: b"Name:\tsleep\nNSpid:\t5678\t42\n",
            1234: b"Name:\tsh\nNSpid:\t1234\t9\t42\n",
        }
        cgroup_for = {
            999: cgroup_for_init,
            1234: cgroup_for_init,
            5678: cgroup_other,
        }

        # Force the fallback path by making _candidates_from_cgroup return None.
        with patch("libdebug.utils.container._candidates_from_cgroup", return_value=None), \
             patch("libdebug.utils.container.os.listdir", lambda _: listed), \
             patch("libdebug.utils.container._read_status", lambda pid: status_for.get(pid)), \
             patch("libdebug.utils.container._read_cgroup", lambda pid: cgroup_for.get(pid)):
            self.assertEqual(resolve_ns_pid_to_host_pid(999, 42, timeout=0.5), 1234)

    def test_resolve_ns_pid_fast_path_uses_cgroup_procs(self):
        """Fast path: candidate list comes from cgroup.procs; we skip the full /proc walk and
        skip the per-candidate cgroup verification because membership is already guaranteed.
        """
        cgroup_init = b"0::/system.slice/docker-deadbeef.scope\n"
        # Two PIDs in the container's cgroup. Only 4242 has the matching NSpid.
        status_for = {
            4111: b"Name:\tinit\nNSpid:\t4111\t1\n",
            4242: b"Name:\tcat\nNSpid:\t4242\t99\n",
        }

        listdir_calls = []

        def fake_listdir(p):
            listdir_calls.append(p)
            return []

        with patch("libdebug.utils.container._candidates_from_cgroup", return_value=[4111, 4242]), \
             patch("libdebug.utils.container._read_status", lambda pid: status_for.get(pid)), \
             patch("libdebug.utils.container._read_cgroup", lambda pid: cgroup_init if pid == 999 else None), \
             patch("libdebug.utils.container.os.listdir", fake_listdir):
            host_pid = resolve_ns_pid_to_host_pid(999, 99, timeout=0.5)

        self.assertEqual(host_pid, 4242)
        # The fast path must NOT scan /proc when cgroup.procs is available.
        self.assertEqual(listdir_calls, [], "fast path must not call os.listdir('/proc')")

    def test_cgroup_v2_path_extraction(self):
        """cgroup v2 returns a single ``0::/path`` line."""
        from libdebug.utils.container import _cgroup_v2_path
        self.assertEqual(
            _cgroup_v2_path(b"0::/system.slice/docker-abc.scope\n"),
            "/system.slice/docker-abc.scope",
        )

    def test_cgroup_v2_path_rejects_v1(self):
        """cgroup v1 has multiple ``id:controller:path`` lines — no ``0::`` line."""
        from libdebug.utils.container import _cgroup_v2_path
        v1 = (
            b"12:memory:/docker/abc\n"
            b"11:cpu:/docker/abc\n"
            b"10:devices:/docker/abc\n"
        )
        self.assertIsNone(_cgroup_v2_path(v1))

    def test_cgroup_v2_path_rejects_empty(self):
        from libdebug.utils.container import _cgroup_v2_path
        self.assertIsNone(_cgroup_v2_path(b""))

    def test_candidates_from_cgroup_returns_none_for_v1(self):
        """When the init's cgroup file is v1-style, the fast path bows out."""
        from libdebug.utils.container import _candidates_from_cgroup
        self.assertIsNone(_candidates_from_cgroup(b"12:memory:/docker/abc\n"))

    def test_candidates_from_cgroup_returns_none_on_missing_file(self):
        """If /sys/fs/cgroup<path>/cgroup.procs doesn't exist, fall through."""
        from libdebug.utils.container import _candidates_from_cgroup
        self.assertIsNone(_candidates_from_cgroup(b"0::/this/path/does/not/exist/anywhere\n"))

    def test_resolve_ns_pid_init_unreadable(self):
        with patch("libdebug.utils.container._read_cgroup", return_value=None):
            with self.assertRaises(ContainerError) as ctx:
                resolve_ns_pid_to_host_pid(999, 42, timeout=0.1)
            self.assertIn("not accessible", str(ctx.exception))

    def test_resolve_ns_pid_no_match_times_out(self):
        with patch("libdebug.utils.container.os.listdir", return_value=[]), \
             patch("libdebug.utils.container._candidates_from_cgroup", return_value=None), \
             patch("libdebug.utils.container._read_cgroup", return_value=b"0::/anything"):
            with self.assertRaises(ContainerError) as ctx:
                resolve_ns_pid_to_host_pid(999, 42, timeout=0.1)
            self.assertIn("Timed out", str(ctx.exception))

    # --- backing-file translation -----------------------------------------------------------

    def test_host_path_identity_in_host_mode(self):
        """When container is None the helper is identity — no path translation."""
        self.assertEqual(
            host_path_for_backing_file(None, None, "/lib/x86_64-linux-gnu/libc.so.6"),
            "/lib/x86_64-linux-gnu/libc.so.6",
        )

    def test_host_path_identity_when_runtime_missing(self):
        """If container is set but runtime isn't (shouldn't happen in practice), be safe and pass through."""
        self.assertEqual(
            host_path_for_backing_file(None, "ctr", "/lib/libc.so.6"),
            "/lib/libc.so.6",
        )

    def test_cache_container_path_skips_anonymous(self):
        """[heap]/[stack]/anon_<addr> have no on-disk backing — cache returns None."""
        for skip in ("[heap]", "[stack]", "[vdso]", "[vvar]", "anon_55ab12340000", ""):
            self.assertIsNone(cache_container_path("docker", "ctr", skip), f"failed for {skip!r}")

    def test_cache_container_path_skips_proc_paths(self):
        """/proc/<pid>/... is host-namespace; not something to docker-cp."""
        self.assertIsNone(cache_container_path("docker", "ctr", "/proc/1/status"))

    def test_cache_container_path_returns_tempfile_on_success(self):
        """A successful docker cp populates the cache; the second call short-circuits."""
        _PATH_CACHE.clear()  # cross-test isolation

        completed = type("R", (), {"returncode": 0, "stderr": "", "stdout": ""})()
        run_calls = []

        def fake_run(cmd, **kw):
            run_calls.append(cmd)
            # docker cp writes some bytes to the dest path so Path.is_file() returns True
            dest = cmd[-1]
            with open(dest, "wb") as f:
                f.write(b"\x7fELF fake")
            return completed

        with patch("libdebug.utils.container.subprocess.run", fake_run):
            path1 = cache_container_path("docker", "ctr", "/lib/libc.so.6")
            path2 = cache_container_path("docker", "ctr", "/lib/libc.so.6")

        try:
            self.assertIsNotNone(path1)
            self.assertEqual(path1, path2, "second lookup must hit the cache, not re-cp")
            self.assertEqual(len(run_calls), 1, "subprocess.run should only fire once")
            self.assertTrue(os.path.exists(path1))
        finally:
            # Drop the tempfile + cache entry so we don't leak between tests.
            from libdebug.utils.container import discard_tempfile
            if path1:
                discard_tempfile(path1)
            _PATH_CACHE.clear()

    def test_cache_container_path_remembers_failure(self):
        """A failed docker cp is also cached (as None) so we don't retry on every symbol lookup."""
        _PATH_CACHE.clear()

        failed = type("R", (), {"returncode": 1, "stderr": "no such file", "stdout": ""})()
        run_calls = []

        def fake_run(cmd, **kw):
            run_calls.append(cmd)
            return failed

        with patch("libdebug.utils.container.subprocess.run", fake_run):
            r1 = cache_container_path("docker", "ctr", "/missing/lib.so")
            r2 = cache_container_path("docker", "ctr", "/missing/lib.so")

        try:
            self.assertIsNone(r1)
            self.assertIsNone(r2)
            self.assertEqual(len(run_calls), 1, "failure must be cached, not retried")
        finally:
            _PATH_CACHE.clear()

    def test_host_path_translates_in_container_mode(self):
        """In container mode, host_path_for_backing_file returns the cached tempfile."""
        _PATH_CACHE.clear()
        completed = type("R", (), {"returncode": 0, "stderr": "", "stdout": ""})()

        def fake_run(cmd, **kw):
            dest = cmd[-1]
            with open(dest, "wb") as f:
                f.write(b"\x7fELF fake")
            return completed

        with patch("libdebug.utils.container.subprocess.run", fake_run):
            host_path = host_path_for_backing_file("docker", "ctr", "/lib/libc.so.6")

        try:
            self.assertNotEqual(host_path, "/lib/libc.so.6")
            self.assertTrue(host_path.startswith("/tmp/libdebug-container-"))
            self.assertTrue(host_path.endswith("libc.so.6"))
        finally:
            from libdebug.utils.container import discard_tempfile
            if host_path != "/bin/sh":
                discard_tempfile(host_path)
            _PATH_CACHE.clear()

    def test_host_path_falls_back_when_cp_fails(self):
        """If docker cp fails, host_path_for_backing_file returns the original path so callers
        get the same not-found behavior they'd see in host mode."""
        _PATH_CACHE.clear()
        failed = type("R", (), {"returncode": 1, "stderr": "denied", "stdout": ""})()

        with patch("libdebug.utils.container.subprocess.run", return_value=failed):
            host_path = host_path_for_backing_file("docker", "ctr", "/lib/secret.so")

        try:
            self.assertEqual(host_path, "/lib/secret.so")
        finally:
            _PATH_CACHE.clear()

    def test_host_path_passes_through_anonymous_mappings(self):
        """Anon mappings have no file to copy — host_path returns the original string."""
        for anon in ("[heap]", "[stack]", "anon_55ab1234"):
            self.assertEqual(
                host_path_for_backing_file("docker", "ctr", anon),
                anon,
            )

    def test_extract_container_binary_resolves_container_symlink_to_regular_file(self):
        """The main binary copy must be usable even when the container path is a symlink."""
        with symlink_cp_container(self) as (runtime, container):
            host_path = extract_container_binary(runtime, container, "/bin/sh")

        try:
            self.assertTrue(os.path.isfile(host_path))
            with open(host_path, "rb") as f:
                self.assertEqual(f.read(), SYMLINK_TARGET_BYTES)
        finally:
            from libdebug.utils.container import discard_tempfile
            discard_tempfile(host_path)

    def test_cache_container_path_resolves_container_symlink_to_regular_file(self):
        """Mapped library copies must not cache a broken host symlink for symlinked container files."""
        _PATH_CACHE.clear()

        with symlink_cp_container(self) as (runtime, container):
            host_path = host_path_for_backing_file(runtime, container, "/bin/sh")

        try:
            self.assertNotEqual(host_path, "/bin/sh")
            self.assertTrue(os.path.isfile(host_path))
            with open(host_path, "rb") as f:
                self.assertEqual(f.read(), SYMLINK_TARGET_BYTES)
        finally:
            from libdebug.utils.container import discard_tempfile
            discard_tempfile(host_path)
            _PATH_CACHE.clear()

    def test_spawn_container_env_none_inherits_container_environment(self):
        """env=None should keep the container's default environment, matching host-mode inheritance."""
        popen_calls = []

        def fake_popen(cmd, **kw):
            popen_calls.append(cmd)
            return _FakePopen()

        with patch("libdebug.utils.container.subprocess.Popen", fake_popen), \
             patch("libdebug.utils.container._read_pid_line", return_value=11), \
             patch("libdebug.utils.container.resolve_ns_pid_to_host_pid", return_value=111):
            spawn_in_container(
                "docker", "ctr", "/bin/echo", ["/bin/echo", "x"], None, 1, None, 2, 3, 2,
            )

        self.assertEqual(
            _effective_env_from_fake_exec_cmd(popen_calls[0]),
            {"PATH": "/usr/bin", "KEEP": "container-default"},
        )

    def test_spawn_container_env_dict_starts_wrapper_with_empty_environment(self):
        """env={} must not inherit the container's configured environment."""
        popen_calls = []

        def fake_popen(cmd, **kw):
            popen_calls.append(cmd)
            return _FakePopen()

        with patch("libdebug.utils.container.subprocess.Popen", fake_popen), \
             patch("libdebug.utils.container._read_pid_line", return_value=11), \
             patch("libdebug.utils.container.resolve_ns_pid_to_host_pid", return_value=111):
            spawn_in_container(
                "docker", "ctr", "/bin/echo", ["/bin/echo"], {}, 1, None, 2, 3, 2,
            )

        self.assertEqual(_effective_env_from_fake_exec_cmd(popen_calls[0]), {})

    def test_spawn_container_env_dict_passes_only_requested_variables(self):
        """Container mode should treat env={...} as the target environment, not as runtime overrides."""
        popen_calls = []

        def fake_popen(cmd, **kw):
            popen_calls.append(cmd)
            return _FakePopen()

        with patch("libdebug.utils.container.subprocess.Popen", fake_popen), \
             patch("libdebug.utils.container._read_pid_line", return_value=11), \
             patch("libdebug.utils.container.resolve_ns_pid_to_host_pid", return_value=111):
            spawn_in_container(
                "docker", "ctr", "/bin/echo", ["/bin/echo"], {"A": "B", "C": "D"}, 1, None, 2, 3, 2,
            )

        self.assertEqual(_effective_env_from_fake_exec_cmd(popen_calls[0]), {"A": "B", "C": "D"})

    def test_detach_does_not_wait_for_long_lived_container_exec_client(self):
        """Detach intentionally leaves the in-container target running, so it must not reap docker exec."""
        from libdebug.ptrace.ptrace_interface import PtraceInterface

        iface = object.__new__(PtraceInterface)
        iface._container_popen = _FakePopen()
        iface._internal_debugger = type(
            "D",
            (),
            {
                "breakpoints": {},
                "resume_context": type(
                    "R",
                    (),
                    {
                        "event_type": set(),
                        "event_hit_ref": set(),
                    },
                )(),
            },
        )()
        iface.lib_trace = type("L", (), {"detach_and_cont": lambda self: None})()

        PtraceInterface.detach(iface)

        self.assertFalse(iface._container_popen.wait_called)
        self.assertFalse(iface._container_popen.kill_called)
