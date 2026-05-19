#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import fcntl
import os
from unittest import TestCase
from unittest.mock import patch


def _make_pipe(nonblocking=True):
    """Return (r, w) with the read end set to non-blocking — mirrors `_run_in_container`."""
    r, w = os.pipe()
    if nonblocking:
        flags = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    return r, w

from libdebug.utils.container import (
    ContainerError,
    SUPPORTED_RUNTIMES,
    _build_target_argv,
    _read_pid_line,
    detect_runtime,
    resolve_ns_pid_to_host_pid,
)


class _FakePopen:
    """Minimal Popen stand-in for _read_pid_line tests."""

    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


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

    def test_build_target_argv_drops_custom_argv0(self):
        # User-supplied custom argv[0] is replaced (documented limitation)
        self.assertEqual(
            _build_target_argv("/bin/foo", ["custom-name", "arg"]),
            ["/bin/foo", "arg"],
        )

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

    def test_resolve_ns_pid_uses_last_column(self):
        """For nested namespaces, the last column of NSpid is the innermost (container) PID."""
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

        def fake_listdir(_):
            return listed

        def fake_read_status(pid):
            return status_for.get(pid)

        def fake_read_cgroup(pid):
            return cgroup_for.get(pid)

        with patch("libdebug.utils.container.os.listdir", fake_listdir), \
             patch("libdebug.utils.container._read_status", fake_read_status), \
             patch("libdebug.utils.container._read_cgroup", fake_read_cgroup):
            self.assertEqual(resolve_ns_pid_to_host_pid(999, 42, timeout=0.5), 1234)

    def test_resolve_ns_pid_init_unreadable(self):
        with patch("libdebug.utils.container._read_cgroup", return_value=None):
            with self.assertRaises(ContainerError) as ctx:
                resolve_ns_pid_to_host_pid(999, 42, timeout=0.1)
            self.assertIn("not accessible", str(ctx.exception))

    def test_resolve_ns_pid_no_match_times_out(self):
        with patch("libdebug.utils.container.os.listdir", return_value=[]), \
             patch("libdebug.utils.container._read_cgroup", return_value=b"0::/anything"):
            with self.assertRaises(ContainerError) as ctx:
                resolve_ns_pid_to_host_pid(999, 42, timeout=0.1)
            self.assertIn("Timed out", str(ctx.exception))
