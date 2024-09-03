#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import psutil
import signal
import unittest
from pwn import process

from libdebug import debugger
from libdebug.debugger.internal_debugger_holder import _cleanup_internal_debugger


class AtexitHandlerTest(unittest.TestCase):
    def test_run_1(self):
        d = debugger("binaries/infinite_loop_test")

        r = d.run()

        pid = d.pid

        d.cont()

        r.sendline(b"3")

        _cleanup_internal_debugger()

        # The process should have been killed
        self.assertNotIn(pid, psutil.pids())

    def test_run_2(self):
        d = debugger("binaries/infinite_loop_test", kill_on_exit=False)

        r = d.run()

        pid = d.pid

        d.cont()

        r.sendline(b"3")

        _cleanup_internal_debugger()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())

        os.kill(pid, signal.SIGKILL)

        # The process should now be dead
        self.assertNotIn(pid, psutil.pids())

    def test_run_3(self):
        d = debugger("binaries/infinite_loop_test", kill_on_exit=False)

        r = d.run()

        pid = d.pid

        d.cont()

        r.sendline(b"3")

        d.kill_on_exit = True

        _cleanup_internal_debugger()

        # The process should have been killed
        self.assertNotIn(pid, psutil.pids())

    def test_run_4(self):
        d = debugger("binaries/infinite_loop_test")

        r = d.run()

        pid = d.pid

        d.cont()

        d.kill_on_exit = False

        r.sendline(b"3")

        _cleanup_internal_debugger()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())

        os.kill(pid, signal.SIGKILL)

        # The process should now be dead
        self.assertNotIn(pid, psutil.pids())

    def test_attach_detach_1(self):
        p = process("binaries/infinite_loop_test")

        d = debugger()

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        d.detach()

        # If the process is still running, poll() should return None
        self.assertIsNone(p.poll(block=False))

        _cleanup_internal_debugger()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

    def test_attach_detach_2(self):
        p = process("binaries/infinite_loop_test")

        d = debugger(kill_on_exit=False)

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        d.detach()

        # If the process is still running, poll() should return None
        self.assertIsNone(p.poll(block=False))

        _cleanup_internal_debugger()

        # We set kill_on_exit to False, so the process should still be alive
        # The process should still be alive
        self.assertIsNone(p.poll(block=False))

        p.kill()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

    def test_attach_detach_3(self):
        p = process("binaries/infinite_loop_test")

        d = debugger(kill_on_exit=False)

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        d.detach()

        # If the process is still running, poll() should return None
        self.assertIsNone(p.poll(block=False))

        d.kill_on_exit = True

        _cleanup_internal_debugger()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

    def test_attach_detach_4(self):
        p = process("binaries/infinite_loop_test")

        d = debugger()

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        d.detach()

        # If the process is still running, poll() should return None
        self.assertIsNone(p.poll(block=False))

        d.kill_on_exit = False

        _cleanup_internal_debugger()

        # We set kill_on_exit to False, so the process should still be alive
        # The process should still be alive
        self.assertIsNone(p.poll(block=False))

        p.kill()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

    def test_attach_1(self):
        p = process("binaries/infinite_loop_test")

        d = debugger()

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        # If the process is still running, poll() should return None
        self.assertIsNone(p.poll(block=False))

        _cleanup_internal_debugger()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

    def test_attach_2(self):
        p = process("binaries/infinite_loop_test")

        d = debugger()

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        d.step()

        p.kill()

        # The process should now be dead
        self.assertIsNotNone(p.poll(block=False))

        # Even if we kill the process, the next call should not raise an exception
        _cleanup_internal_debugger()
