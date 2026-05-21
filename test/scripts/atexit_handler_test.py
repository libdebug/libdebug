#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2026 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import subprocess
import psutil
import os
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE
from time import sleep
from pwn import process
import io
import logging
import sys


from libdebug import debugger
from libdebug.debugger.internal_debugger_holder import _cleanup_internal_debugger
from multiprocessing import Process, Queue


class AtexitHandlerTest(TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput
        sys.stderr = self.capturedOutput

        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_handler.close()

    def test_run_1(self):
        def provola(queue):
            d = debugger(RESOLVE_EXE("infinite_loop_test"))
            r = d.run()
            pid = d.pid

            d.cont()
            r.sendline(b"3")

            _cleanup_internal_debugger()

            # Send pid back to the parent
            queue.put(pid)

        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_run_2(self):
        def provola(queue):
            d = debugger(RESOLVE_EXE("infinite_loop_test"), kill_on_exit=False)
            r = d.run()
            pid = d.pid

            d.cont()
            r.sendline(b"3")

            _cleanup_internal_debugger()

            # Send pid back to the parent
            queue.put(pid)
        
        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())
        
        # We can actually kill the process
        os.kill(pid, 9)
        
        while True:
            try:
                pid, status = os.waitpid(pid, os.WNOHANG)
                if pid == 0:
                    continue
            except OSError:
                break
            sleep(0.1)
        
        # The process should not have been killed
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_run_3(self):
        def provola(queue):
            d = debugger(RESOLVE_EXE("infinite_loop_test"), kill_on_exit=False)
            r = d.run()
            pid = d.pid

            d.cont()
            r.sendline(b"3")
            
            d.kill_on_exit = True

            _cleanup_internal_debugger()

            # Send pid back to the parent
            queue.put(pid)

        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_run_4(self):
        def provola(queue):
            d = debugger(RESOLVE_EXE("infinite_loop_test"))
            r = d.run()
            pid = d.pid

            d.cont()
            r.sendline(b"3")
            
            d.kill_on_exit = False

            _cleanup_internal_debugger()

            # Send pid back to the parent
            queue.put(pid)
        
        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())
        
        # We can actually kill the process
        os.kill(pid, 9)
        
        while True:
            try:
                pid, status = os.waitpid(pid, os.WNOHANG)
                if pid == 0:
                    continue
            except OSError:
                break
            sleep(0.1)
        
        # The process should not have been killed
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_attach_detach_1(self):
        def provola(queue):
            p = subprocess.Popen([RESOLVE_EXE("infinite_loop_test")], stdin=subprocess.PIPE)

            d = debugger()
            
            pid = p.pid

            d.attach(pid)

            p.stdin.write(b"3\n")
            p.stdin.flush()

            d.step()
            d.step()

            d.detach()
            
            _cleanup_internal_debugger()
            
            # Send pid back to the parent
            queue.put(pid)
            
        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())
        
        # We can actually kill the process
        os.kill(pid, 9)
        
        while True:
            try:
                pid, status = os.waitpid(pid, os.WNOHANG)
                if pid == 0:
                    continue
            except OSError:
                break
            sleep(0.1)
        
        # The process should not have been killed
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_attach_detach_2(self):
        def provola(queue):
            p = subprocess.Popen([RESOLVE_EXE("infinite_loop_test")], stdin=subprocess.PIPE)

            d = debugger(kill_on_exit=False)
            
            pid = p.pid

            d.attach(pid)

            p.stdin.write(b"3\n")
            p.stdin.flush()

            d.step()
            d.step()

            d.detach()
            
            _cleanup_internal_debugger()
            
            # Send pid back to the parent
            queue.put(pid)

        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()

        # The process should not have been killed
        self.assertIn(pid, psutil.pids())
        
        # We can actually kill the process
        os.kill(pid, 9)
        
        while True:
            try:
                pid, status = os.waitpid(pid, os.WNOHANG)
                if pid == 0:
                    continue
            except OSError:
                break
            sleep(0.1)
        
        # The process should not have been killed
        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())

    def test_attach_1(self):
        def provola(queue):
            p = subprocess.Popen([RESOLVE_EXE("infinite_loop_test")], stdin=subprocess.PIPE)

            d = debugger(kill_on_exit=False)
            
            pid = p.pid

            d.attach(pid)

            p.stdin.write(b"3\n")
            p.stdin.flush()

            d.step()
            d.step()
            
            _cleanup_internal_debugger()
            
            # Send pid back to the parent
            queue.put(pid)
            
        q = Queue()
        process = Process(target=provola, args=(q,))
        process.start()
        process.join()

        pid = q.get()

        if pid in psutil.pids():
            # This might be a false positive due to some race conditions
            sleep(1)
            self.assertNotIn(pid, psutil.pids())
    
    def test_attach_2(self):
        p = process(RESOLVE_EXE("infinite_loop_test"), env={})

        d = debugger()

        d.attach(p.pid)

        p.sendline(b"3")

        d.step()
        
        d.step()

        p.kill()

        # The process should now be stopped in tracing stop. We are stealing some signal to 
        # libdebug.
        self.assertIsNotNone(p.poll(block=False))
        
        # Even if we kill the process, the next call should not raise an exception
        _cleanup_internal_debugger()

        p.close()
        del p

    def test_warning_nonblocking(self):
        d = debugger(RESOLVE_EXE("infinite_loop_test"))

        d.run()
        d.cont()

        # Simulate atexit handler
        _cleanup_internal_debugger()

        self.assertIn("WARNING", self.log_capture_string.getvalue())
        self.assertIn(
            "Script terminated while the debuggee is still running. Is your last statement non-blocking?",
            self.log_capture_string.getvalue(),
        )

    def test_no_warning_correct_usage(self):
        d = debugger(RESOLVE_EXE("infinite_loop_test"))

        d.run()

        # Simulate atexit handler
        _cleanup_internal_debugger()

        self.assertNotIn(
            "Script terminated while the debuggee is still running. Is your last statement non-blocking?",
            self.log_capture_string.getvalue(),
        )
