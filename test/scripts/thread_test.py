#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import unittest

from libdebug import debugger


class ThreadTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/thread_test")
    
    def test_thread(self):
        from libdebug.liblog import liblog

        liblog.debugger_logger.setLevel(5)

        d = self.d

        d.run()
        
        bp_t0 = d.breakpoint("do_nothing")
        bp_t1 = d.breakpoint("thread_1_function")
        bp_t2 = d.breakpoint("thread_2_function")
        bp_t3 = d.breakpoint("thread_3_function")

        t1 = None
        t2 = None
        t3 = None

        t1_done = False
        t2_done = False
        t3_done = False
        
        d.cont()

        for _ in range(15):
            d.wait()

            if len(d.threads.values()) == 2:
                t1 = d.threads[list(d.threads.keys())[1]]
            
            if len(d.threads.values()) == 3:
                t2 = d.threads[list(d.threads.keys())[2]]

            if len(d.threads.values()) == 4:
                t3 = d.threads[list(d.threads.keys())[3]]

            print([f'{a}: {hex(t.rip)}' for a, t in d.threads.items()])

            if bp_t0.address == d.rip:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if t1 and bp_t1.address == t1.rip:
                t1_done = True
            if t2 and bp_t2.address == t2.rip:
                t2_done = True
            if t3 and bp_t3.address == t3.rip:
                t3_done = True

            d.cont()
            
        d.kill()
