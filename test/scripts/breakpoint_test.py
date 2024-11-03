#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


match PLATFORM:
    case "amd64":
        TEST_BPS_ADDRESS_1 = 0x40115B
        TEST_BPS_ADDRESS_2 = 0x40116D
        TEST_BPS_ADDRESS_3 = 0x401162

        TEST_BP_DISABLE_ON_CREATION_ADDRESS = 0x40119c

        def CHECK_REGISTERS(harness, d):
            harness.assertEqual(d.regs.rsi, 45)
            harness.assertEqual(d.regs.esi, 45)
            harness.assertEqual(d.regs.si, 45)
            harness.assertEqual(d.regs.sil, 45)
            
        TEST_THREAD_SCOPED_END_THREAD = 0x128a
    case "aarch64":
        TEST_BPS_ADDRESS_1 = 0x7fc
        TEST_BPS_ADDRESS_2 = 0x820
        TEST_BPS_ADDRESS_3 = 0x814

        TEST_BP_DISABLE_ON_CREATION_ADDRESS = 0x854

        def CHECK_REGISTERS(harness, d):
            harness.assertEqual(d.regs.x1, 45)
            harness.assertEqual(d.regs.w1, 45)
        
        TEST_THREAD_SCOPED_END_THREAD = 0xaec
    case "i386":
        TEST_BPS_ADDRESS_1 = 0x11d0
        TEST_BPS_ADDRESS_2 = 0x11ea
        TEST_BPS_ADDRESS_3 = 0x11d7

        TEST_BP_DISABLE_ON_CREATION_ADDRESS = 0x1235

        def CHECK_REGISTERS(harness, d):
            value = int.from_bytes(d.memory[d.regs.esp + 4, 4], "little")
            harness.assertEqual(value, 45)
        TEST_THREAD_SCOPED_END_THREAD = 0x1243
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")

class BreakpointTest(TestCase):
    def setUp(self):
        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)


    def test_bps(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 10)

        d.kill()
        d.terminate()

    def test_bps_waiting(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"), auto_interrupt_on_command=True)

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            d.wait()
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        d.kill()
        d.terminate()

    def test_bp_disable(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 1)

        d.kill()
        d.terminate()

    def test_bp_disable_hw(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1, hardware=True)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 1)

        d.kill()
        d.terminate()

    def test_bp_disable_reenable(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp4 = d.breakpoint(TEST_BPS_ADDRESS_3)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        d.kill()
        d.terminate()

    def test_bp_disable_reenable_hw(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp4 = d.breakpoint(TEST_BPS_ADDRESS_3, hardware=True)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        d.kill()
        d.terminate()

    def test_bps_running(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp3 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.running:
                pass
            if d.instruction_pointer == bp1.address:
                self.assertFalse(d.running)
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertFalse(d.running)
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertFalse(d.running)
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 10)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_bp_backing_file_amd64(self):
        d = debugger(RESOLVE_EXE("executable_section_test"))

        d.run()

        bp1 = d.breakpoint(0x1266, file="binary")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        bp1 = d.breakpoint(0x1266, file="executable_section_test")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.run()

        bp1 = d.breakpoint(0x1266, file="hybrid")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        with self.assertRaises(ValueError):
            d.breakpoint(0x1266, file="absolute")

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_bp_backing_file_aarch64(self):
        d = debugger(RESOLVE_EXE("executable_section_test"))

        d.run()

        bp1 = d.breakpoint(0x968, file="binary")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        bp1 = d.breakpoint(0x968, file="executable_section_test")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.run()

        bp1 = d.breakpoint(0x968, file="hybrid")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        with self.assertRaises(ValueError):
            d.breakpoint(0x968, file="absolute")

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_bp_backing_file_i386(self):
        d = debugger(RESOLVE_EXE("executable_section_test"))

        d.run()

        bp1 = d.breakpoint(0x804926b, file="binary")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x9, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.eax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        bp1 = d.breakpoint(0x804926b, file="executable_section_test")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x9, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.eax, 9)

        d.run()

        bp1 = d.breakpoint(0x804926b, file="hybrid")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x9, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.instruction_pointer], b"]")
            self.assertEqual(d.regs.eax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        with self.assertRaises(ValueError):
            d.breakpoint(0x9D0, file="absolute")

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.bp("random_function")
        bp2 = d.bp(TEST_BP_DISABLE_ON_CREATION_ADDRESS)
        bp1.disable()

        d.cont()

        self.assertFalse(bp1.hit_on(d))
        self.assertTrue(bp2.hit_on(d))

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_2(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp = d.bp("random_function")

        bp.disable()

        d.cont()
        d.wait()

        # Validate we didn't segfault
        self.assertTrue(d.dead)
        self.assertIsNone(d.exit_signal)

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_hardware(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1 = d.bp("random_function", hardware=True)
        bp2 = d.bp(TEST_BP_DISABLE_ON_CREATION_ADDRESS)
        bp1.disable()

        d.cont()

        self.assertFalse(bp1.hit_on(d))
        self.assertTrue(bp2.hit_on(d))

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_2_hardware(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp = d.bp("random_function", hardware=True)

        bp.disable()

        d.cont()
        d.wait()

        # Validate we didn't segfault
        self.assertTrue(d.dead)
        self.assertIsNone(d.exit_signal)

        d.kill()
        d.terminate()
        
    def test_bp_sync_sw_thread_scoped(self):
        d = debugger(RESOLVE_EXE("multithread_input"))
        
        r = d.run()
        
        d.cont()
        
        # Let wait all threads to be created
        r.recvuntil(b"All threads have been created.")
        
        # Interrupt the process
        d.interrupt()
        
        # Choice a target
        target = d.threads[2]
        other_threads = d.threads.copy()
        other_threads.remove(target)
        
        # Set a breakpoint on the target thread
        bp = target.bp(TEST_THREAD_SCOPED_END_THREAD, file="binary")
        
        for _ in range(5):
            # Process will ask for input. Let put some input in the buffer
            r.sendline(b"Io_no")
        
        # Process scoped continue and wait
        d.cont()
        d.wait()
        
        self.assertTrue(bp.hit_on(target))
        
        for thread in other_threads:
            self.assertFalse(bp.hit_on(thread))
        
        d.kill()
        d.terminate()
    
    def test_bp_sync_hw_thread_scoped(self):
        d = debugger(RESOLVE_EXE("multithread_input"))
        
        r = d.run()
        
        d.cont()
        
        # Let wait all threads to be created
        r.recvuntil(b"All threads have been created.")
        
        # Interrupt the process
        d.interrupt()
        
        # Choice a target
        target = d.threads[2]
        other_threads = d.threads.copy()
        other_threads.remove(target)
        
        # Set a breakpoint on the target thread
        bp = target.bp(TEST_THREAD_SCOPED_END_THREAD, file="binary", hardware=True)
        
        for _ in range(5):
            # Process will ask for input. Let put some input in the buffer
            r.sendline(b"Io_no")
        
        # Process scoped continue and wait
        d.cont()
        d.wait()
        
        self.assertTrue(bp.hit_on(target))
        
        for thread in other_threads:
            self.assertFalse(bp.hit_on(thread))
        
        d.kill()
        d.terminate()
    
    def test_bp_async_sw_thread_scoped(self):
        def callback(t, bp):
            # self.assertEqual(t.thread_id, target.thread_id)
            pass
        
        d = debugger(RESOLVE_EXE("multithread_input"))
        
        r = d.run()
        
        d.cont()
        
        # Let wait all threads to be created
        r.recvuntil(b"All threads have been created.")
        
        # Interrupt the process
        d.interrupt()
        
        # Choice a target
        target = d.threads[2]
        other_threads = d.threads.copy()
        other_threads.remove(target)
        
        # Set a breakpoint on the target thread
        bp = target.bp(TEST_THREAD_SCOPED_END_THREAD, file="binary", callback=callback)
        
        # Process scoped continue and wait
        d.cont()
        for _ in range(5):
            # Process will ask for input
            r.sendline(b"Io_no")
        
        d.wait()
        
        d.kill()
        
        # The callback should have been called only once, from the target thread only
        self.assertEqual(bp.hit_count, 1)
        
        d.terminate()
        