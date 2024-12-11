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
            self.assertEqual(t.thread_id, target.thread_id)
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
        
        
    def test_multiple_bps_sync(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1_1 = d.breakpoint("random_function")
        bp1_2 = d.breakpoint("random_function")
        bp2_1 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp2_2 = d.breakpoint(TEST_BPS_ADDRESS_1)
        bp3_1 = d.breakpoint(TEST_BPS_ADDRESS_2)
        bp3_2 = d.breakpoint(TEST_BPS_ADDRESS_2)

        counter = 1

        d.cont()

        while True:
            if d.instruction_pointer == bp1_1.address:
                self.assertTrue(bp1_1.hit_count == 1)
                self.assertTrue(bp1_2.hit_count == 1)
                
                self.assertTrue(bp1_1.hit_on(d))
                self.assertTrue(bp1_2.hit_on(d))
                
                self.assertFalse(bp2_1.hit_on(d))
                self.assertFalse(bp2_2.hit_on(d))
                
                self.assertFalse(bp3_1.hit_on(d))
                self.assertFalse(bp3_2.hit_on(d))
            elif d.instruction_pointer == bp2_1.address:
                self.assertTrue(bp2_1.hit_count == counter)
                self.assertTrue(bp2_2.hit_count == counter)
                
                self.assertTrue(bp2_1.hit_on(d))
                self.assertTrue(bp2_2.hit_on(d))
                
                self.assertFalse(bp1_1.hit_on(d))
                self.assertFalse(bp1_2.hit_on(d))
                
                self.assertFalse(bp3_1.hit_on(d))
                self.assertFalse(bp3_2.hit_on(d))
                counter += 1
            elif d.instruction_pointer == bp3_1.address:
                self.assertTrue(bp3_1.hit_count == 1)
                self.assertTrue(bp3_2.hit_count == 1)
                                
                CHECK_REGISTERS(self, d)
                
                self.assertTrue(bp3_1.hit_on(d))
                self.assertTrue(bp3_2.hit_on(d))
                
                self.assertFalse(bp1_1.hit_on(d))
                self.assertFalse(bp1_2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2_1.hit_count, 10)
        self.assertEqual(bp2_2.hit_count, 10)
        
        self.assertEqual(d.breakpoints[bp1_1.address].hit_count, 2)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_1].hit_count, 20)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_2].hit_count, 2)

        d.kill()
        d.terminate()
        
    def test_multiple_bps_async(self):
        counter_1_1, counter_1_2 = 0, 0
        counter_2_1, counter_2_2 = 0, 0
        counter_3_1, counter_3_2 = 0, 0
        
        def first_first(t, bp):
            nonlocal counter_1_1
            counter_1_1 += 1
            self.assertEqual(counter_1_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_1_1, counter_1_2)
            
        def first_second(t, bp):
            nonlocal counter_1_2
            counter_1_2 += 1
            self.assertEqual(counter_1_2, bp.hit_count)
            
            # This callback should be called after the first one
            self.assertEqual(counter_1_2, counter_1_1)
            
        def second_first(t, bp):
            nonlocal counter_2_1
            counter_2_1 += 1
            self.assertEqual(counter_2_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_2_1, counter_2_2)
            
        def second_second(t, bp):
            nonlocal counter_2_2
            counter_2_2 += 1
            self.assertEqual(counter_2_2, bp.hit_count)
            
            # This callback should be called after the first one
            self.assertEqual(counter_2_2, counter_2_1)
            
        def third_first(t, bp):
            nonlocal counter_3_1
            counter_3_1 += 1
            self.assertEqual(counter_3_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_3_1, counter_3_2)
            
        def third_second(t, bp):
            nonlocal counter_3_2
            counter_3_2 += 1
            self.assertEqual(counter_3_2, bp.hit_count)
            
            # This callback should be called after the first one
            self.assertEqual(counter_3_2, counter_3_1)
    
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1_1 = d.breakpoint("random_function", callback=first_first)
        bp1_2 = d.breakpoint("random_function", callback=first_second)
        bp2_1 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_first)
        bp2_2 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_second)
        bp3_1 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_first)
        bp3_2 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_second)

        d.cont()
        
        d.wait()

        self.assertEqual(counter_1_1, 1)
        self.assertEqual(counter_1_2, 1)
        self.assertEqual(bp2_1.hit_count, 10)
        self.assertEqual(bp2_2.hit_count, 10)
        self.assertEqual(counter_3_1, 1)
        self.assertEqual(counter_3_2, 1)
        
        
        self.assertEqual(d.breakpoints[bp1_1.address].hit_count, 2)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_1].hit_count, 20)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_2].hit_count, 2)

        d.kill()
        d.terminate()
        
        
    def test_multiple_bps_async_both_sw_hw(self):
        counter_1_1, counter_1_2 = 0, 0
        counter_2_1, counter_2_2 = 0, 0
        counter_3_1, counter_3_2 = 0, 0
        
        def first_first(t, bp):
            nonlocal counter_1_1
            counter_1_1 += 1
            
            # This callback should be called before the second one
            self.assertGreater(counter_1_1, counter_1_2)
            
        def first_second(t, bp):
            nonlocal counter_1_2
            counter_1_2 += 1
            
            # This callback should be called after the first one
            self.assertTrue(counter_1_2 == counter_1_1 or counter_1_2 == counter_1_1 - 1)
            
        def second_first(t, bp):
            nonlocal counter_2_1
            counter_2_1 += 1
            
            # This callback should be called before the second one
            self.assertGreater(counter_2_1, counter_2_2)
            
        def second_second(t, bp):
            nonlocal counter_2_2
            counter_2_2 += 1
            
            # This callback should be called after the first one
            self.assertTrue(counter_2_2 == counter_2_1 or counter_2_2 == counter_2_1 - 1)
            
        def third_first(t, bp):
            nonlocal counter_3_1
            counter_3_1 += 1
            
            # This callback should be called before the second one
            self.assertGreater(counter_3_1, counter_3_2)
            
        def third_second(t, bp):
            nonlocal counter_3_2
            counter_3_2 += 1
            
            # This callback should be called after the first one
            self.assertTrue(counter_3_2 == counter_3_1 or counter_3_2 == counter_3_1 - 1)
    
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1_1 = d.breakpoint("random_function", callback=first_first)
        bp1_1_hw = d.breakpoint("random_function", callback=first_first, hardware=True)
        bp1_2 = d.breakpoint("random_function", callback=first_second)
        bp1_2_hw = d.breakpoint("random_function", callback=first_second, hardware=True)
        bp2_1 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_first)
        bp2_1_hw = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_first, hardware=True)
        bp2_2 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_second)
        bp2_2_hw = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_second, hardware=True)
        bp3_1 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_first)
        bp3_1_hw = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_first, hardware=True)
        bp3_2 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_second)
        bp3_2_hw = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_second, hardware=True)

        d.cont()
        
        d.wait()

        self.assertEqual(counter_1_1, 2)
        self.assertEqual(counter_1_2, 2)
        self.assertEqual(counter_2_1, 20)
        self.assertEqual(counter_2_2, 20)
        self.assertEqual(counter_3_1, 2)
        self.assertEqual(counter_3_2, 2)
        
        self.assertEqual(bp1_1.hit_count, counter_1_1 // 2)
        self.assertEqual(bp1_2.hit_count, counter_1_2 // 2)
        self.assertEqual(bp2_1.hit_count, counter_2_1 // 2)
        self.assertEqual(bp2_2.hit_count, counter_2_2 // 2)
        self.assertEqual(bp3_1.hit_count, counter_3_1 // 2)
        self.assertEqual(bp3_2.hit_count, counter_3_2 // 2)
        
        self.assertEqual(bp1_1_hw.hit_count, counter_1_1 // 2)
        self.assertEqual(bp1_2_hw.hit_count, counter_1_2 // 2)
        self.assertEqual(bp2_1_hw.hit_count, counter_2_1 // 2)
        self.assertEqual(bp2_2_hw.hit_count, counter_2_2 // 2)
        self.assertEqual(bp3_1_hw.hit_count, counter_3_1 // 2)
        self.assertEqual(bp3_2_hw.hit_count, counter_3_2 // 2)
        
        
        self.assertEqual(d.breakpoints[bp1_1.address].hit_count, 4)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_1].hit_count, 40)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_2].hit_count, 4)

        d.kill()
        d.terminate()
    
    
    def test_multiple_bps_disable(self):
        counter_1_1, counter_1_2 = 0, 0
        counter_2_1, counter_2_2 = 0, 0
        counter_3_1, counter_3_2 = 0, 0
        
        def first_first(t, bp):
            nonlocal counter_1_1
            counter_1_1 += 1
            self.assertEqual(counter_1_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_1_1, counter_1_2)
            
        def first_second(t, bp):
            nonlocal counter_1_2
            counter_1_2 += 1
            self.assertEqual(counter_1_2, bp.hit_count)
            
            # This callback should be called after the first one
            self.assertEqual(counter_1_2, counter_1_1)
            
        def second_first(t, bp):
            nonlocal counter_2_1
            counter_2_1 += 1
            self.assertEqual(counter_2_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_2_1, counter_2_2)
            
        def second_second(t, bp):
            nonlocal counter_2_2
            counter_2_2 += 1
            self.assertEqual(counter_2_2, bp.hit_count)
                        
            # Disable the breakpoint
            bp.disable()
            
        def third_first(t, bp):
            nonlocal counter_3_1
            counter_3_1 += 1
            self.assertEqual(counter_3_1, bp.hit_count)
            
            # This callback should be called before the second one
            self.assertGreater(counter_3_1, counter_3_2)
            
        def third_second(t, bp):
            nonlocal counter_3_2
            counter_3_2 += 1
            self.assertEqual(counter_3_2, bp.hit_count)
            
            # This callback should be called after the first one
            self.assertEqual(counter_3_2, counter_3_1)
    
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp1_1 = d.breakpoint("random_function", callback=first_first)
        bp1_2 = d.breakpoint("random_function", callback=first_second)
        bp2_1 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_first)
        bp2_2 = d.breakpoint(TEST_BPS_ADDRESS_1, callback=second_second)
        bp3_1 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_first)
        bp3_2 = d.breakpoint(TEST_BPS_ADDRESS_2, callback=third_second)

        d.cont()
        
        d.wait()
        
        self.assertEqual(counter_1_1, 1)
        self.assertEqual(counter_1_2, 1)
        self.assertEqual(bp2_1.hit_count, 10)
        self.assertEqual(bp2_2.hit_count, 1)
        self.assertEqual(counter_3_1, 1)
        self.assertEqual(counter_3_2, 1)
        
        
        self.assertEqual(d.breakpoints[bp1_1.address].hit_count, 2)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_1].hit_count, 11)
        self.assertEqual(d.breakpoints[TEST_BPS_ADDRESS_2].hit_count, 2)

        d.kill()
        d.terminate()
    
    def test_max_number_hw_bp_scoped(self):
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
        
        # Set bps on the target thread until we finish the hardware breakpoints
        offset = 0
        while True:
            try:
                target.bp(TEST_THREAD_SCOPED_END_THREAD + offset, file="binary", callback=True, hardware=True)
            except ValueError:
                break
            offset += 0x10
            
        # At this point we should be able to set sw breakpoints on the same thread
        target.bp(TEST_THREAD_SCOPED_END_THREAD + offset, file="binary", callback=True)
        
        # We should also be able to set hw breakpoints on other threads
        for thread in other_threads:
            thread.bp(TEST_THREAD_SCOPED_END_THREAD, file="binary", hardware=True)
        
        d.kill()        
        d.terminate()
        
    def test_breakpoints_list_thread_scoped(self):        
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
        
        # Set 10 bps on the target thread
        offset = 0
        for _ in range(10):
            target.bp(TEST_THREAD_SCOPED_END_THREAD + offset, file="binary", callback=True)
            offset += 0x10
            
        # 10 different bp locations on the target thread
        self.assertEqual(len(target.breakpoints), 10)
        
        # No breakpoints on other threads
        for thread in other_threads:
            self.assertEqual(len(thread.breakpoints), 0)
        
        # 10 different bp locations on the whole process
        self.assertEqual(len(d.breakpoints), 10)
        
        # 1 installed breakpoint for each location
        for breakpoint_list in target.breakpoints.values():
            self.assertEqual(len(breakpoint_list), 1)
            
        # Set again 10 bps on the target thread. These bps should be appended to the previous ones
        offset = 0
        for _ in range(10):
            target.bp(TEST_THREAD_SCOPED_END_THREAD + offset, file="binary", callback=True)
            offset += 0x10
            
        # 10 different bp locations on the target thread
        self.assertEqual(len(target.breakpoints), 10)
        
        # No breakpoints on other threads
        for thread in other_threads:
            self.assertEqual(len(thread.breakpoints), 0)
            
        # 10 different bp locations on the whole process
        self.assertEqual(len(d.breakpoints), 10)
        
        # 2 installed breakpoints for each location
        for breakpoint_list in target.breakpoints.values():
            self.assertEqual(len(breakpoint_list), 2)
            
        # Set again 4 hw bps on the target thread. These bps should be appended to the previous ones
        offset = 0
        for _ in range(4):
            target.bp(TEST_THREAD_SCOPED_END_THREAD + offset, file="binary", callback=True, hardware=True)
            offset += 0x10
            
        # 10 different bp locations on the target thread
        self.assertEqual(len(target.breakpoints), 10)
        
        # No breakpoints on other threads
        for thread in other_threads:
            self.assertEqual(len(thread.breakpoints), 0)
            
        # 10 different bp locations on the whole process
        self.assertEqual(len(d.breakpoints), 10)
        
        # 3 installed breakpoints for the first 4 locations, 2 for the rest
        for i, breakpoint_list in enumerate(target.breakpoints.values()):
            if i < 4:
                self.assertEqual(len(breakpoint_list), 3)
            else:
                self.assertEqual(len(breakpoint_list), 2)
        
        # We should also be able to set hw breakpoints on other threads
        for thread in other_threads:
            thread.bp(TEST_THREAD_SCOPED_END_THREAD, file="binary", hardware=True)
            
        # Still 10 different bp locations on the target thread
        self.assertEqual(len(target.breakpoints), 10)
        
        # 1 breakpoint location on other threads
        for thread in other_threads:
            self.assertEqual(len(thread.breakpoints), 1)
            
        # 10 different bp locations on the whole process
        self.assertEqual(len(d.breakpoints), 10)
                
        d.kill()        
        d.terminate()