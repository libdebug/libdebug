#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE
from libdebug import debugger
import tempfile
import sys

class SnapshotsTest(TestCase):
    def setUp(self) -> None:
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput
        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)
        
    def tearDown(self):
        # Restore stdout
        self.capturedOutput.close()
        sys.stdout = sys.__stdout__
        # Remove the custom handler
        self.logger.removeHandler(self.log_handler)
        # Restore the original handlers
        self.logger.handlers = self.original_handlers
        # Close the log capture string buffer
        self.log_capture_string.close()

    def test_thread_base_snapshot(self):
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False)
        d.run()

        thread = d.threads[0]

        # Create initial snapshot
        ts1 = thread.create_snapshot(level="base", name="_start_snapshot")
        
        # Check for properties
        self.assertEqual(ts1.name, "_start_snapshot")
        self.assertEqual(ts1.level, "base")
        self.assertEqual(ts1.thread_id, thread.tid)
        self.assertEqual(ts1.arch, d.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1.regs, reg_name) and ts1.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check that the snapshot correctly throws an exception if we try to access memory
        with self.assertRaises(ValueError):
            a = ts1.memory[0x0000, 0x1000, "binary"]

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1.maps[i], current_map)

        # Check exception on backtrace
        with self.assertRaises(ValueError):
            saved_backtrace = ts1.backtrace()

        # Try saving
        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ts1.save(save_path)
        ts1_restored = d.load_snapshot(save_path)

        #########################################################################
        # --- Check that the restored snapshot is equal to the original one --- #
        #########################################################################

        # Check for properties
        self.assertEqual(ts1_restored.name, ts1.name)
        self.assertEqual(ts1_restored.level, ts1.level)
        self.assertEqual(ts1_restored.thread_id, ts1.thread_id)
        self.assertEqual(ts1_restored.arch, ts1.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1_restored.regs, reg_name) and ts1_restored.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check that the snapshot correctly throws an exception if we try to access memory
        with self.assertRaises(ValueError):
            a = ts1_restored.memory[0x0000, 0x1000, "binary"]

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1_restored.maps[i], current_map)

        # Check exception on backtrace
        with self.assertRaises(ValueError):
            saved_backtrace = ts1_restored.backtrace()

        d.kill()
        d.terminate()

        tmp_file.close()

    def test_thread_writable_snapshot(self):
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False, fast_memory=True)
        d.run()

        thread = d.threads[0]

        # Create initial snapshot
        ts1 = thread.create_snapshot(level="writable", name="_start_snapshot")
        
        # Check for properties
        self.assertEqual(ts1.name, "_start_snapshot")
        self.assertEqual(ts1.level, "writable")
        self.assertEqual(ts1.thread_id, thread.tid)
        self.assertEqual(ts1.arch, d.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1.regs, reg_name) and ts1.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1.maps[i], current_map)

        # Check for correct memory access
        for map in d.maps: 
            if 'w' in map.permissions:
                is_protected = False

                try:
                    b = d.memory[map.start:map.end, "absolute"]
                # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                except (OSError, OverflowError, ValueError):
                    is_protected = True

                if not is_protected:
                    a = ts1.memory[map.start:map.end, "absolute"]
                    self.assertEqual(a, b)
            else:
                with self.assertRaises(ValueError):
                    a = ts1.memory[map.start:map.end, "absolute"]

        # Check equality of stack trace
        current_backtrace = d.backtrace()
        saved_backtrace = ts1.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, saved_backtrace[i])

        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ts1.save(save_path)
        ts1_restored = d.load_snapshot(save_path)

        #########################################################################
        # --- Check that the restored snapshot is equal to the original one --- #
        #########################################################################

        # Check for properties
        self.assertEqual(ts1_restored.name, ts1.name)
        self.assertEqual(ts1_restored.level, ts1.level)
        self.assertEqual(ts1_restored.thread_id, ts1.thread_id)
        self.assertEqual(ts1_restored.arch, ts1.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1_restored.regs, reg_name) and ts1_restored.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check for correct memory access
        for map in d.maps:
            if 'w' in map.permissions:
                is_protected = False

                try:
                    b = d.memory[map.start:map.end, "absolute"]
                # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                except (OSError, OverflowError, ValueError):
                    is_protected = True

                if not is_protected:
                    a = ts1.memory[map.start:map.end, "absolute"]
                    self.assertEqual(a, b)
            else:
                with self.assertRaises(ValueError):
                    a = ts1_restored.memory[map.start:map.end, "absolute"]

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1_restored.maps[i], current_map)

        # Check equality of stack trace
        current_backtrace = d.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, ts1_restored.backtrace()[i])

        d.kill()
        d.terminate()

        tmp_file.close()

    def test_thread_full_snapshot(self):
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False, fast_memory=True)
        d.run()

        thread = d.threads[0]

        # Create initial snapshot
        ts1 = thread.create_snapshot(level="full", name="_start_snapshot")
        
        # Check for properties
        self.assertEqual(ts1.name, "_start_snapshot")
        self.assertEqual(ts1.level, "full")
        self.assertEqual(ts1.thread_id, thread.tid)
        self.assertEqual(ts1.arch, d.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1.regs, reg_name) and ts1.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1.maps[i], current_map)

        # Check correct memory access
        for map in d.maps:
            is_protected = False

            try:
                b = d.memory[map.start:map.end, "absolute"]
            # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
            except (OSError, OverflowError, ValueError):
                is_protected = True

            if not is_protected:
                a = ts1.memory[map.start:map.end, "absolute"]
                self.assertEqual(a, b)

        # Check equality of stack trace
        current_backtrace = d.backtrace()
        saved_backtrace = ts1.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, saved_backtrace[i])

        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ts1.save(save_path)
        ts1_restored = d.load_snapshot(save_path)

        #########################################################################
        # --- Check that the restored snapshot is equal to the original one --- #
        #########################################################################

        # Check for properties
        self.assertEqual(ts1_restored.name, ts1.name)
        self.assertEqual(ts1_restored.level, ts1.level)
        self.assertEqual(ts1_restored.thread_id, ts1.thread_id)
        self.assertEqual(ts1_restored.arch, ts1.arch)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ts1_restored.regs, reg_name) and ts1_restored.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check correct memory access
        for map in d.maps:
            is_protected = False

            try:
                b = d.memory[map.start:map.end, "absolute"]
            # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
            except (OSError, OverflowError, ValueError):
                is_protected = True

            if not is_protected:
                a = ts1_restored.memory[map.start:map.end, "absolute"]
                self.assertEqual(a, b)

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ts1_restored.maps[i], current_map)

        # Check equality of stack trace
        current_backtrace = d.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, ts1_restored.backtrace()[i])

        d.kill()
        d.terminate()

        tmp_file.close()

    def test_process_base_snapshot(self):
        
        # Create a debugger and start
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False)
        d.run()

        bp = d.breakpoint("not_interesting")
        d.cont()
        d.wait()

        self.assertEqual(len(d.threads), 4)

        # Create initial snapshot
        ps1 = d.create_snapshot(level="base", name="_start_snapshot")

        # Check for properties
        self.assertEqual(ps1.name, "_start_snapshot")
        self.assertEqual(ps1.level, "base")
        self.assertEqual(ps1.arch, d.arch)
        self.assertEqual(ps1.process_id, d.pid)
        self.assertEqual(len(ps1.threads), len(d.threads))

        # Check for thread ids
        for i, thread in enumerate(d.threads):
            self.assertEqual(ps1.threads[i].tid, thread.tid)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ps1.regs, reg_name) and ps1.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check that the snapshot correctly throws an exception if we try to access memory
        with self.assertRaises(ValueError):
            a = ps1.memory[0x0000, 0x1000, "binary"]

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ps1.maps[i], current_map)
        
        # Check exception on backtrace
        with self.assertRaises(ValueError):
            saved_backtrace = ps1.backtrace()

        # Check for correct thread registers
        for i, thread in enumerate(d.threads):
            for reg_name in dir(thread.regs):
                if isinstance(getattr(thread.regs, reg_name), int | float):
                    self.assertTrue(
                        hasattr(ps1.threads[i].regs, reg_name) and 
                        ps1.threads[i].regs.__getattribute__(reg_name) ==\
                        thread.regs.__getattribute__(reg_name)
                    )

        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ps1.save(save_path)
        ps1_restored = d.load_snapshot(save_path)

        #########################################################################
        # --- Check that the restored snapshot is equal to the original one --- #
        #########################################################################

        # Check for properties
        self.assertEqual(ps1_restored.name, ps1.name)
        self.assertEqual(ps1_restored.level, ps1.level)
        self.assertEqual(ps1_restored.arch, ps1.arch)
        self.assertEqual(ps1_restored.process_id, ps1.process_id)
        self.assertEqual(len(ps1_restored.threads), len(ps1.threads))

        # Check for thread ids
        for i, thread in enumerate(d.threads):
            self.assertEqual(ps1_restored.threads[i].tid, thread.tid)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ps1_restored.regs, reg_name) and ps1_restored.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check that the snapshot correctly throws an exception if we try to access memory
        with self.assertRaises(ValueError):
            a = ps1_restored.memory[0x0000, 0x1000, "binary"]

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ps1_restored.maps[i], current_map)

        # Check exception on backtrace
        with self.assertRaises(ValueError):
            saved_backtrace = ps1_restored.backtrace()

        # Check for correct thread registers
        for i, thread in enumerate(d.threads):
            for reg_name in dir(thread.regs):
                if isinstance(getattr(thread.regs, reg_name), int | float):
                    self.assertTrue(
                        hasattr(ps1_restored.threads[i].regs, reg_name) and 
                        ps1_restored.threads[i].regs.__getattribute__(reg_name) ==\
                        thread.regs.__getattribute__(reg_name)
                    )

        d.kill()
        d.terminate()

        tmp_file.close()

    def test_process_full_snapshot(self):
        # Create a debugger and start
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False, fast_memory=True)
        d.run()

        bp = d.breakpoint("not_interesting")
        d.cont()
        d.wait()

        self.assertEqual(len(d.threads), 4)

        # Create initial snapshot
        ps1 = d.create_snapshot(level="full", name="_start_snapshot")

        # Check for properties
        self.assertEqual(ps1.name, "_start_snapshot")
        self.assertEqual(ps1.level, "full")
        self.assertEqual(ps1.arch, d.arch)
        self.assertEqual(ps1.process_id, d.pid)
        self.assertEqual(len(ps1.threads), len(d.threads))

        # Check for thread ids
        for i, thread in enumerate(d.threads):
            self.assertEqual(ps1.threads[i].tid, thread.tid)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ps1.regs, reg_name) and ps1.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check memory access
        for map in d.maps:
            is_protected = False

            try:
                b = d.memory[map.start:map.end, "absolute"]
            # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
            except (OSError, OverflowError, ValueError):
                is_protected = True

            if not is_protected:
                a = ps1.memory[map.start:map.end, "absolute"]
                self.assertEqual(a, b)

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ps1.maps[i], current_map)
        
        # Check equality of stack trace
        current_backtrace = d.backtrace()
        saved_backtrace = ps1.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, saved_backtrace[i])

        # Check for correct thread registers
        for i, thread in enumerate(d.threads):
            for reg_name in dir(thread.regs):
                if isinstance(getattr(thread.regs, reg_name), int | float):
                    self.assertTrue(
                        hasattr(ps1.threads[i].regs, reg_name) and 
                        ps1.threads[i].regs.__getattribute__(reg_name) ==\
                        thread.regs.__getattribute__(reg_name)
                    )

        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ps1.save(save_path)
        ps1_restored = d.load_snapshot(save_path)

        #########################################################################
        # --- Check that the restored snapshot is equal to the original one --- #
        #########################################################################

        # Check for properties
        self.assertEqual(ps1_restored.name, ps1.name)
        self.assertEqual(ps1_restored.level, ps1.level)
        self.assertEqual(ps1_restored.arch, ps1.arch)
        self.assertEqual(ps1_restored.process_id, ps1.process_id)
        self.assertEqual(len(ps1_restored.threads), len(ps1.threads))

        # Check for thread ids
        for i, thread in enumerate(d.threads):
            self.assertEqual(ps1_restored.threads[i].tid, thread.tid)

        # Check for registers
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(ps1_restored.regs, reg_name) and ps1_restored.regs.__getattribute__(reg_name) == d.regs.__getattribute__(reg_name))

        # Check memory access
        for map in d.maps:
            is_protected = False

            try:
                b = d.memory[map.start:map.end, "absolute"]
            # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
            except (OSError, OverflowError, ValueError):
                is_protected = True

            if not is_protected:
                a = ps1_restored.memory[map.start:map.end, "absolute"]
                self.assertEqual(a, b)

        # Check equality of maps
        for i, current_map in enumerate(d.maps):
            self.assertEqual(ps1_restored.maps[i], current_map)

        # Check equality of stack trace
        current_backtrace = d.backtrace()

        for i, spc in enumerate(current_backtrace):
            self.assertEqual(spc, ps1_restored.backtrace()[i])

        # Check for correct thread registers
        for i, thread in enumerate(d.threads):
            for reg_name in dir(thread.regs):
                if isinstance(getattr(thread.regs, reg_name), int | float):
                    self.assertTrue(
                        hasattr(ps1_restored.threads[i].regs, reg_name) and 
                        ps1_restored.threads[i].regs.__getattribute__(reg_name) ==\
                        thread.regs.__getattribute__(reg_name)
                    )

        d.kill()
        d.terminate()

        tmp_file.close()

    def test_diff_thread_base_full(self):
        # Create a debugger and start
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False, fast_memory=True)
        d.run()

        ts1 = d.threads[0].create_snapshot(level="base", name="_start_snapshot")

        # Move forward
        d.breakpoint("main", file="binary")
        d.cont()
        d.wait()

        # Create a new snapshot
        ts2 = d.threads[0].create_snapshot(level="full", name="main_snapshot")

        # Diff it
        diff = ts2.diff(ts1)

        # Check for properties
        self.assertEqual(diff.snapshot1, ts1)
        self.assertEqual(diff.snapshot2, ts2)
        self.assertEqual(diff.level, "base")

        # Check for register diff correctness
        for reg_name in dir(d.regs):
            if isinstance(getattr(d.regs, reg_name), int | float):
                self.assertTrue(hasattr(diff.regs, reg_name))

                reg_diff = diff.regs.__getattribute__(reg_name)

                old_val = ts1.regs.__getattribute__(reg_name)
                new_val = ts2.regs.__getattribute__(reg_name)
                has_changed = old_val != new_val

                self.assertEqual(reg_diff.old_value, old_val)
                self.assertEqual(reg_diff.new_value, new_val)
                self.assertEqual(reg_diff.has_changed, has_changed)
        
        d.terminate()

    def test_symbol_permanence_test(self):
        d = debugger(RESOLVE_EXE("process_snapshot_test"), auto_interrupt_on_command=False, aslr=False, fast_memory=True)
        d.run()

        # Create a snapshot
        ps1 = d.create_snapshot(level="writable", name="_start_snapshot")

        binary_page = ps1.maps.filter("binary")[0]

        d.kill()

        # This should not throw an exception even if the binary is dead
        symbol1 = ps1.memory._symbol_ref["main"]
        symbol2 = ps1.memory._symbol_ref.filter(binary_page.start + symbol1[0].start)
        self.assertEqual(symbol1, symbol2)
        

        tmp_file = tempfile.NamedTemporaryFile(suffix=".json")
        save_path = tmp_file.name

        ps1.save(save_path)
        ps1_restored = d.load_snapshot(save_path)

        # Retry filtering symbols on the restored snapshot
        restored_symbol1 = ps1_restored.memory._symbol_ref["main"]
        restored_symbol2 = ps1.memory._symbol_ref.filter(binary_page.start + restored_symbol1[0].start)

        self.assertEqual(restored_symbol1, restored_symbol2)

        self.assertEqual(symbol1, restored_symbol1)
        d.terminate()

        tmp_file.close()