#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from libdebug import debugger
from unittest import TestCase
import tracemalloc
import gc
import objgraph


class MemoryLeakTest(TestCase):
    def test_memory_leak(self):
        def runner():
            d = debugger("ls")
            d.run()
            d.cont()
            d.wait()
            d.kill()
            d.terminate()
            
        # Initialize the counter, to remove dependencies from previous tests
        internal_debugger_count = objgraph.count('InternalDebugger')
        debugger_count = objgraph.count('Debugger')
        pipe_manager_count = objgraph.count('PipeManager')
        resume_context_count = objgraph.count('ResumeContext')
        process_memory_manager_count = objgraph.count('ProcessMemoryManager')
        ptrace_interface_count = objgraph.count('PtraceInterface')
        direct_memory_view_count = objgraph.count('DirectMemoryView')
        chunked_memory_view_count = objgraph.count('ChunkedMemoryView')
        ptrace_status_handler_count = objgraph.count('PtraceStatusHandler')
        thread_context_count = objgraph.count('ThreadContext')
        amd64_ptrace_register_holder_count = objgraph.count('Amd64PtraceRegisterHolder')
        aarch64_ptrace_register_holder_count = objgraph.count('Aarch64PtraceRegisterHolder')
        i386_over_amd64_ptrace_register_holder_count = objgraph.count('I386OverAMD64PtraceRegisterHolder')
        i386_ptrace_register_holder_count = objgraph.count('I386PtraceRegisterHolder')
        amd64_registers_count = objgraph.count('Amd64Registers')
        aarch64_registers_count = objgraph.count('Aarch64Registers')
        i386_over_amd64_registers_count = objgraph.count('I386OverAMD64Registers')
        i386_registers_count = objgraph.count('I386Registers')
 
        # Force garbage collection before starting
        gc.collect()

        # Start tracking memory
        tracemalloc.start()
        snapshot1 = tracemalloc.take_snapshot()

        # Run the runner 1000 times
        for _ in range(1000):
            runner()
            
        # Force garbage collection after
        gc.collect()
            
        # Get memory usage after execution
        snapshot2 = tracemalloc.take_snapshot()
        stats = snapshot2.compare_to(snapshot1, "lineno")

        # Stop tracemalloc
        tracemalloc.stop()
        
        # Compute total leaked memory
        total_leaked_memory = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
        
        # Assert that the total leaked memory is less than 1MB
        self.assertLess(total_leaked_memory, 1024 * 1024)
        
        # Get leaking objects
        objgraph.get_leaking_objects()
        
        # Check that there are no objects of the following types more than before
        self.assertEqual(internal_debugger_count, objgraph.count('InternalDebugger'))
        self.assertEqual(debugger_count, objgraph.count('Debugger'))
        self.assertEqual(pipe_manager_count, objgraph.count('PipeManager'))
        self.assertEqual(resume_context_count, objgraph.count('ResumeContext'))
        self.assertEqual(process_memory_manager_count, objgraph.count('ProcessMemoryManager'))
        self.assertEqual(ptrace_interface_count, objgraph.count('PtraceInterface'))
        self.assertEqual(direct_memory_view_count, objgraph.count('DirectMemoryView'))
        self.assertEqual(chunked_memory_view_count, objgraph.count('ChunkedMemoryView'))
        self.assertEqual(ptrace_status_handler_count, objgraph.count('PtraceStatusHandler'))
        self.assertEqual(thread_context_count, objgraph.count('ThreadContext'))
        self.assertEqual(amd64_ptrace_register_holder_count, objgraph.count('Amd64PtraceRegisterHolder'))
        self.assertEqual(aarch64_ptrace_register_holder_count, objgraph.count('Aarch64PtraceRegisterHolder'))
        self.assertEqual(i386_over_amd64_ptrace_register_holder_count, objgraph.count('I386OverAMD64PtraceRegisterHolder'))
        self.assertEqual(i386_ptrace_register_holder_count, objgraph.count('I386PtraceRegisterHolder'))
        self.assertEqual(amd64_registers_count, objgraph.count('Amd64Registers'))
        self.assertEqual(aarch64_registers_count, objgraph.count('Aarch64Registers'))
        self.assertEqual(i386_over_amd64_registers_count, objgraph.count('I386OverAMD64Registers'))
        self.assertEqual(i386_registers_count, objgraph.count('I386Registers'))