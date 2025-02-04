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
        
        # Check that there are no objects of the following types
        assert objgraph.count('InternalDebugger') == 0
        assert objgraph.count('Debugger') == 0
        assert objgraph.count('PipeManager') == 0
        assert objgraph.count('ResumeContext') == 0
        assert objgraph.count('ProcessMemoryManager') == 0
        assert objgraph.count('PtraceInterface') == 0
        assert objgraph.count('DirectMemoryView') == 0
        assert objgraph.count('ChunkedMemoryView') == 0
        assert objgraph.count('PtraceStatusHandler') == 0
        assert objgraph.count('ThreadContext') == 0
        assert objgraph.count('Amd64PtraceRegisterHolder') == 0
        assert objgraph.count('Aarch64PtraceRegisterHolder') == 0
        assert objgraph.count('I386OverAMD64PtraceRegisterHolder') == 0
        assert objgraph.count('I386PtraceRegisterHolder') == 0
        assert objgraph.count('Amd64Registers') == 0
        assert objgraph.count('Aarch64Registers') == 0
        assert objgraph.count('I386OverAMD64Registers') == 0
        assert objgraph.count('I386Registers') == 0