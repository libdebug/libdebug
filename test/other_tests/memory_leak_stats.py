#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
import tracemalloc
import gc
import objgraph
from libdebug import debugger

def runner():
    d = debugger("ls")
    d.run()
    d.cont()
    d.wait()
    d.kill()
    d.terminate()
    
# First run to initialize the memory
runner()

"""
Part 1: Object Growth Check
"""
# Force garbage collection before starting
gc.collect()
 
# Get initial object count
print("\n--- OBJECT GROWTH CHECK: BEFORE ---\n")
objgraph.show_growth(limit=20)

# Run the runner N times
for _ in range(100):
    runner()
    
# Force garbage collection before starting
gc.collect()
    
# Get object count after execution
print("\n--- OBJECT GROWTH CHECK: AFTER ---\n")
objgraph.show_growth(limit=20)


""" Part 2: Memory Leak Check """
# Force garbage collection before starting
gc.collect()

# Start tracking memory
tracemalloc.start()
snapshot1 = tracemalloc.take_snapshot()

# Run the runner N times
for _ in range(100):
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
print(f"\n\nTotal leaked memory: {total_leaked_memory} bytes")

print("\nMemory Usage Differences:")
for stat in stats[:20]:
    print(stat)