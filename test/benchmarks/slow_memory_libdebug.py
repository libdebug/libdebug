#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from time import perf_counter
import pickle
from libdebug import debugger
import random

def callback(t,b):
    """ Callback function to be called at each breakpoint hit """
    pass

def test():
    """ This test includes the time to:
    - run the debugged process from the entrypoint,
    - hit the breakpoint 1000 times,
    - each time the breakpoint is hit, execute an empty callback,
    - wait the process to end.
    """    
    # Start the process (it will stop at the entrypoint)
    d.run()     

    # Choose a random memory map
    all_maps = d.maps()

    # Filter maps with read / write permission
    r_maps = [m for m in all_maps if "r" in m.permissions]
    w_maps = [m for m in all_maps if "w" in m.permissions]

    start = perf_counter()

    for _ in range(1000):
        random_map = random.choice(r_maps)
        random_address = random.randint(0, random_map.size - 8)
        _ = d.memory[random_address, 8, random_map.backing_file]

        random_map = random.choice(w_maps)
        random_address = random.randint(0, random_map.size - 8)
        d.memory[random_address, 8, random_map.backing_file] = b"\xde\xc0\xad\xde\xde\xc0\xad\xde"

    # Stop the timer
    end = perf_counter()
    
    # Kill for a clean exit
    d.kill()

    results.append(end-start)

# Initialize the results
results = []

# Initialize the debugger
d = debugger("../binaries/math_loop_test", fast_memory=False)

for _ in range(1000):
    test()

# Terminate the debugger
d.terminate()

# Save the result in a pickle file
with open("slow_memory_libdebug.pkl", "wb") as f:
    pickle.dump(results, f)

# print("Results:", results)  