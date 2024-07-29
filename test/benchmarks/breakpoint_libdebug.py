#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from time import perf_counter
import pickle
from libdebug import debugger


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
    global results
    
    # Start the process (it will stop at the entrypoint)
    d.run()     

    # Set the hardware breakpoint     
    d.breakpoint(0x401302, callback=callback, hardware=True)

    start = perf_counter()
    
    # Continue the process from the entrypoint
    d.cont()

    # Wait for the process to end
    d.wait()

    end = perf_counter()
    
    # Kill the process
    d.kill()

    results.append(end-start)

# Initialize the results
results = []

# Initialize the debugger
d = debugger("../binaries/math_loop_test")

for _ in range(1000):
    test()

# Terminate the debugger
d.terminate()

# Save the result in a pickle file
with open("breakpoint_libdebug.pkl", "wb") as f:
    pickle.dump(results, f)

# print("Results:", results)  