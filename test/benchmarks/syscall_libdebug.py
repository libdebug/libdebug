#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from time import perf_counter
import pickle
from libdebug import debugger


def callback_on_enter(t,b):
    """ Callback function to be called on syscall entry """
    pass

def callback_on_exit(t,b):
    """ Callback function to be called on syscall exit """
    pass

def start_breakpoint(t,b):
    """ Callback function to be called each time the breakpoint set just before 
    the main loop is hit 
    """
    global start
    # Start the timer
    start = perf_counter()

def end_breakpoint(t,b):
    """ Callback function to be called each time the breakpoint set right after 
    the main loop is hit 
    """
    # Stop the timer
    end = perf_counter()
    # Update the results
    results.append(end-start)

def test():
    """ This test includes the time to:
        - run the debugged process from the breakpoint just before the main loop,
        - manage 1000 calls to the syscall getpid (each call is handled by the callback functions),
        - reach the breakpoint right after the main loop,
    """    
    # Start the process (it will stop at the entrypoint)
    d.run()     

    # Set the breakpoints before and after the main loop
    d.breakpoint(0x401243, hardware=True, callback=start_breakpoint, file="absolute")
    d.breakpoint(0x401332, hardware=True, callback=end_breakpoint, file="absolute")

    # Handle the syscall getpid, install the callbacks
    d.handle_syscall("getpid", on_enter=callback_on_enter, on_exit=callback_on_exit)

    # Continue the process from the entrypoint
    d.cont()

    # Wait for the process to end
    d.wait()

    # Kill the process
    d.kill()

# Initialize the results
results = []

# Initialize the debugger
d = debugger("../binaries/math_loop_test")

for _ in range(10):
    test()

# Terminate the debugger
d.terminate()

# Save the result in a pickle file
with open("syscall_libdebug.pkl", "wb") as f:
    pickle.dump(results, f)

print("Results:", results)