#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import gdb
from time import perf_counter
import pickle

class MyBreakpoint(gdb.Breakpoint):
    """ Class to handle the breakpoint action """
    def __init__(self, spec):
        """ Initialize a hardware breakpoint """
        super(MyBreakpoint, self).__init__(spec, gdb.BP_HARDWARE_BREAKPOINT)
        self.silent = True
        
    def stop(self):
        """ Callback function to be called at each breakpoint hit """
        pass

class Debugger(gdb.Command):
    """ Class to handle the debugging session """
    def __init__(self):
        super(Debugger, self).__init__("breakpoint_gdb", gdb.COMMAND_USER)
        
    def test(self):
        """ This test includes the time to:
        - run the debugged process from the entrypoint,
        - hit the breakpoint 1000 times,
        - each time the breakpoint is hit, execute an empty callback,
        - wait the process to end.
        """
        gdb.execute("set pagination off")

        # Start the process (it will stop at the entrypoint)
        gdb.execute("start")
        
        # Set the hardware breakpoint
        MyBreakpoint("*0x401302")
        
        # Start the timer
        start = perf_counter()
        
        # Continue the process from the entrypoint and wait for the process to end
        gdb.execute("continue")
        
        # Stop the timer
        end = perf_counter()

        # Delete the breakpoints
        gdb.execute("del breakpoints")
        
        self.results.append(end-start)

    def invoke(self, arg, from_tty):
        # Initialize the results
        self.results = []
        
        # Load the binary
        binary = "../binaries/amd64/math_loop_test"
        gdb.execute(f"file {binary}")
        
        for _ in range(1000):
            self.test()

        # Save the result in a pickle file
        with open("breakpoint_gdb.pkl", "wb") as f:
            pickle.dump(self.results, f)
        # print("Results:", self.results)
        
Debugger()