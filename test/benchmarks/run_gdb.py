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
        
    def stop(self):
        """ Callback function to be called at each breakpoint hit """
        gdb.parse_and_eval("$rax")
        gdb.selected_inferior().read_memory(gdb.parse_and_eval("$rbp"), 8).tobytes()

class Debugger(gdb.Command):
    """ Class to handle the debugging session """
    def __init__(self):
        super(Debugger, self).__init__("run_gdb", gdb.COMMAND_USER)
        
    def test(self):
        """ This test includes the time to:
        - run the debugged process from the beginning,
        - set the hardware breakpoint,
        - hit the breakpoint 1000 times,
        - each time the breakpoint is hit, access to the RAX register
        and the memory pointed by the RBP register,
        - wait the process to end.
        """
        start = perf_counter()
        
        # Start the process (it will stop at the entrypoint)
        gdb.execute("start")
        
        # Set the hardware breakpoint
        bp = MyBreakpoint("*0x401302")
        bp.silent = True
        
        # Continue the process from the entrypoint and wait for the process to end
        gdb.execute("continue")
                
        end = perf_counter()
        
        # Delete the breakpoints
        gdb.execute("del breakpoints")
        
        self.results.append(end-start)

    def invoke(self, arg, from_tty):
        # Initialize the results
        self.results = []
        
        # Load the binary
        binary = "../binaries/math_loop_test"
        gdb.execute(f"file {binary}")
        
        for _ in range(1000):
            self.test()

        # Save the result in a pickle file
        with open("run_gdb.pkl", "wb") as f:
            pickle.dump(self.results, f)
            
        # print("Results:", self.results)
        
Debugger()