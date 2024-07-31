#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

########################################################################################
#  This script requires GDB 15.1 or later to run due to the use of the new Python API  #
########################################################################################

import gdb
from time import perf_counter
import pickle


# Initialize the global variables
results = []

def stop_handler(event):
    """ Callback function to be called at each stop event """
    if isinstance(event, gdb.StopEvent):
        # Check if the stop is due the desired syscall
        if event.details["reason"] == "syscall-entry" and event.details["syscall-number"] == 39:
            gdb.post_event(lambda: gdb.execute("continue"))
        elif event.details["reason"] == "syscall-return" and event.details["syscall-number"] == 39:
            gdb.post_event(lambda: gdb.execute("continue"))

class StartBreakpoint(gdb.Breakpoint):
    """ Class to handle the breakpoint set just before the main loop """
    def __init__(self, spec):
        """ Initialize a hardware breakpoint """
        super(StartBreakpoint, self).__init__(spec, gdb.BP_HARDWARE_BREAKPOINT)
        self.silent = True
        
    def stop(self):
        """ Callback function to be called at each breakpoint hit """
        global start
        # Start the timer
        start = perf_counter()

class EndBreakpoint(gdb.Breakpoint):
    """ Class to handle the breakpoint set right after the main loop """
    def __init__(self, spec):
        """ Initialize a hardware breakpoint """
        super(EndBreakpoint, self).__init__(spec, gdb.BP_HARDWARE_BREAKPOINT)
        self.silent = True
        
    def stop(self):
        """ Callback function to be called at each breakpoint hit """
        # Stop the timer
        end = perf_counter()

        # Kill the process
        gdb.execute("kill")

        if len(results) < 1000:
            results.append(end-start)
            # Restart the process
            gdb.execute("run")
        else:
            # Save the results and quit
            with open("syscall_gdb.pkl", "wb") as f:
                pickle.dump(results, f)
            # print("Results:", results)
            gdb.execute("quit")

class Debugger(gdb.Command):
    """ Class to handle the debugging session """
    def __init__(self):
        super(Debugger, self).__init__("syscall_gdb", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        """ This test includes the time to:
        - run the debugged process from the breakpoint just before the main loop,
        - manage 1000 calls to the syscall getpid (handled by the stop_handler),
        - reach the breakpoint right after the main loop,
        """

        # Load the binary
        binary = "../binaries/math_loop_test"
        gdb.execute(f"file {binary}")

        gdb.execute("set confirm off")
        gdb.execute("set pagination off")

        # Catch the syscall getpid
        gdb.execute("catch syscall getpid")

        # Connect the stop_handler to the stop event
        # It will be called at each stop event and will check 
        # if the syscall getpid is called
        gdb.events.stop.connect(stop_handler)

        # Start the process (it will stop at the entrypoint)
        gdb.execute("start")

        # Set the breakpoints before and after the main loop
        StartBreakpoint("*0x401243")
        EndBreakpoint("*0x401332")

        # Continue the process from the entrypoint
        gdb.execute("continue")

Debugger()