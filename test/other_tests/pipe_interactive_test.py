#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger
from threading import Thread
from time import sleep
import os

def multi_process_spam_sync_test_auto():
    """Test a multi-process spam binary with syncronous breakpoints and auto_quit=False."""
    print("Test a multi-process spam binary with syncronous breakpoints and auto_quit=False.")
    d = debugger('../binaries/multi')

    r = d.run()
    # Install a brakpoint after the input of the user is read
    # This is a syncronous breakpoint
    bp = d.bp(0x129b, hardware=True, file="binary")
    d.cont()
        
    # The interactive will NOT quit automatically when the breakpoint is hit    
    print("Press Ctrl+C to pass to the next interactive session.")
    r.interactive()

    bp.disable()

    d.cont()
    
    print("Let open again the interactive session. You should see the prompt again and all the missing messages.")
    print("Press Ctrl+C to pass to the next test.")
    
    r.interactive()
    
    print("End of the test.")
    d.interrupt()
    d.kill()

def multi_process_spam_sync_test_no_auto():
    """Test a multi-process spam binary with syncronous breakpoints and auto_quit=True."""
    print("Test a multi-process spam binary with syncronous breakpoints and auto_quit=True.")
    d = debugger('../binaries/multi')

    r = d.run()
    # Install a brakpoint after the input of the user is read
    # This is a syncronous breakpoint
    bp = d.bp(0x129b, hardware=True, file="binary")
    d.cont()
        
    # The interactive will quit automatically when the breakpoint is hit    
    r.interactive(auto_quit=True)

    bp.disable()

    d.cont()
    
    print("Let open again the interactive session.")
    print("Press Ctrl+C to pass to the next test.")
    
    r.interactive()
    
    print("End of the test.")
    d.interrupt()
    d.kill()

def multi_process_spam_async_test():
    """Test a multi-process spam binary with asyncronous breakpoints."""
    print("Test a multi-process spam binary with asyncronous breakpoints.")
    d = debugger('../binaries/multi')

    r = d.run()
    # Install a brakpoint after the input of the user is read
    # This is an asyncronous breakpoint
    d.bp(0x129b, hardware=True, file="binary", callback=lambda _, __: print("Callback called. Ctrl+C to pass to the next test."))
    d.cont()

    r.interactive() 
    
    print("End of the test.")
    
    d.interrupt()
    d.kill()
    
def process_death_during_interactive_test():
    """Test the death of a process during an interactive session."""
    print("Test the death of a process during an interactive session.")
    print("Press Ctrl+C to exit the test.")
    d = debugger('../binaries/multi')

    r = d.run()
    d.cont()
    
    # spawn a thread to kill the process after 5 seconds
    def kill():
        sleep(5)
        os.kill(d.pid, 9)
        
    t = Thread(target=kill)
    t.start()
    
    r.interactive()
    
    print("End of the test.")
    t.join()
        

multi_process_spam_sync_test_auto()
multi_process_spam_sync_test_no_auto()
multi_process_spam_async_test()
process_death_during_interactive_test()