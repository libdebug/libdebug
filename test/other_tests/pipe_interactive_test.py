#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger
from threading import Thread
from time import sleep
import os

def multi_process_spam_sync_test_auto():
    """Test a multi-process spam binary with syncronous breakpoints and auto_quit=False."""
    print("Test a multi-process spam binary with syncronous breakpoints and auto_quit=False.")
    d = debugger('../binaries/amd64/multi')

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
    d = debugger('../binaries/amd64/multi')

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
    d = debugger('../binaries/amd64/multi')

    r = d.run()
    # Install a brakpoint after the input of the user is read
    # This is an asyncronous breakpoint
    d.bp(0x129b, hardware=True, file="binary", callback=lambda _, __: print("Callback called. Ctrl+C to pass to the next test."))
    d.cont()

    r.interactive() 
    
    print("End of the test.")
    
    d.interrupt()
    d.terminate()

    
def process_death_during_interactive_test():
    """Test the death of a process during an interactive session."""
    print("Test the death of a process during an interactive session.")
    print("Wait 5 seconds, then press Ctrl+C to exit the test.")
    d = debugger('../binaries/amd64/multi')

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
    
def complex_ctf_test():
    """Test a complex CTF binary that might mess up the terminal."""
    
    #
    # blackjack - challenge from m0leCon CTF 2025 Finals
    #
    
    print("Test a complex CTF binary that might mess up the terminal.")
    print("Press Ctrl+C to exit the test.")
    
    def fix_seed(t, bp):
        """Fix the seed"""
        t.regs.edi = 0xdeadbeef
    
    os.chdir("../binaries/amd64/CTF/blackjack")
    
    d = debugger("blackjack", aslr=False)
    
    r = d.run()
    
    d.bp(0x312, file="blackjack", callback=fix_seed)
    d.bp(0x21EF, file="blackjack")
    
    d.cont()

    r.sendline(b'500')
    r.sendline(b"\x07\x00\x00\x00")

    d.cont()
    r.sendline(b'500')
    r.sendline(b"\xee\x00\x00\x00")


    r.interactive()
    d.kill()
    

multi_process_spam_sync_test_auto()
multi_process_spam_sync_test_no_auto()
multi_process_spam_async_test()
process_death_during_interactive_test()
complex_ctf_test()