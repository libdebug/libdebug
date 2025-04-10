#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger, libcontext

"""
Single thread test
"""
d = debugger("../binaries/amd64/basic_test")

# libcontext.terminal = ["tmux", "splitw", "-h"]
# libcontext.terminal = ["gnome-terminal", "--tab", "--"]

d.run()

bp = d.breakpoint("register_test")

d.step()
d.step()

print(hex(d.regs.rip))

d.gdb()

print(hex(d.regs.rip))

d.cont()
d.wait()

print(hex(d.regs.rip))

d.step()

print(hex(d.regs.rip))

d.kill()

"""
Single thread test with hardware breakpoint
"""
d = debugger("../binaries/amd64/basic_test")

# libcontext.terminal = ["tmux", "splitw", "-h"]
# libcontext.terminal = ["gnome-terminal", "--tab", "--"]

d.run()

bp = d.breakpoint("register_test", hardware=True)

d.step()
d.step()

print(hex(d.regs.rip))

d.gdb()

print(hex(d.regs.rip))

d.cont()
d.wait()

print(hex(d.regs.rip))

d.step()

print(hex(d.regs.rip))

d.kill()

"""
Multi thread test 1
"""
d = debugger("../binaries/amd64/multithread_input")

d.run(redirect_pipes=False)

# Before other threads are created
d.bp(0x12e1, file="binary")

d.cont()

d.wait()


# Continue until all the threads are created
d.gdb()

assert len(d.threads) > 1

d.kill()


"""
Multi thread test 2
"""
d = debugger("../binaries/amd64/multithread_input")

d.run(redirect_pipes=False)

# After other threads are created
d.bp(0x1390, file="binary")

d.cont()

d.wait()

# Continue and input until a couple of threads finish their execution
d.gdb()

assert len([t for t in d.threads if t.dead]) > 1

d.kill()


"""
Test for GDB migration inside a callback.
"""
d = debugger("../binaries/amd64/backtrace_test")

d.run()

d.gdb()

line_called = False

def callback_1(_, __):
    global line_called

    d.gdb()

    # We expect this line to be hit
    line_called = True

line_called_2 = False

def callback_2(_, __):
    global line_called_2

    # We expect this callback to be hit
    line_called_2 = True

bp1 = d.bp("function1", callback=callback_1)
bp2 = d.bp("function3", callback=callback_2)

d.cont()

d.wait()

assert line_called
assert line_called_2

assert bp1.hit_count == 1
assert bp2.hit_count == 1

d.kill()


"""
Test for GDB migration inside a callback 2.
"""
d = debugger("../binaries/amd64/backtrace_test")

d.run()

d.gdb()

line_called = False

def callback_1(_, __):
    global line_called

    d.gdb(blocking=False)

    # We expect this line not to be hit
    line_called = True

line_called_2 = False

def callback_2(_, __):
    global line_called_2

    # We expect this callback to be hit
    line_called_2 = True

bp1 = d.bp("function1", callback=callback_1)
bp2 = d.bp("function3", callback=callback_2)

d.cont()

d.wait()

assert not line_called
assert not line_called_2

assert bp1.hit_count == 1
assert bp2.hit_count == 0

d.wait_for_gdb()

d.cont()

d.kill()